/*
 * dpdk_receiver.cu — T2: DPDK poll-mode receiver.
 *
 * Data path:
 *   NIC → DPDK poll-mode (no kernel) → host mbuf → extract payload
 *       → cudaMemcpy H→D → process_ticks_kernel → BenchmarkResult → harness
 *
 * Key difference from T1: no OS socket overhead, DPDK bypasses the kernel
 * entirely. The cudaMemcpy step is identical to T1.
 *
 * Benchmark definition for T2:
 *   t1 = receiver-side ingress timestamp on lxcpu1, taken at the earliest
 *        host-visible point in the DPDK RX path after the packet is accepted
 *        by the NIC/PMD and passes the UDP dst-port filter.
 *
 * Build requires DPDK installed (pkg-config libdpdk).
 *
 * Usage:
 *   dpdk_receiver -- [EAL args] -- [app args]
 *   dpdk_receiver -- -l 0-1 -n 4 -- --port 0 --batch 256 --tier 2
 *
 * Note: must run as root or with appropriate hugepage / IOMMU setup.
 */

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_udp.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_flow.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <cuda_runtime.h>

#include "tick_message.h"
#include "benchmark_result.h"
#include "signal_result.h"
#include "process_kernel.cuh"

static bool g_light_bench = false;

/* ── Constants ───────────────────────────────────────────────────────────── */
#define RX_RING_SIZE   1024
#define NUM_MBUFS      8191
#define MBUF_CACHE_SZ  250
#define BURST_SIZE                   32
#define DEFAULT_BATCH                256
#define ETH_IP_UDP_HDR               42   /* 14 + 20 + 8 */
#define DEFAULT_MAX_BATCH_LATENCY_NS 1000000ULL

#define CUDA_CHECK(call) \
    do { cudaError_t _e=(call); if(_e!=cudaSuccess){ \
        fprintf(stderr,"CUDA %s:%d: %s\n",__FILE__,__LINE__,cudaGetErrorString(_e)); exit(1); \
    }} while(0)

/* ── DPDK port init ──────────────────────────────────────────────────────── */
static int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf{};
    port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(port, &dev_info);

    if (rte_eth_dev_configure(port, 1, 1, &port_conf) < 0)
        return -1;

    struct rte_eth_rxconf rxq_conf = dev_info.default_rxconf;
    if (rte_eth_rx_queue_setup(port, 0, RX_RING_SIZE,
                                rte_eth_dev_socket_id(port),
                                &rxq_conf, mbuf_pool) < 0)
        return -1;

    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
    if (rte_eth_tx_queue_setup(port, 0, RX_RING_SIZE,
                                rte_eth_dev_socket_id(port),
                                &txq_conf) < 0)
        return -1;

    if (rte_eth_dev_start(port) < 0) return -1;

    /* Enable promiscuous mode so we receive multicast */
    rte_eth_promiscuous_enable(port);

    /* Join multicast group via igmp (done at OS level or via DPDK filter) */
    struct rte_ether_addr mcast_mac;
    /* 239.0.0.1 → 01:00:5e:00:00:01 */
    mcast_mac.addr_bytes[0] = 0x01;
    mcast_mac.addr_bytes[1] = 0x00;
    mcast_mac.addr_bytes[2] = 0x5e;
    mcast_mac.addr_bytes[3] = 0x00;
    mcast_mac.addr_bytes[4] = 0x00;
    mcast_mac.addr_bytes[5] = 0x01;
    rte_eth_dev_set_mc_addr_list(port, &mcast_mac, 1);

    /* rte_flow rule: steer UDP dst port 5005 to RX queue 0.
     * Required for mlx5 bifurcated driver — without this, kernel gets all traffic. */
    struct rte_flow_attr attr{};
    attr.ingress = 1;

    struct rte_flow_item_ipv4 ipv4_spec{};
    ipv4_spec.hdr.next_proto_id = IPPROTO_UDP;
    struct rte_flow_item_ipv4 ipv4_mask{};
    ipv4_mask.hdr.next_proto_id = 0xFF;

    struct rte_flow_item_udp udp_spec{};
    udp_spec.hdr.dst_port = rte_cpu_to_be_16(TICK_MCAST_PORT);
    struct rte_flow_item_udp udp_mask{};
    udp_mask.hdr.dst_port = 0xFFFF;

    struct rte_flow_item pattern[] = {
        { RTE_FLOW_ITEM_TYPE_ETH,  nullptr, nullptr, nullptr },
        { RTE_FLOW_ITEM_TYPE_IPV4, &ipv4_spec, nullptr, &ipv4_mask },
        { RTE_FLOW_ITEM_TYPE_UDP,  &udp_spec, nullptr, &udp_mask },
        { RTE_FLOW_ITEM_TYPE_END,  nullptr, nullptr, nullptr },
    };

    struct rte_flow_action_queue queue_action{};
    queue_action.index = 0;

    struct rte_flow_action actions[] = {
        { RTE_FLOW_ACTION_TYPE_QUEUE, &queue_action },
        { RTE_FLOW_ACTION_TYPE_END,   nullptr },
    };

    struct rte_flow_error flow_err{};
    struct rte_flow *flow = rte_flow_create(port, &attr, pattern, actions, &flow_err);
    if (!flow) {
        fprintf(stderr, "  WARN: rte_flow_create failed: %s (falling back to promiscuous)\n",
                flow_err.message ? flow_err.message : "unknown");
    } else {
        fprintf(stderr, "  rte_flow: steering UDP dst port %d → queue 0\n", TICK_MCAST_PORT);
    }

    return 0;
}

/* ── UDP send socket (non-DPDK, for results to harness) ────────────────── */
static int make_udp_send(const char *addr, int port, sockaddr_in &dest)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_port        = htons((uint16_t)port);
    dest.sin_addr.s_addr = inet_addr(addr);
    return fd;
}

template<typename T>
static inline void send_many(int fd, sockaddr_in &dest, const T *items, int n)
{
    if (n <= 0) return;
    struct mmsghdr msgs[DEFAULT_BATCH];
    struct iovec   iovs[DEFAULT_BATCH];
    int sent = 0;
    while (sent < n) {
        int chunk = std::min(n - sent, DEFAULT_BATCH);
        for (int i = 0; i < chunk; ++i) {
            iovs[i].iov_base = const_cast<T *>(&items[sent + i]);
            iovs[i].iov_len  = sizeof(T);
            std::memset(&msgs[i], 0, sizeof(msgs[i]));
            msgs[i].msg_hdr.msg_name    = &dest;
            msgs[i].msg_hdr.msg_namelen = sizeof(dest);
            msgs[i].msg_hdr.msg_iov     = &iovs[i];
            msgs[i].msg_hdr.msg_iovlen  = 1;
        }
        int rc = sendmmsg(fd, msgs, chunk, 0);
        if (rc < 0) { perror("sendmmsg"); break; }
        sent += rc;
    }
}

/* ── GPU resource bundle (same as T1) ───────────────────────────────────── */
struct GpuResources {
    TickMessage  *d_ticks     = nullptr;
    SignalResult *d_signals   = nullptr;
    TickMessage  *h_ticks     = nullptr;
    SignalResult *h_signals   = nullptr;
    double       *d_fast_ema  = nullptr;
    double       *d_slow_ema  = nullptr;
    double       *d_avg_gain  = nullptr;
    double       *d_avg_loss  = nullptr;
    double       *d_last_mid  = nullptr;
    cudaStream_t  stream      = nullptr;
    int           cap         = DEFAULT_BATCH;
};

static void gpu_init(GpuResources &r, int cap)
{
    r.cap = cap;
    CUDA_CHECK(cudaMallocHost(&r.h_ticks,   cap * sizeof(TickMessage)));
    CUDA_CHECK(cudaMallocHost(&r.h_signals, cap * sizeof(SignalResult)));
    CUDA_CHECK(cudaMalloc(&r.d_ticks,   cap * sizeof(TickMessage)));
    CUDA_CHECK(cudaMalloc(&r.d_signals, cap * sizeof(SignalResult)));
    size_t state_sz = MAX_INSTRUMENTS * sizeof(double);
    CUDA_CHECK(cudaMalloc(&r.d_fast_ema, state_sz)); CUDA_CHECK(cudaMemset(r.d_fast_ema, 0, state_sz));
    CUDA_CHECK(cudaMalloc(&r.d_slow_ema, state_sz)); CUDA_CHECK(cudaMemset(r.d_slow_ema, 0, state_sz));
    CUDA_CHECK(cudaMalloc(&r.d_avg_gain, state_sz)); CUDA_CHECK(cudaMemset(r.d_avg_gain, 0, state_sz));
    CUDA_CHECK(cudaMalloc(&r.d_avg_loss, state_sz)); CUDA_CHECK(cudaMemset(r.d_avg_loss, 0, state_sz));
    CUDA_CHECK(cudaMalloc(&r.d_last_mid, state_sz)); CUDA_CHECK(cudaMemset(r.d_last_mid, 0, state_sz));
    CUDA_CHECK(cudaStreamCreate(&r.stream));
}

/* ── Process batch ──────────────────────────────────────────────────────────
 * Uses host wall-clock for t2/t3/t4 (after each cudaStreamSynchronize).
 * The kernel still writes clock64() into sig.t3_ns/t4_ns, but those fields
 * are absolute SM cycles (not deltas), so the previous "t2 + sig.t3_ns *
 * ns_per_cycle" math produced ~minutes of fake compute latency. Fixed by
 * mirroring T1's host-stamping pattern. */
static void process_batch(GpuResources &r, int n, uint8_t tier,
                           int harness_fd, sockaddr_in harness_dest,
                           int signal_fd,  sockaddr_in signal_dest)
{
    CUDA_CHECK(cudaMemcpyAsync(r.d_ticks, r.h_ticks,
                                n * sizeof(TickMessage),
                                cudaMemcpyHostToDevice, r.stream));
    CUDA_CHECK(cudaStreamSynchronize(r.stream));
    uint64_t t2 = now_ns();

    launch_process_ticks(r.d_ticks, n, r.d_signals,
                          r.d_fast_ema, r.d_slow_ema,
                          r.d_avg_gain, r.d_avg_loss, r.d_last_mid,
                          t2, r.stream, g_light_bench);
    CUDA_CHECK(cudaStreamSynchronize(r.stream));
    uint64_t t3 = now_ns();

    CUDA_CHECK(cudaMemcpyAsync(r.h_signals, r.d_signals,
                                n * sizeof(SignalResult),
                                cudaMemcpyDeviceToHost, r.stream));
    CUDA_CHECK(cudaStreamSynchronize(r.stream));
    uint64_t t4 = now_ns();

    BenchmarkResult brs[DEFAULT_BATCH];
    SignalResult    sigs[DEFAULT_BATCH];
    for (int i = 0; i < n; ++i) {
        const TickMessage  &tick = r.h_ticks[i];
        const SignalResult &sig  = r.h_signals[i];

        brs[i] = BenchmarkResult{};
        brs[i].tick_id = tick.tick_id;
        brs[i].t1_ns   = tick.timestamp_ns;
        brs[i].t2_ns   = t2;
        brs[i].t3_ns   = t3;
        brs[i].t4_ns   = t4;
        brs[i].tier    = tier;

        sigs[i] = sig;
        sigs[i].t3_ns = t3;
        sigs[i].t4_ns = t4;
    }
    send_many(harness_fd, harness_dest, brs,  n);
    send_many(signal_fd,  signal_dest,  sigs, n);
}

/* ── main ───────────────────────────────────────────────────────────────── */
int main(int argc, char **argv)
{
    /* DPDK EAL init consumes args up to "--" */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL init failed\n");
    argc -= ret;
    argv += ret;

    uint16_t    dpdk_port   = 0;
    int         batch_size  = DEFAULT_BATCH;
    uint8_t     tier        = 2;
    const char *harness_ip  = "127.0.0.1";
    const char *fillsim_ip  = "127.0.0.1";

    for (int i = 1; i < argc; ++i) {
        if      (!strcmp(argv[i],"--port")      && i+1<argc) dpdk_port  = (uint16_t)atoi(argv[++i]);
        else if (!strcmp(argv[i],"--batch")     && i+1<argc) batch_size = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--tier")      && i+1<argc) tier       = (uint8_t)atoi(argv[++i]);
        else if (!strcmp(argv[i],"--harness")   && i+1<argc) harness_ip = argv[++i];
        else if (!strcmp(argv[i],"--fillsim")   && i+1<argc) fillsim_ip = argv[++i];
        else if (!strcmp(argv[i],"--light-bench"))          g_light_bench = true;
    }

    fprintf(stderr, "[T2 dpdk_receiver] dpdk_port=%u batch=%d\n", dpdk_port, batch_size);
    if (g_light_bench)
        fprintf(stderr, "[T2] light benchmark mode enabled (Monte Carlo skipped)\n");

    uint16_t nb_ports = rte_eth_dev_count_avail();
    fprintf(stderr, "[T2] DPDK ports available: %u\n", nb_ports);
    for (uint16_t p = 0; p < nb_ports; ++p) {
        struct rte_ether_addr mac;
        rte_eth_macaddr_get(p, &mac);
        fprintf(stderr, "[T2]   port %u MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", p,
                mac.addr_bytes[0], mac.addr_bytes[1], mac.addr_bytes[2],
                mac.addr_bytes[3], mac.addr_bytes[4], mac.addr_bytes[5]);
    }

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SZ, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    if (port_init(dpdk_port, mbuf_pool) < 0)
        rte_exit(EXIT_FAILURE, "Port init failed\n");

    sockaddr_in harness_dest{}, signal_dest{};
    int harness_fd = make_udp_send(harness_ip, BENCH_RESULT_PORT, harness_dest);
    int signal_fd  = make_udp_send(fillsim_ip, SIGNAL_PORT, signal_dest);

    GpuResources gpu{};
    gpu_init(gpu, batch_size);

    struct rte_mbuf *burst[BURST_SIZE];
    int batch_n = 0;

    struct rte_eth_stats stats_before{};
    rte_eth_stats_get(dpdk_port, &stats_before);
    fprintf(stderr, "[T2] initial stats: ipackets=%lu imissed=%lu ierrors=%lu rx_nombuf=%lu\n",
            stats_before.ipackets, stats_before.imissed,
            stats_before.ierrors, stats_before.rx_nombuf);

    fprintf(stderr, "[T2] polling on DPDK port %u...\n", dpdk_port);

    uint64_t poll_count = 0;
    uint64_t total_rx = 0;
    uint64_t total_filtered = 0;
    uint64_t total_short = 0;
    uint64_t idle_polls = 0;
    uint64_t batch_start_ns = 0;
    uint64_t total_batches  = 0;
    uint64_t last_report_ns = 0;

    while (true) {
        uint16_t nb_rx = rte_eth_rx_burst(dpdk_port, 0, burst, BURST_SIZE);
        poll_count++;

        if (nb_rx > 0 && total_rx == 0 && total_filtered == 0 && total_short == 0)
            fprintf(stderr, "[T2] first burst: %u pkts after %lu polls\n", nb_rx, poll_count);

        if (poll_count % 10000000 == 0) {
            struct rte_eth_stats st{};
            rte_eth_stats_get(dpdk_port, &st);
            fprintf(stderr, "[T2] poll=%luM hw: ipkts=%lu imissed=%lu ierr=%lu nombuf=%lu | "
                    "sw: rx=%lu filtered=%lu short=%lu\n",
                    poll_count / 1000000, st.ipackets, st.imissed,
                    st.ierrors, st.rx_nombuf, total_rx, total_filtered, total_short);
        }

        for (uint16_t p = 0; p < nb_rx; ++p) {
            struct rte_mbuf *m = burst[p];
            uint32_t pkt_len   = rte_pktmbuf_pkt_len(m);

            if (pkt_len < ETH_IP_UDP_HDR + sizeof(TickMessage)) {
                total_short++;
                rte_pktmbuf_free(m);
                continue;
            }

            const uint8_t *data = rte_pktmbuf_mtod(m, uint8_t *);
            const struct rte_udp_hdr *udp =
                reinterpret_cast<const struct rte_udp_hdr *>(data + 14 + 20);
            if (ntohs(udp->dst_port) != TICK_MCAST_PORT) {
                total_filtered++;
                rte_pktmbuf_free(m);
                continue;
            }
            total_rx++;

            const TickMessage *tick =
                reinterpret_cast<const TickMessage *>(data + ETH_IP_UDP_HDR);
            uint64_t rx_ts_ns = now_ns();
            if (batch_n == 0) batch_start_ns = now_ns();
            memcpy(&gpu.h_ticks[batch_n], tick, sizeof(TickMessage));
            gpu.h_ticks[batch_n].timestamp_ns = rx_ts_ns;
            ++batch_n;

            rte_pktmbuf_free(m);

            if (batch_n >= batch_size) {
                process_batch(gpu, batch_n, tier,
                               harness_fd, harness_dest, signal_fd, signal_dest);
                ++total_batches;
                uint64_t now_n = now_ns();
                if (total_batches <= 5 || now_n - last_report_ns >= 1000000000ULL) {
                    fprintf(stderr, "[T2] batch %lu: %d ticks (total_rx=%lu)\n",
                            total_batches, batch_n, total_rx);
                    last_report_ns = now_n;
                }
                batch_n = 0;
            }
        }

        /* Time-based flush: cap how long any tick sits in batch waiting for a
         * full set. Without this, low-rate runs measure batch-fill time, not
         * data-path latency. */
        if (batch_n > 0 &&
            (now_ns() - batch_start_ns) >= DEFAULT_MAX_BATCH_LATENCY_NS) {
            process_batch(gpu, batch_n, tier,
                          harness_fd, harness_dest, signal_fd, signal_dest);
            ++total_batches;
            uint64_t now_n = now_ns();
            if (total_batches <= 5 || now_n - last_report_ns >= 1000000000ULL) {
                fprintf(stderr, "[T2] batch %lu: %d ticks [age] (total_rx=%lu)\n",
                        total_batches, batch_n, total_rx);
                last_report_ns = now_n;
            }
            batch_n = 0;
            idle_polls = 0;
        }

        if (nb_rx == 0) idle_polls++; else idle_polls = 0;
    }

    rte_eal_cleanup();
    return 0;
}
