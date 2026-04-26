/*
 * dpdk_receiver.cu — T2: DPDK poll-mode receiver.
 *
 * Data path:
 *   NIC → DPDK poll-mode (no kernel) → host mbuf → extract payload
 *       → cudaMemcpy H→D → process_ticks_kernel → BenchmarkResult → harness
 *
 * Key difference from T1: no OS socket overhead, DPDK bypasses the kernel
 * entirely.  The cudaMemcpy step is identical to T1.
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

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <cuda_runtime.h>

#include "tick_message.h"
#include "benchmark_result.h"
#include "signal_result.h"
#include "process_kernel.cuh"

/* ── Constants ───────────────────────────────────────────────────────────── */
#define RX_RING_SIZE   1024
#define NUM_MBUFS      8191
#define MBUF_CACHE_SZ  250
#define BURST_SIZE     32
#define DEFAULT_BATCH  256
#define ETH_IP_UDP_HDR 42   /* 14 + 20 + 8 */

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
        { RTE_FLOW_ITEM_TYPE_IPV4, &ipv4_spec, &ipv4_mask, nullptr },
        { RTE_FLOW_ITEM_TYPE_UDP,  &udp_spec, &udp_mask, nullptr },
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

static double gpu_clock_khz = 0;

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
    int dev; CUDA_CHECK(cudaGetDevice(&dev));
    int clock_khz = 0;
    CUDA_CHECK(cudaDeviceGetAttribute(&clock_khz, cudaDevAttrClockRate, dev));
    gpu_clock_khz = clock_khz;
}

/* ── Process batch ──────────────────────────────────────────────────────── */
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
                          t2, r.stream);
    CUDA_CHECK(cudaStreamSynchronize(r.stream));

    CUDA_CHECK(cudaMemcpyAsync(r.h_signals, r.d_signals,
                                n * sizeof(SignalResult),
                                cudaMemcpyDeviceToHost, r.stream));
    CUDA_CHECK(cudaStreamSynchronize(r.stream));

    for (int i = 0; i < n; ++i) {
        const TickMessage  &tick = r.h_ticks[i];
        const SignalResult &sig  = r.h_signals[i];

        double ns_per_cycle = (gpu_clock_khz > 0) ? 1e6 / gpu_clock_khz : 1.0;
        uint64_t t3 = t2 + (uint64_t)(sig.t3_ns * ns_per_cycle);
        uint64_t t4 = t2 + (uint64_t)(sig.t4_ns * ns_per_cycle);

        BenchmarkResult br{};
        br.tick_id = tick.tick_id;
        br.t1_ns   = tick.timestamp_ns;
        br.t2_ns   = t2;
        br.t3_ns   = t3;
        br.t4_ns   = t4;
        br.tier    = tier;

        sendto(harness_fd, &br, sizeof(br), 0,
               reinterpret_cast<const sockaddr *>(&harness_dest), sizeof(harness_dest));

        SignalResult out = sig;
        out.t3_ns = t3; out.t4_ns = t4;
        sendto(signal_fd, &out, sizeof(out), 0,
               reinterpret_cast<const sockaddr *>(&signal_dest), sizeof(signal_dest));
    }
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
    }

    fprintf(stderr, "[T2 dpdk_receiver] dpdk_port=%u batch=%d\n", dpdk_port, batch_size);

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

    fprintf(stderr, "[T2] polling on DPDK port %u...\n", dpdk_port);

    while (true) {
        uint16_t nb_rx = rte_eth_rx_burst(dpdk_port, 0, burst, BURST_SIZE);

        for (uint16_t p = 0; p < nb_rx; ++p) {
            struct rte_mbuf *m = burst[p];
            uint32_t pkt_len   = rte_pktmbuf_pkt_len(m);

            if (pkt_len < ETH_IP_UDP_HDR + sizeof(TickMessage)) {
                rte_pktmbuf_free(m);
                continue;
            }

            /* Verify destination port (UDP dst = TICK_MCAST_PORT) */
            const uint8_t *data = rte_pktmbuf_mtod(m, uint8_t *);
            const struct rte_udp_hdr *udp =
                reinterpret_cast<const struct rte_udp_hdr *>(data + 14 + 20);
            if (ntohs(udp->dst_port) != TICK_MCAST_PORT) {
                rte_pktmbuf_free(m);
                continue;
            }

            const TickMessage *tick =
                reinterpret_cast<const TickMessage *>(data + ETH_IP_UDP_HDR);
            memcpy(&gpu.h_ticks[batch_n], tick, sizeof(TickMessage));
            ++batch_n;

            rte_pktmbuf_free(m);

            if (batch_n >= batch_size) {
                process_batch(gpu, batch_n, tier,
                               harness_fd, harness_dest, signal_fd, signal_dest);
                batch_n = 0;
            }
        }
    }

    rte_eal_cleanup();
    return 0;
}
