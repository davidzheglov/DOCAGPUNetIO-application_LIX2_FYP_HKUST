/*
 * rdma_receiver.cu — T3: GPU RDMA raw-packet receiver.
 *
 * Data path:
 *   NIC → libibverbs RAW_PACKET QP → DMA directly into GPU memory (nv_peer_mem)
 *       → extract_ticks_kernel (parse ETH/IP/UDP on GPU, NO cudaMemcpy H→D)
 *       → process_ticks_kernel → BenchmarkResult → harness
 *
 * Key difference from T1/T2: nv_peer_mem (or nvidia_peermem) kernel module
 * allows ibverbs to register GPU memory regions.  The NIC writes received
 * packets straight into device memory — the cudaMemcpy H→D step is eliminated.
 *
 * Uses IBV_QPT_RAW_PACKET so regular UDP multicast from send_ticks.py works
 * (same sender as T1/T2/T4 — fair benchmark comparison).  ibv_create_flow
 * steers UDP dst port 5005 packets into the QP.
 *
 * Prerequisites on the server:
 *   sudo modprobe nvidia-peermem   (or nv_peer_mem on older drivers)
 *   sudo modprobe ib_uverbs rdma_ucm
 *
 * Usage:
 *   rdma_receiver --dev mlx5_0 [--batch 256] [--tier 3]
 *                 [--harness <ip>] [--fillsim <ip>]
 */

#include <infiniband/verbs.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>

#include <cuda_runtime.h>

#include "tick_message.h"
#include "benchmark_result.h"
#include "signal_result.h"
#include "process_kernel.cuh"

/* ── Constants ───────────────────────────────────────────────────────────── */
#define DEFAULT_BATCH   256
#define MAX_RECV_WR     512    /* pre-posted receive work requests */
#define PKT_BUF_SIZE    2048   /* must be >= MTU + headers */
#define ETH_IP_UDP_HDR  42     /* 14 (ETH) + 20 (IPv4) + 8 (UDP) */

#define CUDA_CHECK(call) \
    do { cudaError_t _e=(call); if(_e!=cudaSuccess){ \
        fprintf(stderr,"CUDA %s:%d: %s\n",__FILE__,__LINE__,cudaGetErrorString(_e)); exit(1); \
    }} while(0)

/* ── GPU-registered receive buffers ─────────────────────────────────────── */
struct GpuRdmaResources {
    uint8_t          *d_pkt_bufs   = nullptr;    /* [MAX_RECV_WR * PKT_BUF_SIZE] */
    TickMessage      *d_ticks      = nullptr;
    SignalResult     *d_signals    = nullptr;
    double           *d_fast_ema   = nullptr;
    double           *d_slow_ema   = nullptr;
    double           *d_avg_gain   = nullptr;
    double           *d_avg_loss   = nullptr;
    double           *d_last_mid   = nullptr;

    SignalResult     *h_signals    = nullptr;
    TickMessage      *h_ticks_copy = nullptr;

    cudaStream_t      stream       = nullptr;
    double            gpu_ns_per_cycle = 1.0;
    int               batch_size   = DEFAULT_BATCH;
};

/* ── ibverbs state ───────────────────────────────────────────────────────── */
struct IbvState {
    ibv_context   *ctx   = nullptr;
    ibv_pd        *pd    = nullptr;
    ibv_mr        *mr    = nullptr;
    ibv_cq        *cq    = nullptr;
    ibv_qp        *qp    = nullptr;
    ibv_flow      *flow  = nullptr;
};

static IbvState g_ibv{};

static int ibv_init(const char *dev_name, int port_num, GpuRdmaResources &r)
{
    int num_devices;
    ibv_device **dev_list = ibv_get_device_list(&num_devices);
    if (!dev_list || num_devices == 0) {
        fprintf(stderr, "No IB devices found\n"); return -1;
    }

    fprintf(stderr, "[T3] IB devices found: %d\n", num_devices);
    ibv_device *dev = nullptr;
    for (int i = 0; i < num_devices; ++i) {
        fprintf(stderr, "[T3]   %s\n", ibv_get_device_name(dev_list[i]));
        if (!strcmp(ibv_get_device_name(dev_list[i]), dev_name))
            dev = dev_list[i];
    }
    if (!dev) {
        fprintf(stderr, "IB device '%s' not found\n", dev_name);
        ibv_free_device_list(dev_list);
        return -1;
    }

    g_ibv.ctx = ibv_open_device(dev);
    ibv_free_device_list(dev_list);
    if (!g_ibv.ctx) { perror("ibv_open_device"); return -1; }

    g_ibv.pd = ibv_alloc_pd(g_ibv.ctx);
    if (!g_ibv.pd) { perror("ibv_alloc_pd"); return -1; }

    /* Register GPU memory — requires nvidia-peermem loaded */
    size_t pkt_buf_total = (size_t)MAX_RECV_WR * PKT_BUF_SIZE;
    g_ibv.mr = ibv_reg_mr(g_ibv.pd, r.d_pkt_bufs, pkt_buf_total,
                            IBV_ACCESS_LOCAL_WRITE);
    if (!g_ibv.mr) {
        fprintf(stderr, "ibv_reg_mr failed (GPU memory) — is nvidia-peermem loaded?\n"
                        "  Try: sudo modprobe nvidia-peermem\n");
        return -1;
    }
    fprintf(stderr, "[T3] GPU memory registered with ibverbs (%.1f MB)\n",
            pkt_buf_total / (1024.0 * 1024.0));

    g_ibv.cq = ibv_create_cq(g_ibv.ctx, MAX_RECV_WR * 2, nullptr, nullptr, 0);
    if (!g_ibv.cq) { perror("ibv_create_cq"); return -1; }

    /* RAW_PACKET QP — receives full Ethernet frames, same as regular UDP */
    ibv_qp_init_attr qp_attr{};
    qp_attr.send_cq          = g_ibv.cq;
    qp_attr.recv_cq          = g_ibv.cq;
    qp_attr.qp_type          = IBV_QPT_RAW_PACKET;
    qp_attr.cap.max_send_wr  = 1;
    qp_attr.cap.max_recv_wr  = MAX_RECV_WR;
    qp_attr.cap.max_send_sge = 1;
    qp_attr.cap.max_recv_sge = 1;

    g_ibv.qp = ibv_create_qp(g_ibv.pd, &qp_attr);
    if (!g_ibv.qp) {
        perror("ibv_create_qp(RAW_PACKET)");
        fprintf(stderr, "  RAW_PACKET QP requires root or CAP_NET_RAW\n");
        return -1;
    }

    /* QP state: RESET → INIT */
    ibv_qp_attr attr{};
    attr.qp_state = IBV_QPS_INIT;
    attr.port_num = (uint8_t)port_num;
    if (ibv_modify_qp(g_ibv.qp, &attr, IBV_QP_STATE | IBV_QP_PORT)) {
        perror("QP RESET→INIT"); return -1;
    }

    /* QP state: INIT → RTR */
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTR;
    if (ibv_modify_qp(g_ibv.qp, &attr, IBV_QP_STATE)) {
        perror("QP INIT→RTR"); return -1;
    }

    fprintf(stderr, "[T3] RAW_PACKET QP created and ready (qpn=%u)\n", g_ibv.qp->qp_num);

    /* Flow steering: match ETH(IPv4) + IPv4(UDP) + UDP(dst_port=5005) */
    struct __attribute__((packed)) {
        ibv_flow_attr        attr;
        ibv_flow_spec_eth    eth;
        ibv_flow_spec_ipv4   ipv4;
        ibv_flow_spec_tcp_udp udp;
    } flow_rule{};

    flow_rule.attr.type          = IBV_FLOW_ATTR_NORMAL;
    flow_rule.attr.num_of_specs  = 3;
    flow_rule.attr.port          = (uint8_t)port_num;
    flow_rule.attr.size          = sizeof(flow_rule);

    /* ETH: match ether_type = 0x0800 (IPv4) */
    flow_rule.eth.type           = IBV_FLOW_SPEC_ETH;
    flow_rule.eth.size           = sizeof(ibv_flow_spec_eth);
    flow_rule.eth.val.ether_type = htons(0x0800);
    flow_rule.eth.mask.ether_type = 0xFFFF;

    /* IPv4: match protocol = UDP (17) */
    flow_rule.ipv4.type          = IBV_FLOW_SPEC_IPV4;
    flow_rule.ipv4.size          = sizeof(ibv_flow_spec_ipv4);
    flow_rule.ipv4.val.src_ip    = 0;
    flow_rule.ipv4.mask.src_ip   = 0;
    flow_rule.ipv4.val.dst_ip    = 0;
    flow_rule.ipv4.mask.dst_ip   = 0;

    /* UDP: match dst_port = TICK_MCAST_PORT (5005) */
    flow_rule.udp.type           = IBV_FLOW_SPEC_UDP;
    flow_rule.udp.size           = sizeof(ibv_flow_spec_tcp_udp);
    flow_rule.udp.val.dst_port   = htons(TICK_MCAST_PORT);
    flow_rule.udp.mask.dst_port  = 0xFFFF;

    g_ibv.flow = ibv_create_flow(g_ibv.qp, &flow_rule.attr);
    if (!g_ibv.flow) {
        perror("ibv_create_flow");
        fprintf(stderr, "  Flow steering failed — try running as root\n");
        return -1;
    }
    fprintf(stderr, "[T3] flow steering: UDP dst port %d → QP\n", TICK_MCAST_PORT);

    return 0;
}

static void post_recv_wrs(GpuRdmaResources &r, int start, int count)
{
    for (int i = 0; i < count; ++i) {
        int slot = (start + i) % MAX_RECV_WR;
        ibv_sge sge{};
        sge.addr   = (uint64_t)(r.d_pkt_bufs + (size_t)slot * PKT_BUF_SIZE);
        sge.length = PKT_BUF_SIZE;
        sge.lkey   = g_ibv.mr->lkey;

        ibv_recv_wr wr{}, *bad = nullptr;
        wr.wr_id   = (uint64_t)slot;
        wr.sg_list = &sge;
        wr.num_sge = 1;
        wr.next    = nullptr;
        if (ibv_post_recv(g_ibv.qp, &wr, &bad)) {
            perror("ibv_post_recv");
        }
    }
}

/* ── GPU init ────────────────────────────────────────────────────────────── */
static void gpu_init(GpuRdmaResources &r, int batch_size)
{
    r.batch_size = batch_size;

    CUDA_CHECK(cudaMalloc(&r.d_pkt_bufs, (size_t)MAX_RECV_WR * PKT_BUF_SIZE));

    CUDA_CHECK(cudaMalloc(&r.d_ticks,   batch_size * sizeof(TickMessage)));
    CUDA_CHECK(cudaMalloc(&r.d_signals, batch_size * sizeof(SignalResult)));
    size_t state_sz = MAX_INSTRUMENTS * sizeof(double);
    CUDA_CHECK(cudaMalloc(&r.d_fast_ema, state_sz)); CUDA_CHECK(cudaMemset(r.d_fast_ema, 0, state_sz));
    CUDA_CHECK(cudaMalloc(&r.d_slow_ema, state_sz)); CUDA_CHECK(cudaMemset(r.d_slow_ema, 0, state_sz));
    CUDA_CHECK(cudaMalloc(&r.d_avg_gain, state_sz)); CUDA_CHECK(cudaMemset(r.d_avg_gain, 0, state_sz));
    CUDA_CHECK(cudaMalloc(&r.d_avg_loss, state_sz)); CUDA_CHECK(cudaMemset(r.d_avg_loss, 0, state_sz));
    CUDA_CHECK(cudaMalloc(&r.d_last_mid, state_sz)); CUDA_CHECK(cudaMemset(r.d_last_mid, 0, state_sz));

    CUDA_CHECK(cudaMallocHost(&r.h_signals,    batch_size * sizeof(SignalResult)));
    CUDA_CHECK(cudaMallocHost(&r.h_ticks_copy, batch_size * sizeof(TickMessage)));

    CUDA_CHECK(cudaStreamCreate(&r.stream));

    int dev; CUDA_CHECK(cudaGetDevice(&dev));
    int clock_khz = 0;
    CUDA_CHECK(cudaDeviceGetAttribute(&clock_khz, cudaDevAttrClockRate, dev));
    r.gpu_ns_per_cycle = 1e6 / (double)clock_khz;
}

/* ── extract_ticks_kernel: parse raw Ethernet frames into TickMessage ────── */
__global__ void extract_ticks_kernel(
    const uint8_t    * __restrict__ pkt_bufs,
    const uint32_t   * __restrict__ pkt_slots,
    int                              n,
    TickMessage      * __restrict__ ticks)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n) return;

    const uint8_t *pkt = pkt_bufs + (size_t)pkt_slots[idx] * PKT_BUF_SIZE;
    /* RAW_PACKET QP: full Ethernet frame — ETH(14) + IP(20) + UDP(8) = 42 bytes */
    const TickMessage *src = reinterpret_cast<const TickMessage *>(
        pkt + ETH_IP_UDP_HDR);
    memcpy(&ticks[idx], src, sizeof(TickMessage));
}

/* ── UDP send ────────────────────────────────────────────────────────────── */
static int make_udp_send(const char *addr, int port, sockaddr_in &dest)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_port        = htons((uint16_t)port);
    dest.sin_addr.s_addr = inet_addr(addr);
    return fd;
}

/* ── main ───────────────────────────────────────────────────────────────── */
int main(int argc, char **argv)
{
    const char *ib_dev_name  = "mlx5_0";
    int         port_num     = 1;
    int         batch_size   = DEFAULT_BATCH;
    uint8_t     tier         = 3;
    const char *harness_ip   = "127.0.0.1";
    const char *fillsim_ip   = "127.0.0.1";

    for (int i = 1; i < argc; ++i) {
        if      (!strcmp(argv[i],"--dev")       && i+1<argc) ib_dev_name = argv[++i];
        else if (!strcmp(argv[i],"--port-num")  && i+1<argc) port_num    = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--batch")     && i+1<argc) batch_size  = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--tier")      && i+1<argc) tier        = (uint8_t)atoi(argv[++i]);
        else if (!strcmp(argv[i],"--harness")   && i+1<argc) harness_ip  = argv[++i];
        else if (!strcmp(argv[i],"--fillsim")   && i+1<argc) fillsim_ip  = argv[++i];
    }

    fprintf(stderr, "[T3 rdma_receiver] ib_dev=%s port=%d batch=%d tier=%d\n",
            ib_dev_name, port_num, batch_size, tier);

    GpuRdmaResources gpu{};
    gpu_init(gpu, batch_size);

    if (ibv_init(ib_dev_name, port_num, gpu) < 0) return 1;

    post_recv_wrs(gpu, 0, MAX_RECV_WR);

    sockaddr_in harness_dest{}, signal_dest{};
    int harness_fd = make_udp_send(harness_ip, BENCH_RESULT_PORT, harness_dest);
    int signal_fd  = make_udp_send(fillsim_ip, SIGNAL_PORT, signal_dest);

    ibv_wc wcs[MAX_RECV_WR];
    uint32_t batch_slots[DEFAULT_BATCH];
    uint32_t *d_slots = nullptr;
    CUDA_CHECK(cudaMalloc(&d_slots, batch_size * sizeof(uint32_t)));

    int batch_n = 0;
    uint64_t total_rx = 0;
    uint64_t total_err = 0;
    uint64_t poll_count = 0;
    uint64_t idle_polls = 0;

    fprintf(stderr, "[T3] waiting for packets (raw packet QP)...\n");

    while (true) {
        int nc = ibv_poll_cq(g_ibv.cq, MAX_RECV_WR, wcs);
        poll_count++;

        if (poll_count % 10000000 == 0) {
            fprintf(stderr, "[T3] poll=%luM total_rx=%lu err=%lu batch_buf=%d\n",
                    poll_count / 1000000, total_rx, total_err, batch_n);
        }

        if (nc > 0) idle_polls = 0;

        for (int w = 0; w < nc; ++w) {
            if (wcs[w].status != IBV_WC_SUCCESS) {
                total_err++;
                post_recv_wrs(gpu, (int)wcs[w].wr_id, 1);
                continue;
            }

            batch_slots[batch_n++] = (uint32_t)wcs[w].wr_id;
            total_rx++;
            post_recv_wrs(gpu, (int)wcs[w].wr_id, 1);

            if (total_rx == 1)
                fprintf(stderr, "[T3] first packet received (byte_len=%u)\n", wcs[w].byte_len);

            if (batch_n >= batch_size) {
                CUDA_CHECK(cudaMemcpyAsync(d_slots, batch_slots,
                                            batch_n * sizeof(uint32_t),
                                            cudaMemcpyHostToDevice, gpu.stream));
                uint64_t t2 = now_ns();

                int blk = (batch_n + 255) / 256;
                extract_ticks_kernel<<<blk, 256, 0, gpu.stream>>>(
                    gpu.d_pkt_bufs, d_slots, batch_n, gpu.d_ticks);

                launch_process_ticks(gpu.d_ticks, batch_n,
                                      gpu.d_signals,
                                      gpu.d_fast_ema, gpu.d_slow_ema,
                                      gpu.d_avg_gain, gpu.d_avg_loss, gpu.d_last_mid,
                                      t2, gpu.stream);
                CUDA_CHECK(cudaStreamSynchronize(gpu.stream));

                CUDA_CHECK(cudaMemcpyAsync(gpu.h_signals, gpu.d_signals,
                                            batch_n * sizeof(SignalResult),
                                            cudaMemcpyDeviceToHost, gpu.stream));
                CUDA_CHECK(cudaMemcpyAsync(gpu.h_ticks_copy, gpu.d_ticks,
                                            batch_n * sizeof(TickMessage),
                                            cudaMemcpyDeviceToHost, gpu.stream));
                CUDA_CHECK(cudaStreamSynchronize(gpu.stream));

                for (int i = 0; i < batch_n; ++i) {
                    const TickMessage  &tick = gpu.h_ticks_copy[i];
                    const SignalResult &sig  = gpu.h_signals[i];

                    uint64_t t3 = t2 + (uint64_t)(sig.t3_ns * gpu.gpu_ns_per_cycle);
                    uint64_t t4 = t2 + (uint64_t)(sig.t4_ns * gpu.gpu_ns_per_cycle);

                    BenchmarkResult br{};
                    br.tick_id = tick.tick_id;
                    br.t1_ns   = tick.timestamp_ns;
                    br.t2_ns   = t2;
                    br.t3_ns   = t3;
                    br.t4_ns   = t4;
                    br.tier    = tier;
                    sendto(harness_fd, &br, sizeof(br), 0,
                           reinterpret_cast<const sockaddr *>(&harness_dest),
                           sizeof(harness_dest));

                    SignalResult out = sig;
                    out.t3_ns = t3; out.t4_ns = t4;
                    sendto(signal_fd, &out, sizeof(out), 0,
                           reinterpret_cast<const sockaddr *>(&signal_dest),
                           sizeof(signal_dest));
                }
                fprintf(stderr, "[T3] batch: processed %d ticks (total_rx=%lu)\n",
                        batch_n, total_rx);
                batch_n = 0;
            }
        }

        /* Partial flush after idle period */
        if (nc == 0 && batch_n > 0) {
            idle_polls++;
            if (idle_polls >= 1000000) {
                CUDA_CHECK(cudaMemcpyAsync(d_slots, batch_slots,
                                            batch_n * sizeof(uint32_t),
                                            cudaMemcpyHostToDevice, gpu.stream));
                uint64_t t2 = now_ns();

                int blk = (batch_n + 255) / 256;
                extract_ticks_kernel<<<blk, 256, 0, gpu.stream>>>(
                    gpu.d_pkt_bufs, d_slots, batch_n, gpu.d_ticks);

                launch_process_ticks(gpu.d_ticks, batch_n,
                                      gpu.d_signals,
                                      gpu.d_fast_ema, gpu.d_slow_ema,
                                      gpu.d_avg_gain, gpu.d_avg_loss, gpu.d_last_mid,
                                      t2, gpu.stream);
                CUDA_CHECK(cudaStreamSynchronize(gpu.stream));

                CUDA_CHECK(cudaMemcpyAsync(gpu.h_signals, gpu.d_signals,
                                            batch_n * sizeof(SignalResult),
                                            cudaMemcpyDeviceToHost, gpu.stream));
                CUDA_CHECK(cudaMemcpyAsync(gpu.h_ticks_copy, gpu.d_ticks,
                                            batch_n * sizeof(TickMessage),
                                            cudaMemcpyDeviceToHost, gpu.stream));
                CUDA_CHECK(cudaStreamSynchronize(gpu.stream));

                for (int i = 0; i < batch_n; ++i) {
                    const TickMessage  &tick = gpu.h_ticks_copy[i];
                    const SignalResult &sig  = gpu.h_signals[i];

                    uint64_t t3 = t2 + (uint64_t)(sig.t3_ns * gpu.gpu_ns_per_cycle);
                    uint64_t t4 = t2 + (uint64_t)(sig.t4_ns * gpu.gpu_ns_per_cycle);

                    BenchmarkResult br{};
                    br.tick_id = tick.tick_id;
                    br.t1_ns   = tick.timestamp_ns;
                    br.t2_ns   = t2;
                    br.t3_ns   = t3;
                    br.t4_ns   = t4;
                    br.tier    = tier;
                    sendto(harness_fd, &br, sizeof(br), 0,
                           reinterpret_cast<const sockaddr *>(&harness_dest),
                           sizeof(harness_dest));

                    SignalResult out = sig;
                    out.t3_ns = t3; out.t4_ns = t4;
                    sendto(signal_fd, &out, sizeof(out), 0,
                           reinterpret_cast<const sockaddr *>(&signal_dest),
                           sizeof(signal_dest));
                }
                fprintf(stderr, "[T3] batch: processed %d ticks (partial flush, total_rx=%lu)\n",
                        batch_n, total_rx);
                batch_n = 0;
                idle_polls = 0;
            }
        }
    }

    if (g_ibv.flow) ibv_destroy_flow(g_ibv.flow);
    ibv_destroy_qp(g_ibv.qp);
    ibv_destroy_cq(g_ibv.cq);
    ibv_dereg_mr(g_ibv.mr);
    ibv_dealloc_pd(g_ibv.pd);
    ibv_close_device(g_ibv.ctx);
    return 0;
}
