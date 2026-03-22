/*
 * rdma_receiver.cu — T3: GPU RDMA receiver.
 *
 * Data path:
 *   NIC → libibverbs UD QP → DMA directly into GPU memory (nv_peer_mem)
 *       → process_ticks_kernel (already in GPU memory, NO cudaMemcpy)
 *       → BenchmarkResult → harness
 *
 * Key difference from T1/T2: nv_peer_mem (or nvidia_peermem) kernel module
 * allows ibverbs to register GPU memory regions.  The NIC writes received
 * packets straight into device memory — the cudaMemcpy H→D step is eliminated.
 *
 * Prerequisites on the server:
 *   sudo modprobe nv_peer_mem   (or nvidia-peermem on newer drivers)
 *   sudo modprobe ib_uverbs rdma_ucm
 *
 * Usage:
 *   rdma_receiver --dev mlx5_0 --gid-index 1 [--batch 256] [--tier 3]
 */

#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>

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
#define INLINE_THRESH   0
/* Buffer size: Ethernet frame up to 1500 bytes per slot */
#define PKT_BUF_SIZE    1500
#define ETH_IP_UDP_HDR  42

#define CUDA_CHECK(call) \
    do { cudaError_t _e=(call); if(_e!=cudaSuccess){ \
        fprintf(stderr,"CUDA %s:%d: %s\n",__FILE__,__LINE__,cudaGetErrorString(_e)); exit(1); \
    }} while(0)

#define IBV_CHECK(call, msg) \
    do { if ((call)) { perror(msg); exit(1); } } while(0)

/* ── GPU-registered receive buffers ─────────────────────────────────────── */
struct GpuRdmaResources {
    /* GPU memory used as RDMA receive buffers */
    uint8_t          *d_pkt_bufs   = nullptr;    /* [MAX_RECV_WR * PKT_BUF_SIZE] */
    TickMessage      *d_ticks      = nullptr;    /* extracted tick data */
    SignalResult     *d_signals    = nullptr;
    double           *d_fast_ema   = nullptr;
    double           *d_slow_ema   = nullptr;
    double           *d_avg_gain   = nullptr;
    double           *d_avg_loss   = nullptr;
    double           *d_last_mid   = nullptr;

    /* Host pinned for results readback */
    SignalResult     *h_signals    = nullptr;
    TickMessage      *h_ticks_copy = nullptr;   /* for BenchmarkResult assembly */

    cudaStream_t      stream       = nullptr;
    double            gpu_ns_per_cycle = 1.0;
    int               batch_size   = DEFAULT_BATCH;
};

/* ── ibverbs state ───────────────────────────────────────────────────────── */
struct IbvState {
    ibv_context   *ctx   = nullptr;
    ibv_pd        *pd    = nullptr;
    ibv_mr        *mr    = nullptr;   /* GPU MR — requires nv_peer_mem */
    ibv_cq        *cq    = nullptr;
    ibv_qp        *qp    = nullptr;
};

static IbvState g_ibv{};

static int ibv_init(const char *dev_name, int gid_index, GpuRdmaResources &r)
{
    int num_devices;
    ibv_device **dev_list = ibv_get_device_list(&num_devices);
    if (!dev_list || num_devices == 0) {
        fprintf(stderr, "No IB devices found\n"); return -1;
    }

    ibv_device *dev = nullptr;
    for (int i = 0; i < num_devices; ++i) {
        if (!strcmp(ibv_get_device_name(dev_list[i]), dev_name)) {
            dev = dev_list[i]; break;
        }
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

    /*
     * Register GPU memory as an MR.
     * This succeeds only if nv_peer_mem / nvidia_peermem is loaded.
     * The NIC's DMA engine will write received packets directly into GPU memory.
     */
    size_t pkt_buf_total = (size_t)MAX_RECV_WR * PKT_BUF_SIZE;
    g_ibv.mr = ibv_reg_mr(g_ibv.pd, r.d_pkt_bufs, pkt_buf_total,
                            IBV_ACCESS_LOCAL_WRITE |
                            IBV_ACCESS_REMOTE_WRITE);
    if (!g_ibv.mr) {
        fprintf(stderr, "ibv_reg_mr failed — is nv_peer_mem loaded?\n");
        return -1;
    }

    g_ibv.cq = ibv_create_cq(g_ibv.ctx, MAX_RECV_WR * 2, nullptr, nullptr, 0);
    if (!g_ibv.cq) { perror("ibv_create_cq"); return -1; }

    ibv_qp_init_attr qp_attr{};
    qp_attr.send_cq          = g_ibv.cq;
    qp_attr.recv_cq          = g_ibv.cq;
    qp_attr.qp_type          = IBV_QPT_UD;
    qp_attr.cap.max_send_wr  = 1;
    qp_attr.cap.max_recv_wr  = MAX_RECV_WR;
    qp_attr.cap.max_send_sge = 1;
    qp_attr.cap.max_recv_sge = 1;

    g_ibv.qp = ibv_create_qp(g_ibv.pd, &qp_attr);
    if (!g_ibv.qp) { perror("ibv_create_qp"); return -1; }

    /* Transition QP: RESET → INIT → RTR */
    ibv_qp_attr attr{};
    attr.qp_state   = IBV_QPS_INIT;
    attr.port_num   = 1;
    attr.pkey_index = 0;
    attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE;
    IBV_CHECK(ibv_modify_qp(g_ibv.qp, &attr,
                             IBV_QP_STATE | IBV_QP_PKEY_INDEX |
                             IBV_QP_PORT  | IBV_QP_ACCESS_FLAGS),
              "QP RESET→INIT");

    memset(&attr, 0, sizeof(attr));
    attr.qp_state      = IBV_QPS_RTR;
    attr.path_mtu      = IBV_MTU_1024;
    attr.rq_psn        = 0;
    attr.max_dest_rd_atomic = 0;
    attr.min_rnr_timer = 0;
    attr.ah_attr.port_num       = 1;
    attr.ah_attr.is_global      = 1;
    attr.ah_attr.grh.sgid_index = (uint8_t)gid_index;
    attr.ah_attr.grh.hop_limit  = 1;
    /* dgid = multicast group 239.0.0.1 mapped to GID ff1e::ef00:0001 */
    attr.ah_attr.grh.dgid.raw[0]  = 0xff; attr.ah_attr.grh.dgid.raw[1] = 0x1e;
    attr.ah_attr.grh.dgid.raw[12] = 0xef; attr.ah_attr.grh.dgid.raw[13] = 0x00;
    attr.ah_attr.grh.dgid.raw[14] = 0x00; attr.ah_attr.grh.dgid.raw[15] = 0x01;
    IBV_CHECK(ibv_modify_qp(g_ibv.qp, &attr,
                             IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU |
                             IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
                             IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER),
              "QP INIT→RTR");

    (void)gid_index;
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
        ibv_post_recv(g_ibv.qp, &wr, &bad);
    }
}

/* ── GPU init ────────────────────────────────────────────────────────────── */
static void gpu_init(GpuRdmaResources &r, int batch_size)
{
    r.batch_size = batch_size;

    /* GPU receive buffers — registered with ibverbs */
    CUDA_CHECK(cudaMalloc(&r.d_pkt_bufs, (size_t)MAX_RECV_WR * PKT_BUF_SIZE));

    /* Processing buffers */
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
    cudaDeviceProp p; CUDA_CHECK(cudaGetDeviceProperties(&p, dev));
    r.gpu_ns_per_cycle = 1e6 / (double)p.clockRate;
}

/* ── extract_ticks_kernel: parse raw Ethernet frames into TickMessage ────── */
__global__ void extract_ticks_kernel(
    const uint8_t    * __restrict__ pkt_bufs,   /* [n * PKT_BUF_SIZE] */
    const uint32_t   * __restrict__ pkt_slots,  /* which slots received */
    int                              n,
    TickMessage      * __restrict__ ticks)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n) return;

    const uint8_t *pkt = pkt_bufs + (size_t)pkt_slots[idx] * PKT_BUF_SIZE;
    /* UD QP adds a 40-byte Global Routing Header before the payload */
    const TickMessage *src = reinterpret_cast<const TickMessage *>(
        pkt + 40 /* GRH */ + 8 /* UDP */ );
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
    int         gid_index    = 1;
    int         batch_size   = DEFAULT_BATCH;
    uint8_t     tier         = 3;
    const char *harness_ip   = "127.0.0.1";
    const char *fillsim_ip   = "127.0.0.1";

    for (int i = 1; i < argc; ++i) {
        if      (!strcmp(argv[i],"--dev")       && i+1<argc) ib_dev_name = argv[++i];
        else if (!strcmp(argv[i],"--gid-index") && i+1<argc) gid_index   = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--batch")     && i+1<argc) batch_size  = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--tier")      && i+1<argc) tier        = (uint8_t)atoi(argv[++i]);
        else if (!strcmp(argv[i],"--harness")   && i+1<argc) harness_ip  = argv[++i];
        else if (!strcmp(argv[i],"--fillsim")   && i+1<argc) fillsim_ip  = argv[++i];
    }

    fprintf(stderr, "[T3 rdma_receiver] ib_dev=%s gid=%d batch=%d tier=%d\n",
            ib_dev_name, gid_index, batch_size, tier);

    GpuRdmaResources gpu{};
    gpu_init(gpu, batch_size);

    if (ibv_init(ib_dev_name, gid_index, gpu) < 0) return 1;

    /* Pre-post all receive WRs */
    post_recv_wrs(gpu, 0, MAX_RECV_WR);

    sockaddr_in harness_dest{}, signal_dest{};
    int harness_fd = make_udp_send(harness_ip, BENCH_RESULT_PORT, harness_dest);
    int signal_fd  = make_udp_send(fillsim_ip, SIGNAL_PORT, signal_dest);

    ibv_wc wcs[MAX_RECV_WR];
    uint32_t batch_slots[DEFAULT_BATCH];
    uint32_t *d_slots = nullptr;
    CUDA_CHECK(cudaMalloc(&d_slots, batch_size * sizeof(uint32_t)));

    int batch_n = 0;

    fprintf(stderr, "[T3] waiting for RDMA completions...\n");

    while (true) {
        int nc = ibv_poll_cq(g_ibv.cq, MAX_RECV_WR, wcs);
        for (int w = 0; w < nc; ++w) {
            if (wcs[w].status != IBV_WC_SUCCESS) continue;
            if (wcs[w].opcode != IBV_WC_RECV)    continue;

            batch_slots[batch_n++] = (uint32_t)wcs[w].wr_id;
            post_recv_wrs(gpu, (int)wcs[w].wr_id, 1);  /* re-post slot */

            if (batch_n >= batch_size) {
                /* Upload slot indices to GPU */
                CUDA_CHECK(cudaMemcpyAsync(d_slots, batch_slots,
                                            batch_n * sizeof(uint32_t),
                                            cudaMemcpyHostToDevice, gpu.stream));
                /* T2: ticks arrived in GPU memory when DMA completed;
                 * we use now() as a conservative upper bound */
                uint64_t t2 = now_ns();

                /* Extract TickMessage from raw packet buffers (all on GPU) */
                int blk = (batch_n + 255) / 256;
                extract_ticks_kernel<<<blk, 256, 0, gpu.stream>>>(
                    gpu.d_pkt_bufs, d_slots, batch_n, gpu.d_ticks);

                /* Process */
                launch_process_ticks(gpu.d_ticks, batch_n,
                                      gpu.d_signals,
                                      gpu.d_fast_ema, gpu.d_slow_ema,
                                      gpu.d_avg_gain, gpu.d_avg_loss, gpu.d_last_mid,
                                      t2, gpu.stream);
                CUDA_CHECK(cudaStreamSynchronize(gpu.stream));

                /* Readback signals + ticks for BenchmarkResult */
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
                batch_n = 0;
            }
        }
    }

    return 0;
}
