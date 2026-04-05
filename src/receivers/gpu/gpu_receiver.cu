/*
 * gpu_receiver.cu — T4 and T5: DOCA GPUNetIO receiver.
 *
 * THIS BINARY IS IDENTICAL FOR T4 AND T5.
 * Deployment difference:
 *   T4 — data_source runs on host CPU, this binary runs on host GPU.
 *   T5 — data_source (live bridge) runs on BlueField DPU ARM,
 *         this binary still runs on the same host GPU.
 *
 * Data path (both T4 and T5):
 *   NIC -> DOCA GPUNetIO RX queue -> GPU kernel (persistent)
 *       -> in-kernel processing (mid, EMA, signal)
 *       -> BenchmarkResult -> harness (via host UDP thread)
 *       -> SignalResult -> fill_simulator
 *
 * DOCA SDK version: 3.x (uses doca_gpunetio_dev_eth_rxq.cuh)
 *
 * Usage:
 *   gpu_receiver --iface <interface> [--gpu 1] [--tier 4]
 *                [--harness <ip>] [--fillsim <ip>]
 */

#include <doca_gpunetio.h>
#include <doca_gpunetio_dev_eth_rxq.cuh>
#include <doca_gpunetio_dev_buf.cuh>
#include <doca_eth_rxq.h>
#include <doca_dev.h>
#include <doca_error.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <chrono>

#include <cuda_runtime.h>

#include "tick_message.h"
#include "benchmark_result.h"
#include "signal_result.h"

/* ── Constants ───────────────────────────────────────��───────────────────── */
#define MAX_PKT_PER_BURST  64
#define MAX_PKT_NUM        2048
#define MAX_PKT_SIZE       2048
#define ETH_IP_UDP_HDR     42       /* 14 + 20 + 8 */
#define RESULT_QUEUE_DEPTH 4096
#define MAX_RX_TIMEOUT_NS  500000ULL  /* 0.5ms timeout */

#define CUDA_CHECK(call) \
    do { cudaError_t _e=(call); if(_e!=cudaSuccess){ \
        fprintf(stderr,"CUDA %s:%d: %s\n",__FILE__,__LINE__,cudaGetErrorString(_e)); exit(1); \
    }} while(0)

#define DOCA_CHECK(call) \
    do { doca_error_t _e=(call); if(_e!=DOCA_SUCCESS){ \
        fprintf(stderr,"DOCA %s:%d: %s\n",__FILE__,__LINE__,doca_error_get_descr(_e)); exit(1); \
    }} while(0)

/* ── Atomic EMA CAS update (device) ─────────────────────────────────────── */
__device__ static double ema_cas(double *slot, double sample, double alpha)
{
    unsigned long long *addr = reinterpret_cast<unsigned long long *>(slot);
    unsigned long long expected, desired;
    double old_val, new_val;
    do {
        expected = atomicAdd(addr, 0ULL);
        old_val  = __longlong_as_double((long long)expected);
        if (old_val == 0.0) old_val = sample;
        new_val  = alpha * sample + (1.0 - alpha) * old_val;
        desired  = (unsigned long long)__double_as_longlong(new_val);
    } while (atomicCAS(addr, expected, desired) != expected);
    return new_val;
}

__device__ static double rsi_cas(double *slot, double sample, double alpha)
{
    unsigned long long *addr = reinterpret_cast<unsigned long long *>(slot);
    unsigned long long expected, desired;
    double old_val, new_val;
    do {
        expected = atomicAdd(addr, 0ULL);
        old_val  = __longlong_as_double((long long)expected);
        new_val  = alpha * sample + (1.0 - alpha) * old_val;
        desired  = (unsigned long long)__double_as_longlong(new_val);
    } while (atomicCAS(addr, expected, desired) != expected);
    return new_val;
}

/* ── GPU result ring (GPU -> CPU readback) ────────────────────────────────── */
struct ResultSlot {
    BenchmarkResult bench;
    SignalResult    signal;
};

struct ResultRing {
    ResultSlot  *slots   = nullptr;
    uint64_t    *head    = nullptr;
    uint64_t     tail    = 0;
    uint32_t     depth   = RESULT_QUEUE_DEPTH;
};

/* ── GPUNetIO persistent receive + process kernel (DOCA 3.x API) ─────────── */
/*
 * Uses doca_gpu_dev_eth_rxq_recv with template parameters:
 *   DOCA_GPUNETIO_ETH_EXEC_SCOPE_BLOCK — all threads in block participate
 *   DOCA_GPUNETIO_ETH_MCST_AUTO        — automatic multicast handling
 *   DOCA_GPUNETIO_ETH_NIC_HANDLER_AUTO — automatic NIC handler
 *
 * Thread 0 drives the receive; all threads process their assigned packet.
 */
__global__ void gpu_recv_process_kernel(
    struct doca_gpu_eth_rxq *rxq,
    volatile uint32_t       *quit_flag,
    double                  *d_fast_ema,
    double                  *d_slow_ema,
    double                  *d_avg_gain,
    double                  *d_avg_loss,
    double                  *d_last_mid,
    ResultSlot              *result_ring,
    volatile uint64_t       *ring_head,
    uint32_t                 ring_depth,
    uint8_t                  tier)
{
    const int tid = threadIdx.x;

    while (!*quit_flag) {
        /* ── Receive a burst of packets (block-scope) ── */
        uint64_t first_pkt_idx = 0;
        uint32_t n_pkts = 0;

        doca_error_t ret = doca_gpu_dev_eth_rxq_recv<
            DOCA_GPUNETIO_ETH_EXEC_SCOPE_BLOCK,
            DOCA_GPUNETIO_ETH_MCST_AUTO,
            DOCA_GPUNETIO_ETH_NIC_HANDLER_AUTO>(
                rxq,
                MAX_PKT_PER_BURST,
                MAX_RX_TIMEOUT_NS,
                &first_pkt_idx,
                &n_pkts,
                NULL);

        __syncthreads();

        if (ret != DOCA_SUCCESS || n_pkts == 0) continue;

        /* ── Each thread processes one packet ── */
        bool processed = false;

        if (tid < (int)n_pkts) {
            uintptr_t buf_addr = doca_gpu_dev_eth_rxq_get_pkt_addr(
                rxq, first_pkt_idx + tid);
            const uint8_t *pkt = reinterpret_cast<const uint8_t *>(buf_addr);

            /* Verify minimum length */
            if (buf_addr != 0) {
                /* Skip Ethernet + IP + UDP headers */
                const uint8_t *udp_hdr = pkt + 14 + 20;
                uint16_t dst_port = (uint16_t)((udp_hdr[2] << 8) | udp_hdr[3]);

                if (dst_port == TICK_MCAST_PORT) {
                    const TickMessage *tick =
                        reinterpret_cast<const TickMessage *>(pkt + ETH_IP_UDP_HDR);

                    /* T2: tick is now in GPU memory */
                    uint64_t t2 = clock64();

                    /* Compute mid and spread */
                    double mid    = (tick->bid + tick->ask) * 0.5;
                    double spread =  tick->ask - tick->bid;
                    int    inst   =  tick->instrument_id % MAX_INSTRUMENTS;

                    /* Dual EMA update */
                    double fast_ema = ema_cas(&d_fast_ema[inst], mid, EMA_ALPHA_FAST);
                    double slow_ema = ema_cas(&d_slow_ema[inst], mid, EMA_ALPHA_SLOW);

                    /* RSI update */
                    double last_mid = d_last_mid[inst];
                    if (last_mid == 0.0) last_mid = mid;
                    double delta   = mid - last_mid;
                    double g       = (delta > 0.0) ? delta : 0.0;
                    double l       = (delta < 0.0) ? -delta : 0.0;
                    double avg_gain = rsi_cas(&d_avg_gain[inst], g, RSI_ALPHA);
                    double avg_loss = rsi_cas(&d_avg_loss[inst], l, RSI_ALPHA);
                    *(unsigned long long *)&d_last_mid[inst] =
                        (unsigned long long)__double_as_longlong(mid);

                    double rs_val = (avg_loss > 1e-12) ? avg_gain / avg_loss : 100.0;
                    float  rsi    = (float)(100.0 - 100.0 / (1.0 + rs_val));
                    rsi = fmaxf(0.0f, fminf(100.0f, rsi));

                    /* EMA crossover signal */
                    int8_t ema_sig = 0;
                    if (slow_ema > 0.0) {
                        double cross = (fast_ema - slow_ema) / slow_ema;
                        if (cross >  EMA_CROSS_THRESH) ema_sig = +1;
                        if (cross < -EMA_CROSS_THRESH) ema_sig = -1;
                    }

                    /* RSI signal */
                    int8_t rsi_sig = 0;
                    if (rsi < RSI_OVERSOLD)   rsi_sig = +1;
                    if (rsi > RSI_OVERBOUGHT) rsi_sig = -1;

                    /* Combined signal */
                    int8_t combined = 0;
                    if (ema_sig != 0 && ema_sig == rsi_sig) combined = ema_sig;

                    /* T3: kernel done */
                    uint64_t t3 = clock64();

                    /* Write to result ring */
                    uint64_t ring_idx = atomicAdd(
                        reinterpret_cast<unsigned long long *>(
                            const_cast<uint64_t *>(ring_head)), 1ULL);
                    ResultSlot *rslot = &result_ring[ring_idx % ring_depth];

                    rslot->bench.tick_id = tick->tick_id;
                    rslot->bench.t1_ns   = tick->timestamp_ns;
                    rslot->bench.t2_ns   = t2;
                    rslot->bench.t3_ns   = t3;
                    rslot->bench.t4_ns   = 0;
                    rslot->bench.tier    = tier;
                    rslot->bench.dropped = 0;
                    memset(rslot->bench._pad, 0, sizeof(rslot->bench._pad));

                    rslot->signal.tick_id       = tick->tick_id;
                    rslot->signal.t3_ns         = t3;
                    rslot->signal.instrument_id = tick->instrument_id;
                    rslot->signal.signal        = combined;
                    rslot->signal.rsi_signal    = rsi_sig;
                    rslot->signal.rsi           = rsi;
                    rslot->signal.mid_price     = mid;
                    rslot->signal.spread        = spread;
                    rslot->signal.fast_ema      = fast_ema;
                    rslot->signal.slow_ema      = slow_ema;

                    __threadfence();
                    uint64_t t4 = clock64();
                    rslot->bench.t4_ns  = t4;
                    rslot->signal.t4_ns = t4;

                    processed = true;
                }
            }
        }

        /* Ensure all threads complete before next burst */
        (void)processed;
        __syncthreads();
    }
}

/* ── CPU forwarding thread ──────────────────────────────────────��─────────── */
struct ForwardCtx {
    ResultRing        *ring        = nullptr;
    double             ns_per_cyc  = 1.0;
    int                harness_fd  = -1;
    int                signal_fd   = -1;
    sockaddr_in        harness_dest{};
    sockaddr_in        signal_dest{};
    std::atomic<bool>  stop{false};
};

static uint64_t cyc_to_ns(uint64_t cyc, double ns_per_cyc)
{
    return (uint64_t)((double)cyc * ns_per_cyc);
}

static void cpu_forward_thread(ForwardCtx *ctx)
{
    while (!ctx->stop.load()) {
        uint64_t head = *ctx->ring->head;
        while (ctx->ring->tail < head) {
            uint64_t idx = ctx->ring->tail % ctx->ring->depth;
            ResultSlot *rs = &ctx->ring->slots[idx];

            BenchmarkResult br  = rs->bench;
            SignalResult    sig = rs->signal;

            br.t2_ns  = cyc_to_ns(br.t2_ns,  ctx->ns_per_cyc);
            br.t3_ns  = cyc_to_ns(br.t3_ns,  ctx->ns_per_cyc);
            br.t4_ns  = cyc_to_ns(br.t4_ns,  ctx->ns_per_cyc);
            sig.t3_ns = br.t3_ns;
            sig.t4_ns = br.t4_ns;

            sendto(ctx->harness_fd, &br, sizeof(br), 0,
                   reinterpret_cast<const sockaddr *>(&ctx->harness_dest),
                   sizeof(ctx->harness_dest));
            sendto(ctx->signal_fd, &sig, sizeof(sig), 0,
                   reinterpret_cast<const sockaddr *>(&ctx->signal_dest),
                   sizeof(ctx->signal_dest));

            ++ctx->ring->tail;
        }
        std::this_thread::sleep_for(std::chrono::microseconds(10));
    }
}

/* ── DOCA host-side initialisation (DOCA 3.x API) ─────────────────────── */
struct DocaContext {
    struct doca_dev         *dev       = nullptr;
    struct doca_gpu         *gpu_dev   = nullptr;
    struct doca_eth_rxq     *rxq_cpu   = nullptr;
    struct doca_gpu_eth_rxq *rxq_gpu   = nullptr;
};

static int doca_init(DocaContext &doca, const char *gpu_pcie, int cuda_device)
{
    CUDA_CHECK(cudaSetDevice(cuda_device));

    /* Open DOCA device — use first available */
    struct doca_devinfo **dev_list;
    uint32_t nb_devs;
    DOCA_CHECK(doca_devinfo_create_list(&dev_list, &nb_devs));

    bool found = false;
    for (uint32_t i = 0; i < nb_devs; ++i) {
        doca_error_t r = doca_dev_open(dev_list[i], &doca.dev);
        if (r == DOCA_SUCCESS) {
            fprintf(stderr, "[gpu_receiver] DOCA device opened: index %u\n", i);
            found = true;
            break;
        }
    }
    doca_devinfo_destroy_list(dev_list);
    if (!found) {
        fprintf(stderr, "No DOCA device found\n");
        return -1;
    }

    /* Create DOCA GPU context */
    DOCA_CHECK(doca_gpu_create(gpu_pcie, &doca.gpu_dev));

    /* Create ETH RX queue */
    DOCA_CHECK(doca_eth_rxq_create(doca.dev, MAX_PKT_NUM, MAX_PKT_SIZE,
                                    &doca.rxq_cpu));

    /* Set RXQ type to CYCLIC for GPU-side receive */
    DOCA_CHECK(doca_eth_rxq_set_type(doca.rxq_cpu, DOCA_ETH_RXQ_TYPE_CYCLIC));

    /* Get GPU handle */
    DOCA_CHECK(doca_eth_rxq_get_gpu_handle(doca.rxq_cpu, &doca.rxq_gpu));

    fprintf(stderr, "[gpu_receiver] DOCA init OK — GPU PCIe: %s\n", gpu_pcie);
    return 0;
}

/* ── UDP send socket helper ─────────────────────────────────────────────── */
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
static volatile uint32_t g_quit = 0;
static void sig_handler(int) { g_quit = 1; }

int main(int argc, char **argv)
{
    const char *gpu_pcie      = "";
    int         cuda_device   = 1;   /* GPU 1 (GPU 0 has VLLM) */
    uint8_t     tier          = 4;
    const char *harness_ip    = "127.0.0.1";
    const char *fillsim_ip    = "127.0.0.1";

    for (int i = 1; i < argc; ++i) {
        if      (!strcmp(argv[i],"--gpu-pcie")  && i+1<argc) gpu_pcie     = argv[++i];
        else if (!strcmp(argv[i],"--gpu")       && i+1<argc) cuda_device  = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--tier")      && i+1<argc) tier         = (uint8_t)atoi(argv[++i]);
        else if (!strcmp(argv[i],"--harness")   && i+1<argc) harness_ip   = argv[++i];
        else if (!strcmp(argv[i],"--fillsim")   && i+1<argc) fillsim_ip   = argv[++i];
    }

    fprintf(stderr, "[T%d gpu_receiver] gpu=%d pcie=%s\n", tier, cuda_device, gpu_pcie);

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    CUDA_CHECK(cudaSetDevice(cuda_device));

    /* Get GPU clock rate for ns conversion */
    int clock_khz = 0;
    CUDA_CHECK(cudaDeviceGetAttribute(&clock_khz, cudaDevAttrClockRate, cuda_device));
    double ns_per_cyc = 1e6 / (double)clock_khz;

    /* DOCA init */
    DocaContext doca{};
    if (doca_init(doca, gpu_pcie, cuda_device) < 0) return 1;

    /* Per-instrument state arrays */
    double *d_fast_ema = nullptr, *d_slow_ema = nullptr;
    double *d_avg_gain = nullptr, *d_avg_loss = nullptr, *d_last_mid = nullptr;
    size_t state_sz = MAX_INSTRUMENTS * sizeof(double);
    CUDA_CHECK(cudaMalloc(&d_fast_ema, state_sz)); CUDA_CHECK(cudaMemset(d_fast_ema, 0, state_sz));
    CUDA_CHECK(cudaMalloc(&d_slow_ema, state_sz)); CUDA_CHECK(cudaMemset(d_slow_ema, 0, state_sz));
    CUDA_CHECK(cudaMalloc(&d_avg_gain, state_sz)); CUDA_CHECK(cudaMemset(d_avg_gain, 0, state_sz));
    CUDA_CHECK(cudaMalloc(&d_avg_loss, state_sz)); CUDA_CHECK(cudaMemset(d_avg_loss, 0, state_sz));
    CUDA_CHECK(cudaMalloc(&d_last_mid, state_sz)); CUDA_CHECK(cudaMemset(d_last_mid, 0, state_sz));

    /* Result ring: host-mapped pinned memory for GPU->CPU transfer */
    ResultRing ring{};
    ring.depth = RESULT_QUEUE_DEPTH;
    CUDA_CHECK(cudaMallocHost(&ring.slots, ring.depth * sizeof(ResultSlot)));
    CUDA_CHECK(cudaMallocHost(&ring.head,  sizeof(uint64_t)));
    *ring.head = 0;
    ring.tail  = 0;

    /* Quit flag (device-accessible) */
    uint32_t *d_quit = nullptr;
    CUDA_CHECK(cudaMalloc(&d_quit, sizeof(uint32_t)));
    CUDA_CHECK(cudaMemset(d_quit, 0, sizeof(uint32_t)));

    /* Output sockets */
    sockaddr_in harness_dest{}, signal_dest{};
    int harness_fd = make_udp_send(harness_ip, BENCH_RESULT_PORT, harness_dest);
    int signal_fd  = make_udp_send(fillsim_ip, SIGNAL_PORT, signal_dest);

    /* CPU forwarding thread */
    ForwardCtx fwd_ctx{};
    fwd_ctx.ring         = &ring;
    fwd_ctx.ns_per_cyc   = ns_per_cyc;
    fwd_ctx.harness_fd   = harness_fd;
    fwd_ctx.signal_fd    = signal_fd;
    fwd_ctx.harness_dest = harness_dest;
    fwd_ctx.signal_dest  = signal_dest;
    std::thread fwd_thread(cpu_forward_thread, &fwd_ctx);

    /* Launch persistent GPU receive kernel */
    fprintf(stderr, "[gpu_receiver] launching persistent GPU kernel...\n");
    gpu_recv_process_kernel<<<1, MAX_PKT_PER_BURST>>>(
        doca.rxq_gpu,
        d_quit,
        d_fast_ema, d_slow_ema, d_avg_gain, d_avg_loss, d_last_mid,
        ring.slots,
        ring.head,
        ring.depth,
        tier);

    /* Wait for SIGINT / SIGTERM */
    while (!g_quit) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    fprintf(stderr, "[gpu_receiver] stopping...\n");

    /* Signal kernel to stop */
    uint32_t one = 1;
    CUDA_CHECK(cudaMemcpy(d_quit, &one, sizeof(one), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaDeviceSynchronize());

    /* Stop forwarding thread */
    fwd_ctx.stop = true;
    fwd_thread.join();

    /* Cleanup */
    doca_eth_rxq_destroy(doca.rxq_cpu);
    doca_gpu_destroy(doca.gpu_dev);
    doca_dev_close(doca.dev);

    cudaFree(d_fast_ema);
    cudaFree(d_slow_ema);
    cudaFree(d_avg_gain);
    cudaFree(d_avg_loss);
    cudaFree(d_last_mid);
    cudaFree(d_quit);
    cudaFreeHost(ring.slots);
    cudaFreeHost(ring.head);
    close(harness_fd);
    close(signal_fd);

    fprintf(stderr, "[gpu_receiver] done\n");
    return 0;
}
