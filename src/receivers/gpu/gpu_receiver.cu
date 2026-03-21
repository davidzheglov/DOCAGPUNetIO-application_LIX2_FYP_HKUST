/*
 * gpu_receiver.cu — T4 and T5: DOCA GPUNetIO receiver.
 *
 * THIS BINARY IS IDENTICAL FOR T4 AND T5.
 * Deployment difference:
 *   T4 — data_source runs on host CPU, this binary runs on host GPU.
 *   T5 — data_source (live bridge) runs on BlueField DPU ARM,
 *         this binary still runs on the same host GPU.
 *   The host GPU binary does not change between T4 and T5.
 *
 * Data path (both T4 and T5):
 *   NIC → DOCA GPUNetIO RX queue → GPU kernel (doca_gpu_eth_rxq_recv_strong)
 *       → in-kernel processing (mid, EMA, signal)
 *       → BenchmarkResult → harness (via host UDP thread)
 *       → SignalResult → fill_simulator
 *
 * The GPU manages its own receive queues.  The CPU is only involved in
 * DOCA context setup and result forwarding.  Host CPU usage drops to ~5%
 * in T5 because the data source is offloaded to the DPU.
 *
 * DOCA SDK version: 2.x
 * Verify exact API names against your installed SDK:
 *   /opt/mellanox/doca/include/doca_gpunetio.h
 *
 * Usage:
 *   gpu_receiver --iface <interface> [--batch 256] [--tier 4]
 *                [--harness <ip>] [--alpha 0.01] [--threshold 0.001]
 */

#include <doca_gpunetio.h>
#include <doca_gpunetio_dev_eth_rxq.cuh>   /* device-side receive API */
#include <doca_eth_rxq.h>
#include <doca_dev.h>
#include <doca_ctx.h>
#include <doca_flow.h>

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

/* ── Constants ───────────────────────────────────────────────────────────── */
#define MAX_PKT_PER_BURST  64
#define ETH_IP_UDP_HDR     42       /* 14 + 20 + 8 */
#define RESULT_QUEUE_DEPTH 4096     /* ring buffer depth for CPU readback */

#define CUDA_CHECK(call) \
    do { cudaError_t _e=(call); if(_e!=cudaSuccess){ \
        fprintf(stderr,"CUDA %s:%d: %s\n",__FILE__,__LINE__,cudaGetErrorString(_e)); exit(1); \
    }} while(0)

#define DOCA_CHECK(call) \
    do { doca_error_t _e=(call); if(_e!=DOCA_SUCCESS){ \
        fprintf(stderr,"DOCA %s:%d: %s\n",__FILE__,__LINE__,doca_error_get_descr(_e)); exit(1); \
    }} while(0)

/* ── Atomic EMA (device) ─────────────────────────────────────────────────── */
__device__ static void ema_update(double *slot, double price, double alpha)
{
    unsigned long long *addr = reinterpret_cast<unsigned long long *>(slot);
    unsigned long long expected, desired;
    do {
        expected = *addr;
        double old_v = __longlong_as_double((long long)expected);
        double new_v = alpha * price + (1.0 - alpha) * old_v;
        desired  = (unsigned long long)__double_as_longlong(new_v);
    } while (atomicCAS(addr, expected, desired) != expected);
}

/* ── Shared GPU result ring (GPU → CPU readback) ─────────────────────────── */
struct ResultSlot {
    BenchmarkResult bench;
    SignalResult    signal;
};

/*
 * GPU→CPU result ring.  The GPU kernel writes completed results here;
 * the CPU forwarding thread drains it and sends UDP packets.
 * head = next slot for GPU to write (written by GPU with atomicAdd).
 * tail = next slot for CPU to read (managed by CPU).
 */
struct ResultRing {
    ResultSlot  *slots   = nullptr;  /* device-accessible pinned memory */
    uint64_t    *head    = nullptr;  /* device-accessible pinned counter */
    uint64_t     tail    = 0;
    uint32_t     depth   = RESULT_QUEUE_DEPTH;
};

/* ── GPUNetIO receive + process kernel ────────────────────────────────────── */
/*
 * This is a persistent CUDA kernel.  It loops calling
 * doca_gpu_eth_rxq_recv_strong() to receive packets directly from
 * the NIC into GPU memory, then processes each tick inline.
 *
 * Thread structure: 1 block, MAX_PKT_PER_BURST threads.
 *   thread 0      — calls recv_strong (producer)
 *   threads 0..N-1 — each processes one received packet (consumer)
 *
 * The kernel runs until *quit_flag is set by the CPU.
 */
__global__ void gpu_recv_process_kernel(
    doca_gpu_eth_rxq_t  *rxq,
    volatile uint32_t   *quit_flag,
    double              *ema_table,          /* [MAX_INSTRUMENTS] */
    ResultSlot          *result_ring,
    volatile uint64_t   *ring_head,
    uint32_t             ring_depth,
    uint8_t              tier,
    double               alpha,
    double               threshold)
{
    /* Shared memory: packet metadata for the current burst */
    __shared__ uint32_t  s_n_rx;
    __shared__ uint64_t  s_buf_addrs[MAX_PKT_PER_BURST];
    __shared__ uint32_t  s_pkt_lens[MAX_PKT_PER_BURST];

    const int tid = threadIdx.x;

    while (!*quit_flag) {

        /* ── Thread 0: receive a burst of packets ── */
        if (tid == 0) {
            doca_gpu_buf_arr_t *buf_arr = nullptr;
            uint32_t n = 0;

            /*
             * doca_gpu_eth_rxq_recv_strong: blocking GPU-side receive.
             * Returns when at least one packet is available.
             * API note: exact signature depends on DOCA SDK version.
             *   doca_gpu_eth_rxq_recv_strong(rxq, timeout_ns, max_pkts,
             *                                &n_pkts, &buf_arr_ptr)
             */
            doca_error_t ret = doca_gpu_eth_rxq_recv_strong(
                rxq,
                0,                     /* timeout_ns: 0 = spin forever */
                MAX_PKT_PER_BURST,
                &n,
                &buf_arr);

            if (ret == DOCA_SUCCESS && n > 0 && buf_arr != nullptr) {
                s_n_rx = n;
                for (uint32_t p = 0; p < n; ++p) {
                    doca_gpu_buf_t *buf = doca_gpu_buf_arr_get_buf(buf_arr, p);
                    uintptr_t addr;
                    uint32_t  len;
                    doca_gpu_buf_get_addr(buf, &addr);
                    doca_gpu_buf_get_len(buf,  &len);
                    s_buf_addrs[p] = addr;
                    s_pkt_lens[p]  = len;
                }
            } else {
                s_n_rx = 0;
            }
        }
        __syncthreads();

        uint32_t n = s_n_rx;
        if (n == 0) continue;

        /* ── Each thread processes one packet ── */
        if (tid < (int)n) {
            const uint8_t *pkt = reinterpret_cast<const uint8_t *>(s_buf_addrs[tid]);
            uint32_t pkt_len   = s_pkt_lens[tid];

            if (pkt_len < ETH_IP_UDP_HDR + sizeof(TickMessage)) goto done;

            /* Skip Ethernet + IP + UDP headers */
            const TickMessage *tick =
                reinterpret_cast<const TickMessage *>(pkt + ETH_IP_UDP_HDR);

            /* Verify UDP destination port */
            const uint8_t *udp_hdr = pkt + 14 + 20;
            uint16_t dst_port = (uint16_t)((udp_hdr[2] << 8) | udp_hdr[3]);
            if (dst_port != TICK_MCAST_PORT) goto done;

            /* T2: tick is now in GPU memory (we're executing in GPU kernel) */
            uint64_t t2 = clock64();

            /* ── Compute mid and spread ── */
            double mid    = (tick->bid + tick->ask) * 0.5;
            double spread =  tick->ask - tick->bid;

            /* ── Update per-instrument EMA ── */
            int slot_idx = tick->instrument_id % MAX_INSTRUMENTS;
            ema_update(&ema_table[slot_idx], mid, alpha);
            double ema = ema_table[slot_idx];

            /* ── Mean-reversion signal ── */
            int8_t sig = 0;
            if (mid < ema - threshold * ema) sig = +1;
            if (mid > ema + threshold * ema) sig = -1;

            /* T3: kernel done */
            uint64_t t3 = clock64();

            /* ── Write to result ring ── */
            uint64_t ring_idx = atomicAdd(
                reinterpret_cast<unsigned long long *>(
                    const_cast<uint64_t *>(ring_head)), 1ULL);
            ResultSlot *rs = &result_ring[ring_idx % ring_depth];

            /* BenchmarkResult */
            rs->bench.tick_id = tick->tick_id;
            rs->bench.t1_ns   = tick->timestamp_ns;
            rs->bench.t2_ns   = t2;    /* GPU clock cycles (converted by CPU) */
            rs->bench.t3_ns   = t3;
            rs->bench.t4_ns   = 0;
            rs->bench.tier    = tier;
            rs->bench.dropped = 0;

            /* SignalResult */
            rs->signal.tick_id       = tick->tick_id;
            rs->signal.t3_ns         = t3;
            rs->signal.instrument_id = tick->instrument_id;
            rs->signal.signal        = sig;
            rs->signal.mid_price     = mid;
            rs->signal.spread        = spread;
            rs->signal.ema           = ema;

            /* T4: write complete */
            __threadfence();
            uint64_t t4 = clock64();
            rs->bench.t4_ns  = t4;
            rs->signal.t4_ns = t4;
        }
        done:
        __syncthreads();
    }
}

/* ── CPU forwarding thread ────────────────────────────────────────────────── */
struct ForwardCtx {
    ResultRing        *ring        = nullptr;
    double             ns_per_cyc  = 1.0;
    uint64_t           cyc_offset  = 0;   /* GPU cycle at startup, ns offset */
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

            br.t2_ns = cyc_to_ns(br.t2_ns,  ctx->ns_per_cyc);
            br.t3_ns = cyc_to_ns(br.t3_ns,  ctx->ns_per_cyc);
            br.t4_ns = cyc_to_ns(br.t4_ns,  ctx->ns_per_cyc);
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
        /* Brief yield to avoid spinning the full CPU core */
        std::this_thread::sleep_for(std::chrono::microseconds(10));
    }
}

/* ── DOCA host-side initialisation ─────────────────────────────────────── */
struct DocaContext {
    doca_dev_t         *dev        = nullptr;
    doca_gpu_t         *gpu        = nullptr;
    doca_eth_rxq_t     *rxq_cpu    = nullptr;   /* CPU handle */
    doca_gpu_eth_rxq_t *rxq_gpu    = nullptr;   /* GPU handle */
    doca_ctx_t         *ctx        = nullptr;
};

static int doca_init(DocaContext &doca, const char *iface, int cuda_device)
{
    /* Set the CUDA device for DOCA GPU context */
    CUDA_CHECK(cudaSetDevice(cuda_device));

    /* Open DOCA device by interface name */
    doca_devinfo_t **dev_list;
    uint32_t nb_devs;
    DOCA_CHECK(doca_devinfo_create_list(&dev_list, &nb_devs));

    for (uint32_t i = 0; i < nb_devs; ++i) {
        char dev_iface[64] = {};
        if (doca_devinfo_get_iface_name(dev_list[i], dev_iface, sizeof(dev_iface))
                == DOCA_SUCCESS &&
            strcmp(dev_iface, iface) == 0)
        {
            DOCA_CHECK(doca_dev_open(dev_list[i], &doca.dev));
            break;
        }
    }
    doca_devinfo_destroy_list(dev_list);

    if (!doca.dev) {
        fprintf(stderr, "DOCA device for interface '%s' not found\n", iface);
        return -1;
    }

    /* Create DOCA GPU context */
    DOCA_CHECK(doca_gpu_create(doca.dev, &doca.gpu));

    /* Create ETH RX queue */
    DOCA_CHECK(doca_eth_rxq_create(doca.dev, MAX_PKT_PER_BURST,
                                    1500 /* max frame */, &doca.rxq_cpu));

    /* Set multicast group */
    /* NOTE: multicast steering is typically handled by DOCA Flow.
     * For simplicity, enable promiscuous receive here and let the GPU
     * kernel filter by destination port. */
    DOCA_CHECK(doca_eth_rxq_set_type(doca.rxq_cpu,
                                      DOCA_ETH_RXQ_TYPE_CYCLIC));

    /* Convert to GPU handle */
    DOCA_CHECK(doca_eth_rxq_get_gpu_handle(doca.rxq_cpu, &doca.rxq_gpu));

    /* Start the queue */
    doca.ctx = doca_eth_rxq_as_doca_ctx(doca.rxq_cpu);
    DOCA_CHECK(doca_ctx_start(doca.ctx));

    fprintf(stderr, "[gpu_receiver] DOCA init OK — interface: %s\n", iface);
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
    const char *iface         = "enp1s0f0";
    int         cuda_device   = 0;
    uint8_t     tier          = 4;
    const char *harness_ip    = "127.0.0.1";
    const char *fillsim_ip    = "127.0.0.1";
    double      alpha         = 0.01;
    double      threshold     = 0.001;

    for (int i = 1; i < argc; ++i) {
        if      (!strcmp(argv[i],"--iface")     && i+1<argc) iface       = argv[++i];
        else if (!strcmp(argv[i],"--gpu")       && i+1<argc) cuda_device = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--tier")      && i+1<argc) tier        = (uint8_t)atoi(argv[++i]);
        else if (!strcmp(argv[i],"--harness")   && i+1<argc) harness_ip  = argv[++i];
        else if (!strcmp(argv[i],"--fillsim")   && i+1<argc) fillsim_ip  = argv[++i];
        else if (!strcmp(argv[i],"--alpha")     && i+1<argc) alpha       = atof(argv[++i]);
        else if (!strcmp(argv[i],"--threshold") && i+1<argc) threshold   = atof(argv[++i]);
    }

    fprintf(stderr, "[T%d gpu_receiver] iface=%s cuda=%d\n", tier, iface, cuda_device);

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    CUDA_CHECK(cudaSetDevice(cuda_device));

    /* Get GPU clock rate for ns conversion */
    cudaDeviceProp prop;
    CUDA_CHECK(cudaGetDeviceProperties(&prop, cuda_device));
    double ns_per_cyc = 1e6 / (double)prop.clockRate;  /* clockRate in kHz */

    /* DOCA init */
    DocaContext doca{};
    if (doca_init(doca, iface, cuda_device) < 0) return 1;

    /* EMA table in device memory */
    double *d_ema = nullptr;
    CUDA_CHECK(cudaMalloc(&d_ema, MAX_INSTRUMENTS * sizeof(double)));
    CUDA_CHECK(cudaMemset(d_ema, 0, MAX_INSTRUMENTS * sizeof(double)));

    /* Result ring: host-mapped device memory for GPU→CPU transfer */
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

    /* Launch persistent GPU receive kernel
     * 1 block, MAX_PKT_PER_BURST threads.
     * The kernel loops internally until *d_quit is set. */
    fprintf(stderr, "[gpu_receiver] launching persistent GPU kernel...\n");
    gpu_recv_process_kernel<<<1, MAX_PKT_PER_BURST>>>(
        doca.rxq_gpu,
        d_quit,
        d_ema,
        ring.slots,
        ring.head,
        ring.depth,
        tier,
        alpha,
        threshold);

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
    DOCA_CHECK(doca_ctx_stop(doca.ctx));
    DOCA_CHECK(doca_eth_rxq_destroy(doca.rxq_cpu));
    DOCA_CHECK(doca_gpu_destroy(doca.gpu));
    DOCA_CHECK(doca_dev_close(doca.dev));

    cudaFree(d_ema);
    cudaFree(d_quit);
    cudaFreeHost(ring.slots);
    cudaFreeHost(ring.head);
    close(harness_fd);
    close(signal_fd);

    fprintf(stderr, "[gpu_receiver] done\n");
    return 0;
}
