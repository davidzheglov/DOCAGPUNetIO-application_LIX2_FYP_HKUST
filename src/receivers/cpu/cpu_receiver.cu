/*
 * cpu_receiver.cu — T1: CPU naive receiver.
 *
 * Data path (Option A — DPU sender, real NIC):
 *   DPU ARM → ConnectX PF1 (ens21f1np1) → kernel UDP socket
 *       → recvfrom() (CPU) → host pinned buffer
 *       → cudaMemcpy H→D → process_ticks_kernel → cudaMemcpy D→H
 *       → BenchmarkResult UDP → harness on port 5010
 *       → SignalResult UDP   → fill_simulator on port 5006
 *
 * The --iface flag binds the multicast join to a specific interface
 * (e.g. ens21f1np1) so that frames arriving from the DPU are accepted.
 * Without it, INADDR_ANY may pick lo and drop real-NIC traffic.
 *
 * Batches up to BATCH_SIZE ticks before launching the kernel.
 * T2 is stamped on the host immediately after cudaMemcpy H→D completes.
 *
 * Usage:
 *   cpu_receiver [--mcast 239.0.0.1] [--port 5005] [--batch 256]
 *                [--tier 1] [--iface ens21f1np1]
 *                [--harness <ip>] [--fillsim <ip>]
 */

#include <arpa/inet.h>
#include <net/if.h>          /* if_nametoindex() */
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <cuda_runtime.h>
#include <cuda_profiler_api.h>
#include <nvtx3/nvToolsExt.h>

#include "tick_message.h"
#include "benchmark_result.h"
#include "signal_result.h"
#include "process_kernel.cuh"

/* Clean shutdown on SIGINT/SIGTERM so cudaProfilerStop() can flush the
 * nsys capture before the process dies. */
static volatile sig_atomic_t g_quit = 0;
static void sig_handler(int) { g_quit = 1; }

/* ── Configuration defaults ─────────────────────────────────────────────────── */
#define DEFAULT_BATCH       256
#define DEFAULT_TIER        1

/* ── CUDA error check ───────────────────────────────────────────────────────── */
#define CUDA_CHECK(call)                                                    \
    do {                                                                    \
        cudaError_t _e = (call);                                           \
        if (_e != cudaSuccess) {                                            \
            fprintf(stderr, "CUDA error %s:%d: %s\n",                     \
                    __FILE__, __LINE__, cudaGetErrorString(_e));            \
            exit(1);                                                        \
        }                                                                   \
    } while (0)

/* ── Multicast receive socket ───────────────────────────────────────────────── */
/*
 * iface_name — Linux interface name to join the mcast group on, e.g.
 *              "ens21f1np1" for the ConnectX PF1 that faces the DPU.
 *              Pass NULL to use INADDR_ANY (kernel picks; loopback-only works
 *              but DPU-sent frames will be silently dropped).
 */
static int make_mcast_recv_socket(const char *mcast_addr, int port,
                                  const char *iface_name)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    /* Enlarge receive buffer to avoid drops during GPU batch processing */
    int rcvbuf = 16 * 1024 * 1024;  /* 16 MB — holds ~330k TickMessages */
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        perror("bind"); close(fd); return -1;
    }

    /* ip_mreqn lets us specify the interface by index, not by IP address.
     * This is the only reliable way when the interface has no unicast IP
     * in the same subnet, or when INADDR_ANY would pick lo instead of the
     * physical NIC that actually receives the DPU-sourced multicast frames. */
    ip_mreqn mreq{};
    mreq.imr_multiaddr.s_addr = inet_addr(mcast_addr);
    mreq.imr_address.s_addr   = INADDR_ANY;
    if (iface_name && iface_name[0] != '\0') {
        mreq.imr_ifindex = (int)if_nametoindex(iface_name);
        if (mreq.imr_ifindex == 0) {
            fprintf(stderr, "[cpu_receiver] ERROR: interface '%s' not found "
                    "(check --iface flag or `ip link`)\n", iface_name);
            close(fd); return -1;
        }
        fprintf(stderr, "[cpu_receiver] joining mcast %s on %s (ifindex=%d)\n",
                mcast_addr, iface_name, mreq.imr_ifindex);
    } else {
        mreq.imr_ifindex = 0;  /* let kernel pick — works for loopback tests */
        fprintf(stderr, "[cpu_receiver] joining mcast %s on INADDR_ANY "
                "(loopback only — use --iface for real-NIC traffic)\n", mcast_addr);
    }
    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("IP_ADD_MEMBERSHIP"); close(fd); return -1;
    }

    /* Timeout so partial batches get flushed when sender stops */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };  /* 100ms */
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    return fd;
}

/* ── UDP send to harness / fill-sim ─────────────────────────────────────────── */
static int make_udp_send_socket(const char *dst_addr, int port,
                                 sockaddr_in &dest)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return -1; }
    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_port        = htons((uint16_t)port);
    dest.sin_addr.s_addr = inet_addr(dst_addr);
    return fd;
}


/* ── GPU resource bundle ─────────────────────────────────────────────────────── */
struct GpuResources {
    TickMessage  *d_ticks     = nullptr;
    SignalResult *d_signals   = nullptr;
    TickMessage  *h_ticks     = nullptr;   /* pinned host buffer */
    SignalResult *h_signals   = nullptr;   /* pinned host buffer */
    /* Per-instrument EMA/RSI state — zero-initialised, persist across batches */
    double       *d_fast_ema  = nullptr;   /* fast EMA (alpha = EMA_ALPHA_FAST) */
    double       *d_slow_ema  = nullptr;   /* slow EMA (alpha = EMA_ALPHA_SLOW) */
    double       *d_avg_gain  = nullptr;   /* RSI running avg gain              */
    double       *d_avg_loss  = nullptr;   /* RSI running avg loss              */
    double       *d_last_mid  = nullptr;   /* previous tick mid-price           */
    cudaStream_t  stream      = nullptr;
    int           batch_size  = DEFAULT_BATCH;
};

static void gpu_init(GpuResources &r, int batch_size)
{
    r.batch_size = batch_size;

    /* Pinned host buffers for fast async memcpy */
    CUDA_CHECK(cudaMallocHost(&r.h_ticks,   batch_size * sizeof(TickMessage)));
    CUDA_CHECK(cudaMallocHost(&r.h_signals, batch_size * sizeof(SignalResult)));

    /* Device tick/signal buffers */
    CUDA_CHECK(cudaMalloc(&r.d_ticks,   batch_size * sizeof(TickMessage)));
    CUDA_CHECK(cudaMalloc(&r.d_signals, batch_size * sizeof(SignalResult)));

    /* Per-instrument state — zero-initialised (kernel seeds on first tick) */
    size_t state_sz = MAX_INSTRUMENTS * sizeof(double);
    CUDA_CHECK(cudaMalloc(&r.d_fast_ema, state_sz)); CUDA_CHECK(cudaMemset(r.d_fast_ema, 0, state_sz));
    CUDA_CHECK(cudaMalloc(&r.d_slow_ema, state_sz)); CUDA_CHECK(cudaMemset(r.d_slow_ema, 0, state_sz));
    CUDA_CHECK(cudaMalloc(&r.d_avg_gain, state_sz)); CUDA_CHECK(cudaMemset(r.d_avg_gain, 0, state_sz));
    CUDA_CHECK(cudaMalloc(&r.d_avg_loss, state_sz)); CUDA_CHECK(cudaMemset(r.d_avg_loss, 0, state_sz));
    CUDA_CHECK(cudaMalloc(&r.d_last_mid, state_sz)); CUDA_CHECK(cudaMemset(r.d_last_mid, 0, state_sz));

    CUDA_CHECK(cudaStreamCreate(&r.stream));

    (void)r;  /* clock query not needed — t3/t4 use host wall-clock */
}

static void gpu_free(GpuResources &r)
{
    cudaFreeHost(r.h_ticks);
    cudaFreeHost(r.h_signals);
    cudaFree(r.d_ticks);
    cudaFree(r.d_signals);
    cudaFree(r.d_fast_ema);
    cudaFree(r.d_slow_ema);
    cudaFree(r.d_avg_gain);
    cudaFree(r.d_avg_loss);
    cudaFree(r.d_last_mid);
    cudaStreamDestroy(r.stream);
}

/* ── Process a complete batch ────────────────────────────────────────────────── */
static void process_batch(GpuResources &r, int n,
                           int harness_fd, sockaddr_in harness_dest,
                           int signal_fd,  sockaddr_in signal_dest,
                           uint8_t tier)
{
    /* Single outer range so the whole batch shows up as one bar in nsys;
     * the inner sub-ranges give the H2D / kernel / D2H / send breakdown. */
    nvtxRangePushA("batch");

    /* H → D */
    nvtxRangePushA("batch_h2d");
    CUDA_CHECK(cudaMemcpyAsync(r.d_ticks, r.h_ticks,
                                n * sizeof(TickMessage),
                                cudaMemcpyHostToDevice, r.stream));
    CUDA_CHECK(cudaStreamSynchronize(r.stream));
    nvtxRangePop();

    /* T2: ticks are now in GPU memory */
    uint64_t t2 = now_ns();

    /* Launch dual-EMA + RSI processing kernel */
    nvtxRangePushA("batch_kernel");
    launch_process_ticks(r.d_ticks, n, r.d_signals,
                          r.d_fast_ema, r.d_slow_ema,
                          r.d_avg_gain, r.d_avg_loss, r.d_last_mid,
                          t2, r.stream);
    CUDA_CHECK(cudaStreamSynchronize(r.stream));
    nvtxRangePop();

    /* T3: kernel complete — host wall-clock after kernel sync */
    uint64_t t3 = now_ns();

    /* D → H results */
    nvtxRangePushA("batch_d2h");
    CUDA_CHECK(cudaMemcpyAsync(r.h_signals, r.d_signals,
                                n * sizeof(SignalResult),
                                cudaMemcpyDeviceToHost, r.stream));
    CUDA_CHECK(cudaStreamSynchronize(r.stream));
    nvtxRangePop();

    /* T4: results readable on host */
    uint64_t t4 = now_ns();

    /* Send BenchmarkResult + SignalResult for each tick */
    nvtxRangePushA("batch_send");
    for (int i = 0; i < n; ++i) {
        const TickMessage  &tick = r.h_ticks[i];
        const SignalResult &sig  = r.h_signals[i];

        BenchmarkResult br{};
        br.tick_id = tick.tick_id;
        br.t1_ns   = tick.timestamp_ns;
        br.t2_ns   = t2;
        br.t3_ns   = t3;   /* host time after kernel sync — same for all ticks in batch */
        br.t4_ns   = t4;   /* host time after D→H copy   — same for all ticks in batch */
        br.tier    = tier;
        br.dropped = 0;

        sendto(harness_fd, &br, sizeof(br), 0,
               reinterpret_cast<const sockaddr *>(&harness_dest),
               sizeof(harness_dest));

        /* Forward SignalResult to fill simulator */
        SignalResult out = sig;
        out.t3_ns = t3;
        out.t4_ns = t4;
        sendto(signal_fd, &out, sizeof(out), 0,
               reinterpret_cast<const sockaddr *>(&signal_dest),
               sizeof(signal_dest));
    }
    nvtxRangePop();  /* batch_send */

    nvtxRangePop();  /* batch */
}

/* ── Main ────────────────────────────────────────────────────────────────────── */
int main(int argc, char **argv)
{
    const char *mcast_addr    = TICK_MCAST_ADDR;
    int         mcast_port    = TICK_MCAST_PORT;
    int         batch_size    = DEFAULT_BATCH;
    uint8_t     tier          = DEFAULT_TIER;
    const char *harness_addr  = "127.0.0.1";
    const char *fillsim_addr  = "127.0.0.1";
    const char *iface_name    = nullptr;   /* NULL = INADDR_ANY (loopback ok) */

    for (int i = 1; i < argc; ++i) {
        if      (!strcmp(argv[i], "--mcast")   && i+1<argc) mcast_addr   = argv[++i];
        else if (!strcmp(argv[i], "--port")    && i+1<argc) mcast_port   = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--batch")   && i+1<argc) batch_size   = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--tier")    && i+1<argc) tier         = (uint8_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--harness") && i+1<argc) harness_addr = argv[++i];
        else if (!strcmp(argv[i], "--fillsim") && i+1<argc) fillsim_addr = argv[++i];
        else if (!strcmp(argv[i], "--iface")   && i+1<argc) iface_name   = argv[++i];
    }

    fprintf(stderr, "[T1 cpu_receiver] mcast=%s:%d batch=%d tier=%d iface=%s\n",
            mcast_addr, mcast_port, batch_size, tier,
            iface_name ? iface_name : "INADDR_ANY");

    /* Clean shutdown: SIGINT/SIGTERM set g_quit so cudaProfilerStop() gets
     * called and the nsys capture-range is closed cleanly. Without this, Ctrl-C
     * kills the process mid-kernel and nsys reports "no profile data". */
    struct sigaction sa{};
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;    /* NOT SA_RESTART — we want recvfrom() to return EINTR */
    sigaction(SIGINT,  &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    /* Receive socket — bind multicast join to the specified interface */
    int recv_fd = make_mcast_recv_socket(mcast_addr, mcast_port, iface_name);
    if (recv_fd < 0) return 1;

    /* Output sockets */
    sockaddr_in harness_dest{}, signal_dest{};
    int harness_fd = make_udp_send_socket(harness_addr, BENCH_RESULT_PORT, harness_dest);
    int signal_fd  = make_udp_send_socket(fillsim_addr, SIGNAL_PORT, signal_dest);
    if (harness_fd < 0 || signal_fd < 0) return 1;

    /* GPU init */
    GpuResources gpu{};
    gpu_init(gpu, batch_size);

    /* Receive loop */
    int batch_n = 0;
    uint64_t total_recv = 0;
    uint64_t total_batches = 0;
    auto start_time = std::chrono::steady_clock::now();

    /* Banner detected by scripts/benchmark.py::start_receiver() */
    fprintf(stderr, "[T1 cpu_receiver] ready — waiting for ticks on %s:%d...\n",
            mcast_addr, mcast_port);
    fflush(stderr);

    /* Start nsys capture here (requires --capture-range=cudaProfilerApi).
     * The outer "steady_state" NVTX range lets post-processing filter out
     * startup batches from throughput/latency numbers. */
    cudaProfilerStart();
    nvtxRangePushA("steady_state");

    while (!g_quit) {
        ssize_t n = recvfrom(recv_fd,
                              &gpu.h_ticks[batch_n], sizeof(TickMessage),
                              0, nullptr, nullptr);

        if (n == sizeof(TickMessage)) {
            ++batch_n;
            ++total_recv;

            if (total_recv == 1)
                fprintf(stderr, "[T1] first tick received (tick_id=%u)\n",
                        gpu.h_ticks[0].tick_id);
        }

        /* Flush when batch is full OR timeout with partial batch */
        bool batch_full = (batch_n >= batch_size);
        bool timeout_flush = (n != sizeof(TickMessage) && batch_n > 0);

        if (batch_full || timeout_flush) {
            process_batch(gpu, batch_n,
                          harness_fd, harness_dest,
                          signal_fd,  signal_dest,
                          tier);
            ++total_batches;
            auto now = std::chrono::steady_clock::now();
            double elapsed = std::chrono::duration<double>(now - start_time).count();
            fprintf(stderr, "[T1] batch %llu: processed %d ticks%s (total recv=%llu, %.0f ticks/s)\n",
                    (unsigned long long)total_batches, batch_n,
                    timeout_flush ? " (partial flush)" : "",
                    (unsigned long long)total_recv,
                    total_recv / elapsed);
            batch_n = 0;
        }
    }

    /* Close nsys capture-range before releasing GPU resources so the
     * final kernel / memcpy traces are flushed to the qdrep. */
    nvtxRangePop();          /* steady_state */
    cudaProfilerStop();

    fprintf(stderr, "[T1 cpu_receiver] shutting down: total_recv=%llu batches=%llu\n",
            (unsigned long long)total_recv,
            (unsigned long long)total_batches);

    gpu_free(gpu);
    close(recv_fd);
    close(harness_fd);
    close(signal_fd);
    return 0;
}
