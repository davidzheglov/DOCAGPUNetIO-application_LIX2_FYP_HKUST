/*
 * cpu_receiver.cu — T1: CPU naive receiver.
 *
 * Data path:
 *   NIC → kernel UDP socket → recvfrom() (CPU) → host buffer
 *       → cudaMemcpy H→D → process_ticks_kernel → results back to host
 *       → BenchmarkResult UDP → harness on port 5010
 *       → SignalResult UDP   → fill_simulator on port 5006
 *
 * Batches up to BATCH_SIZE ticks before launching the kernel.
 * T2 is stamped on the host immediately after cudaMemcpy H→D completes.
 *
 * Usage:
 *   cpu_receiver [--mcast 239.0.0.1] [--port 5005] [--batch 256]
 *                [--tier 1] [--harness <ip>] [--fillsim <ip>]
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <cuda_runtime.h>

#include "tick_message.h"
#include "benchmark_result.h"
#include "signal_result.h"
#include "process_kernel.cuh"

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
static int make_mcast_recv_socket(const char *mcast_addr, int port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        perror("bind"); close(fd); return -1;
    }

    ip_mreq mreq{};
    mreq.imr_multiaddr.s_addr = inet_addr(mcast_addr);
    mreq.imr_interface.s_addr = INADDR_ANY;
    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("IP_ADD_MEMBERSHIP"); close(fd); return -1;
    }
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
    /* H → D */
    CUDA_CHECK(cudaMemcpyAsync(r.d_ticks, r.h_ticks,
                                n * sizeof(TickMessage),
                                cudaMemcpyHostToDevice, r.stream));
    CUDA_CHECK(cudaStreamSynchronize(r.stream));

    /* T2: ticks are now in GPU memory */
    uint64_t t2 = now_ns();

    /* Launch dual-EMA + RSI processing kernel */
    launch_process_ticks(r.d_ticks, n, r.d_signals,
                          r.d_fast_ema, r.d_slow_ema,
                          r.d_avg_gain, r.d_avg_loss, r.d_last_mid,
                          t2, r.stream);
    CUDA_CHECK(cudaStreamSynchronize(r.stream));

    /* T3: kernel complete — host wall-clock after kernel sync */
    uint64_t t3 = now_ns();

    /* D → H results */
    CUDA_CHECK(cudaMemcpyAsync(r.h_signals, r.d_signals,
                                n * sizeof(SignalResult),
                                cudaMemcpyDeviceToHost, r.stream));
    CUDA_CHECK(cudaStreamSynchronize(r.stream));

    /* T4: results readable on host */
    uint64_t t4 = now_ns();

    /* Send BenchmarkResult + SignalResult for each tick */
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

    for (int i = 1; i < argc; ++i) {
        if      (!strcmp(argv[i], "--mcast")   && i+1<argc) mcast_addr   = argv[++i];
        else if (!strcmp(argv[i], "--port")    && i+1<argc) mcast_port   = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--batch")   && i+1<argc) batch_size   = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--tier")    && i+1<argc) tier         = (uint8_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--harness") && i+1<argc) harness_addr = argv[++i];
        else if (!strcmp(argv[i], "--fillsim") && i+1<argc) fillsim_addr = argv[++i];
    }

    fprintf(stderr, "[T1 cpu_receiver] mcast=%s:%d batch=%d tier=%d\n",
            mcast_addr, mcast_port, batch_size, tier);

    /* Receive socket */
    int recv_fd = make_mcast_recv_socket(mcast_addr, mcast_port);
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

    fprintf(stderr, "[T1] waiting for ticks on %s:%d...\n", mcast_addr, mcast_port);

    while (true) {
        ssize_t n = recvfrom(recv_fd,
                              &gpu.h_ticks[batch_n], sizeof(TickMessage),
                              0, nullptr, nullptr);
        if (n != sizeof(TickMessage)) continue;

        ++batch_n;
        ++total_recv;

        if (total_recv == 1)
            fprintf(stderr, "[T1] first tick received (tick_id=%u)\n",
                    gpu.h_ticks[0].tick_id);

        if (batch_n >= batch_size) {
            process_batch(gpu, batch_n,
                          harness_fd, harness_dest,
                          signal_fd,  signal_dest,
                          tier);
            ++total_batches;
            auto now = std::chrono::steady_clock::now();
            double elapsed = std::chrono::duration<double>(now - start_time).count();
            fprintf(stderr, "[T1] batch %llu: processed %d ticks (total recv=%llu, %.0f ticks/s)\n",
                    (unsigned long long)total_batches, batch_n,
                    (unsigned long long)total_recv,
                    total_recv / elapsed);
            batch_n = 0;
        }
    }

    gpu_free(gpu);
    close(recv_fd);
    close(harness_fd);
    close(signal_fd);
    return 0;
}
