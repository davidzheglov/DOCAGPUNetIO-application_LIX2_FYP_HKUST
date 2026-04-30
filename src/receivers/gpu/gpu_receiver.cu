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
 * Benchmark definition for T4/T5:
 *   By default, t1 preserves TickMessage.timestamp_ns from the sender so the
 *   harness can reconcile cross-host clock differences centrally for every
 *   tier. An experimental --nic-t1 mode instead uses the GPUNetIO RX CQE
 *   timestamp via doca_gpu_dev_eth_rxq_get_pkt_ts().
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
#include <doca_mmap.h>
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
#include <fstream>
#include <thread>
#include <chrono>

#include <cuda_runtime.h>
#include <cuda_profiler_api.h>
#include <nvtx3/nvToolsExt.h>

#include "tick_message.h"
#include "benchmark_result.h"
#include "signal_result.h"

/* ── Constants ───────────────────────────────────────��───────────────────── */
/*
 * MAX_PKT_PER_BURST = 32 is deliberate: the receive kernel uses the
 * WARP-scope template variant `doca_gpu_dev_eth_rxq_recv<WARP,...>`,
 * which needs exactly one warp (32 threads) and processes up to one
 * packet per thread per poll. See the kernel comment below for why we
 * moved off the `_thread` variant — in short: `_thread` does not
 * auto-advance the DOCA consumer cursor, causing every packet to be
 * re-delivered ~3-4x until it wraps out of the 2048-slot DOCA RX ring.
 */
#define MAX_PKT_PER_BURST  32
#define MAX_PKT_NUM        2048
#define MAX_PKT_SIZE       2048
#define ETH_IP_UDP_HDR     42       /* 14 + 20 + 8 */
#define RESULT_QUEUE_DEPTH 65536
#define SEND_BATCH         1024
#define MAX_RX_TIMEOUT_NS  10000000ULL  /* 10ms timeout */

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

/* ── Per-tick Monte Carlo VaR forecast ────────────────────────────────────
 * Identical to process_kernel.cuh::compute_risk_mc — duplicated here because
 * gpu_receiver.cu has its own inline ema_cas/rsi_cas that would collide with
 * a #include of process_kernel.cuh. Keep this in sync if you change the math
 * (or refactor both into a shared gpu_helpers.cuh). */
__device__ static void compute_risk_mc(
    double mid, double recent_vol_deviation, uint32_t seed,
    double &var_95, double &cvar_95,
    double &mc_mean, double &mc_std)
{
    /* FP32 inner sim — see commentary in process_kernel.cuh. Inputs/outputs
     * stay double for ABI compatibility with SignalResult. */
    const float sigma   = (float)(MC_BASE_VOL * (1.0 + recent_vol_deviation));
    const float dt      = (float)MC_DT;
    const float sqrt_dt = sqrtf(dt);
    const float drift   = -0.5f * sigma * sigma * dt;
    const float diff    =  sigma * sqrt_dt;
    const float TWO_PI  = 6.28318530f;
    const float mid_f   = (float)mid;

    float sum   = 0.0f;
    float sumsq = 0.0f;

    uint32_t rng = seed | 1u;

    for (int p = 0; p < MC_N_PATHS; ++p) {
        float S = mid_f;
        for (int s = 0; s < MC_N_STEPS; ++s) {
            rng = rng * 1664525u + 1013904223u;
            float u1 = ((float)rng + 1.0f) * (1.0f / 4294967297.0f);
            rng = rng * 1664525u + 1013904223u;
            float u2 =  (float)rng         * (1.0f / 4294967296.0f);
            float z  = sqrtf(-2.0f * logf(u1)) * cosf(TWO_PI * u2);
            S = S * expf(drift + diff * z);
        }
        sum   += S;
        sumsq += S * S;
    }

    const float n      = (float)MC_N_PATHS;
    const float mean_f = sum / n;
    const float var_f  = sumsq / n - mean_f * mean_f;
    const float std_f  = sqrtf(fmaxf(var_f, 0.0f));

    mc_mean = (double)mean_f;
    mc_std  = (double)std_f;
    var_95  = mc_mean - 1.6448536270 * mc_std;
    cvar_95 = mc_mean - 2.0627128443 * mc_std;
}

/* ── GPU result ring (GPU -> CPU readback) ────────────────────────────────── */
struct ResultSlot {
    volatile uint64_t seq;
    BenchmarkResult bench;
    SignalResult    signal;
};

struct ResultRing {
    ResultSlot  *slots   = nullptr;
    uint64_t    *head    = nullptr;
    uint64_t     tail    = 0;
    uint32_t     depth   = RESULT_QUEUE_DEPTH;
};

struct GpuKernelStats {
    uint64_t polls;
    uint64_t bursts;
    uint64_t rx_pkts;
    uint64_t addr_zero;
    uint64_t port_miss;
    uint64_t ring_writes;
};

/* ── GPUNetIO persistent receive + process kernel (DOCA 3.x API) ─────────── */
/*
 * Uses doca_gpu_dev_eth_rxq_recv<WARP_SCOPE> — the warp-scope template
 * variant. All 32 threads in the warp participate in the recv call, which
 * means DOCA's internal consumer cursor is advanced automatically on each
 * call via the implicit warp-sync at the end of the template.
 *
 * Template parameters:
 *   DOCA_GPUNETIO_ETH_EXEC_SCOPE_WARP  — all 32 warp threads participate
 *   DOCA_GPUNETIO_ETH_MCST_AUTO        — automatic multicast handling
 *   DOCA_GPUNETIO_ETH_NIC_HANDLER_AUTO — automatic NIC handler
 *
 * Why not the `_thread` variant (which we used previously):
 *   `doca_gpu_dev_eth_rxq_recv_thread()` does NOT auto-advance the
 *   consumer cursor (documented in docs/DOCA_GPUNETIO_BRINGUP.md:971).
 *   That caused every packet to be re-delivered ~3-4 times until it
 *   wrapped out of the 2048-slot DOCA RX ring — visible as ~73% duplicate
 *   rows at 10 kHz. The template variants (BLOCK / WARP) handle the
 *   commit internally and produce each packet exactly once.
 *
 * Why WARP rather than BLOCK:
 *   An earlier BLOCK-scope attempt crashed after ~4000 polls with
 *   "unspecified launch failure" (root cause never diagnosed). WARP-scope
 *   is the variant receive_icmp.cu in the DOCA reference samples uses
 *   reliably. 32 threads × ~kHz poll rate >> target ingest rate, so one
 *   warp is sufficient headroom through 1 MHz.
 *
 * KNOWN LATENT RACE (not fixed in this patch — separate from the
 * DOCA duplication bug above):
 *   atomicAdd(ring_head, 1) publishes the slot index BEFORE we write
 *   the slot fields, so the CPU forwarder can in principle observe
 *   ring_head advance and read a half-written (or stale-from-previous-
 *   wrap) slot. In practice the CPU forwarder sleeps 10 μs between
 *   poll iterations which gives the threadfence_system + slot writes
 *   time to drain to host-mapped memory, so we rarely hit this. A
 *   proper fix is a 2-phase commit (reserve locally via block atomic,
 *   write slots, then thread 0 publishes ring_head by count). Tracked
 *   as a follow-up — it does NOT explain the 10 kHz ~3.86x duplication,
 *   only occasional garbled rows, and we have not seen evidence of the
 *   latter in the current benchmark CSVs.
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
    GpuKernelStats          *stats,
    uint8_t                  tier,
    int                      use_nic_t1,
    int                      light_mode)
{
    const int tid = threadIdx.x;

    /* ── Diagnostic counters (thread 0 only) ── */
    __shared__ uint64_t s_poll_count;
    __shared__ uint64_t s_recv_count;
    __shared__ uint64_t s_pkt_total;
    __shared__ uint64_t s_addr_zero;
    __shared__ uint64_t s_port_miss;
    __shared__ uint64_t s_ring_writes;
    if (tid == 0) {
        s_poll_count  = 0;
        s_recv_count  = 0;
        s_pkt_total   = 0;
        s_addr_zero   = 0;
        s_port_miss   = 0;
        s_ring_writes = 0;
    }
    __syncthreads();

    /* Shared recv output — thread 0 writes, all threads read after barrier */
    __shared__ uint64_t s_first_pkt_idx;
    __shared__ uint32_t s_n_pkts;
    __shared__ doca_error_t s_ret;
    __shared__ uint64_t s_ring_base;

    while (!*quit_flag) {
        /* ── All 32 warp threads participate in the recv (WARP-scope) ──
         * The template variant auto-advances DOCA's internal consumer
         * cursor via its trailing __syncwarp(), so every packet is
         * delivered exactly once. `_thread` did NOT do this and caused
         * ~3-4x duplication at low rates — see kernel header comment. */
        doca_error_t warp_ret = doca_gpu_dev_eth_rxq_recv<
                                    DOCA_GPUNETIO_ETH_EXEC_SCOPE_WARP,
                                    DOCA_GPUNETIO_ETH_MCST_AUTO,
                                    DOCA_GPUNETIO_ETH_NIC_HANDLER_AUTO>(
                                rxq,
                                MAX_PKT_PER_BURST,
                                MAX_RX_TIMEOUT_NS,
                                &s_first_pkt_idx,
                                &s_n_pkts,
                                NULL);
        if (tid == 0) {
            s_ret = warp_ret;

            s_poll_count++;
            if (s_ret != DOCA_SUCCESS && s_ret != (doca_error_t)14 /* DOCA_ERROR_EMPTY */) {
                if (s_poll_count <= 5 || s_poll_count % 100000 == 0)
                    printf("[GPU] poll #%llu: recv returned error %d (n_pkts=%u)\n",
                           (unsigned long long)s_poll_count, (int)s_ret, s_n_pkts);
            }
            if (s_n_pkts > 0) {
                s_recv_count++;
                s_pkt_total += s_n_pkts;
                if (s_recv_count <= 10 || s_recv_count % 10000 == 0)
                    printf("[GPU] poll #%llu: GOT %u pkts (total bursts=%llu, total pkts=%llu)\n",
                           (unsigned long long)s_poll_count, s_n_pkts,
                           (unsigned long long)s_recv_count,
                           (unsigned long long)s_pkt_total);
            }
            /* Print periodic heartbeat every 50000 polls */
            if (s_poll_count % 50000 == 0)
                printf("[GPU] heartbeat: %llu polls, %llu bursts, %llu pkts, "
                       "%llu addr_zero, %llu port_miss, %llu ring_writes\n",
                       (unsigned long long)s_poll_count,
                       (unsigned long long)s_recv_count,
                       (unsigned long long)s_pkt_total,
                       (unsigned long long)s_addr_zero,
                       (unsigned long long)s_port_miss,
                       (unsigned long long)s_ring_writes);
        }
        __syncthreads();  /* All threads now see s_n_pkts, s_first_pkt_idx, s_ret */

        /* ── Each thread processes one packet ── */
        uintptr_t buf_addr = 0;
        const uint8_t *pkt = nullptr;
        uint16_t dst_port = 0;
        bool active_pkt = false;
        if (s_ret == DOCA_SUCCESS && s_n_pkts > 0 && tid < (int)s_n_pkts) {
            buf_addr = doca_gpu_dev_eth_rxq_get_pkt_addr(
                rxq, s_first_pkt_idx + tid);
            pkt = reinterpret_cast<const uint8_t *>(buf_addr);

            /* Verify minimum length */
            if (buf_addr == 0) {
                atomicAdd((unsigned long long *)&s_addr_zero, 1ULL);
                if (tid == 0) printf("[GPU] pkt %d: buf_addr is NULL!\n", tid);
            }
            if (buf_addr != 0) {
                /* Skip Ethernet + IP + UDP headers */
                const uint8_t *udp_hdr = pkt + 14 + 20;
                dst_port = (uint16_t)((udp_hdr[2] << 8) | udp_hdr[3]);

                /* Diagnostic: print first few packet headers */
                if (s_recv_count <= 5 && tid == 0) {
                    printf("[GPU] pkt header dump (first 48 bytes):\n");
                    printf("[GPU]   ETH dst=%02x:%02x:%02x:%02x:%02x:%02x "
                           "src=%02x:%02x:%02x:%02x:%02x:%02x type=%02x%02x\n",
                           pkt[0],pkt[1],pkt[2],pkt[3],pkt[4],pkt[5],
                           pkt[6],pkt[7],pkt[8],pkt[9],pkt[10],pkt[11],
                           pkt[12],pkt[13]);
                    printf("[GPU]   IP: proto=%u src=%u.%u.%u.%u dst=%u.%u.%u.%u\n",
                           pkt[23], pkt[26],pkt[27],pkt[28],pkt[29],
                           pkt[30],pkt[31],pkt[32],pkt[33]);
                    printf("[GPU]   UDP: src_port=%u dst_port=%u (expected %u)\n",
                           (unsigned)((udp_hdr[0]<<8)|udp_hdr[1]),
                           (unsigned)dst_port, (unsigned)TICK_MCAST_PORT);
                }

                if (dst_port != TICK_MCAST_PORT) {
                    atomicAdd((unsigned long long *)&s_port_miss, 1ULL);
                }
                active_pkt = (dst_port == TICK_MCAST_PORT);
            }
        }

        unsigned active_mask = __ballot_sync(0xffffffffu, active_pkt);
        int active_count = __popc(active_mask);
        if (tid == 0) {
            s_ring_base = (active_count > 0)
                ? atomicAdd(reinterpret_cast<unsigned long long *>(
                                const_cast<uint64_t *>(ring_head)),
                            (unsigned long long)active_count)
                : 0ULL;
        }
        __syncwarp();

        if (active_pkt) {
                    int rank = __popc(active_mask & ((1u << tid) - 1u));
                    const TickMessage *tick =
                        reinterpret_cast<const TickMessage *>(pkt + ETH_IP_UDP_HDR);
                    uint64_t t1 = use_nic_t1
                        ? doca_gpu_dev_eth_rxq_get_pkt_ts(
                              rxq, s_first_pkt_idx + tid)
                        : tick->timestamp_ns;

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

                    double var_95 = mid, cvar_95 = mid, mc_mean = mid, mc_std = 0.0;
                    if (!light_mode) {
                        double rel_spread = (mid > 0.0) ? (spread / mid) : 0.0;
                        double vol_dev    = fmin(rel_spread * 50.0, 4.0);
                        uint32_t seed = (uint32_t)(tick->tick_id * 2654435761u
                                                  ^ ((uint32_t)inst * 0x9E3779B1u)
                                                  ^ (uint32_t)t2);
                        compute_risk_mc(mid, vol_dev, seed,
                                        var_95, cvar_95, mc_mean, mc_std);
                    }

                    /* T3: kernel done */
                    uint64_t t3 = clock64();

                    /* Reserve a unique absolute slot number, write the payload,
                     * then publish readiness via the per-slot sequence number.
                     * The CPU consumer must not trust ring_head alone. */
                    uint64_t ring_idx = s_ring_base + (uint64_t)rank;
                    ResultSlot *rslot = &result_ring[ring_idx % ring_depth];

                    rslot->bench.tick_id = tick->tick_id;
                    rslot->bench.t1_ns   = t1;
                    rslot->bench.t2_ns   = t2;
                    rslot->bench.t3_ns   = t3;
                    rslot->bench.t4_ns   = 0;   /* 0 = "in flight" sentinel */
                    rslot->bench.compute_ns = t3 - t2; /* raw GPU-cycle delta */
                    rslot->bench.tier    = tier;
                    rslot->bench.dropped = 0;
                    memset(rslot->bench._pad, 0, sizeof(rslot->bench._pad));

                    rslot->signal.tick_id       = tick->tick_id;
                    rslot->signal.t3_ns         = t3;
                    rslot->signal.t4_ns         = 0;
                    rslot->signal.instrument_id = tick->instrument_id;
                    rslot->signal.signal        = combined;
                    rslot->signal.rsi_signal    = rsi_sig;
                    rslot->signal.rsi           = rsi;
                    rslot->signal.mid_price     = mid;
                    rslot->signal.spread        = spread;
                    rslot->signal.fast_ema      = fast_ema;
                    rslot->signal.slow_ema      = slow_ema;
                    rslot->signal.var_95        = var_95;
                    rslot->signal.cvar_95       = cvar_95;
                    rslot->signal.mc_mean       = mc_mean;
                    rslot->signal.mc_std        = mc_std;

                    uint64_t t4 = clock64();
                    rslot->bench.t4_ns  = t4;
                    rslot->signal.t4_ns = t4;
                    __threadfence_system();
                    rslot->seq = ring_idx + 1;

                    atomicAdd((unsigned long long *)&s_ring_writes, 1ULL);
        }

        /* Ensure all threads complete before next burst */
        __syncthreads();
    }

    if (tid == 0 && stats != nullptr) {
        stats->polls       = s_poll_count;
        stats->bursts      = s_recv_count;
        stats->rx_pkts     = s_pkt_total;
        stats->addr_zero   = s_addr_zero;
        stats->port_miss   = s_port_miss;
        stats->ring_writes = s_ring_writes;
    }
}

/* ── CPU forwarding thread ──────────────────────────────────────��─────────── */
struct ForwardCtx {
    ResultRing        *ring        = nullptr;
    double             ns_per_cyc  = 1.0;
    /* GPU clock64() <-> host wall-clock anchor captured just before
     * the persistent kernel starts. Lets cpu_forward_thread translate
     * every (t1, t2, t3, t4) from "cycles since SM reset" into
     * "nanoseconds since Unix epoch" in the receiver host clock domain.
     * Without this anchor, ingress/e2e latencies are nonsense because the
     * GPU clock and host wall clock don't even share a zero. */
    uint64_t           gpu_cyc_anchor        = 0;
    uint64_t           host_wall_anchor_ns   = 0;
    int                harness_fd  = -1;
    int                signal_fd   = -1;
    sockaddr_in        harness_dest{};
    sockaddr_in        signal_dest{};
    bool               t1_bypass_gpu_cycle_conversion = false;
    std::atomic<bool>  stop{false};
    std::atomic<uint64_t> forwarded{0};
    std::atomic<uint64_t> ring_overflow_drops{0};
};

template<typename T>
static inline void send_many(int fd, sockaddr_in &dest, const T *items, int n);

/* One-shot kernel: read clock64() once so the host can anchor the GPU
 * cycle counter to wall-clock time. Launched just before the persistent
 * receive kernel; see main(). */
__global__ static void clock64_anchor_kernel(uint64_t *out)
{
    if (threadIdx.x == 0 && blockIdx.x == 0) {
        *out = clock64();
    }
}

/* Translate a raw clock64() cycle value into nanoseconds since the Unix
 * epoch, using the anchor pair captured at kernel launch. Preserves the
 * 0 sentinel (used when t4 hasn't been written yet). */
static uint64_t cyc_to_wall_ns(uint64_t cyc,
                                uint64_t cyc_anchor,
                                uint64_t wall_anchor_ns,
                                double   ns_per_cyc)
{
    if (cyc == 0) return 0;
    /* clock64() is 64-bit unsigned and monotonic within an SM session,
     * but (cyc - cyc_anchor) can wrap if cyc < cyc_anchor (shouldn't
     * happen in steady state). Cast to signed for safe subtraction. */
    int64_t delta_cyc = (int64_t)(cyc - cyc_anchor);
    int64_t delta_ns  = (int64_t)((double)delta_cyc * ns_per_cyc);
    return (uint64_t)((int64_t)wall_anchor_ns + delta_ns);
}

static uint64_t cyc_delta_to_ns(uint64_t delta_cyc, double ns_per_cyc)
{
    return (uint64_t)((double)delta_cyc * ns_per_cyc);
}

static void cpu_forward_thread(ForwardCtx *ctx)
{
    uint64_t fwd_count = 0;
    uint64_t ring_overflow_drop = 0;
    uint64_t last_report = 0;
    auto start_time = std::chrono::steady_clock::now();

    fprintf(stderr, "[CPU-FWD] forwarding thread started, ring depth=%u\n",
            ctx->ring->depth);

    while (!ctx->stop.load()) {
        uint64_t head = *ctx->ring->head;
        bool did_work = false;

        /* Periodic report even when idle */
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
        if (elapsed > 0 && elapsed % 5 == 0 && (uint64_t)elapsed != last_report) {
            last_report = elapsed;
            fprintf(stderr, "[CPU-FWD] %llds: ring head=%llu tail=%llu forwarded=%llu\n",
                    (long long)elapsed,
                    (unsigned long long)head,
                    (unsigned long long)ctx->ring->tail,
                    (unsigned long long)fwd_count);
        }

        if (ctx->ring->tail < head) {
            if (head - ctx->ring->tail > ctx->ring->depth) {
                uint64_t lost = (head - ctx->ring->tail) - ctx->ring->depth;
                ring_overflow_drop += lost;
                ctx->ring->tail = head - ctx->ring->depth;
                fprintf(stderr,
                        "[CPU-FWD] ring overflow: dropped %llu stale results "
                        "(total=%llu)\n",
                        (unsigned long long)lost,
                        (unsigned long long)ring_overflow_drop);
            }
            nvtxRangePushA("forward_batch");
            BenchmarkResult bench_batch[SEND_BATCH];
            SignalResult sig_batch[SEND_BATCH];
            int out_n = 0;
            while (ctx->ring->tail < head) {
                uint64_t idx = ctx->ring->tail % ctx->ring->depth;
                ResultSlot *rs = &ctx->ring->slots[idx];
                uint64_t expected_seq = ctx->ring->tail + 1;
                if (rs->seq != expected_seq) {
                    break;
                }

                BenchmarkResult br  = rs->bench;
                SignalResult    sig = rs->signal;

                if (!ctx->t1_bypass_gpu_cycle_conversion) {
                    br.t1_ns = cyc_to_wall_ns(br.t1_ns,
                                              ctx->gpu_cyc_anchor,
                                              ctx->host_wall_anchor_ns,
                                              ctx->ns_per_cyc);
                }
                br.t2_ns  = cyc_to_wall_ns(br.t2_ns,
                                           ctx->gpu_cyc_anchor,
                                           ctx->host_wall_anchor_ns,
                                           ctx->ns_per_cyc);
                br.t3_ns  = cyc_to_wall_ns(br.t3_ns,
                                           ctx->gpu_cyc_anchor,
                                           ctx->host_wall_anchor_ns,
                                           ctx->ns_per_cyc);
                br.t4_ns  = cyc_to_wall_ns(br.t4_ns,
                                           ctx->gpu_cyc_anchor,
                                           ctx->host_wall_anchor_ns,
                                           ctx->ns_per_cyc);
                br.compute_ns = cyc_delta_to_ns(br.compute_ns, ctx->ns_per_cyc);
                sig.t3_ns = br.t3_ns;
                sig.t4_ns = br.t4_ns;
                bench_batch[out_n] = br;
                sig_batch[out_n] = sig;
                ++out_n;
                fwd_count++;
                if (fwd_count <= 5 || fwd_count % 100000 == 0) {
                    fprintf(stderr, "[CPU-FWD] #%llu: tick=%u queued_for_send\n",
                            (unsigned long long)fwd_count, br.tick_id);
                }

                rs->seq = ctx->ring->tail + ctx->ring->depth;
                ++ctx->ring->tail;
                did_work = true;

                if (out_n >= SEND_BATCH || ctx->ring->tail >= head) {
                    nvtxRangePushA("sendto_pair");
                    send_many(ctx->harness_fd, ctx->harness_dest, bench_batch, out_n);
                    send_many(ctx->signal_fd,  ctx->signal_dest,  sig_batch,   out_n);
                    nvtxRangePop();
                    out_n = 0;
                }
            }
            nvtxMarkA("batch_done");
            nvtxRangePop();
        }
        if (!did_work) {
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }
    }

    fprintf(stderr, "[CPU-FWD] stopped. total forwarded=%llu ring_overflow_drops=%llu\n",
            (unsigned long long)fwd_count,
            (unsigned long long)ring_overflow_drop);
    ctx->forwarded.store(fwd_count, std::memory_order_relaxed);
    ctx->ring_overflow_drops.store(ring_overflow_drop, std::memory_order_relaxed);
}

/* ── DOCA host-side initialisation (DOCA 3.x API) ─────────────────────── */
struct DocaContext {
    struct doca_dev              *dev        = nullptr;
    struct doca_gpu              *gpu_dev    = nullptr;
    struct doca_flow_port        *flow_port  = nullptr;
    struct doca_eth_rxq          *rxq_cpu    = nullptr;
    struct doca_gpu_eth_rxq      *rxq_gpu    = nullptr;
    struct doca_mmap             *pkt_mmap   = nullptr;
    struct doca_ctx              *rxq_ctx    = nullptr;
    void                         *gpu_pkt_buf = nullptr;
    struct doca_flow_pipe_entry  *flow_entry = nullptr;  /* for counter query */
};

static bool g_use_nic_t1 = false;
static bool g_light_bench = false;
static const char *g_stats_file = nullptr;

static void write_receiver_stats(const char *path,
                                 uint64_t flow_pkts,
                                 const GpuKernelStats &gpu,
                                 uint64_t cpu_forwarded,
                                 uint64_t ring_overflow)
{
    if (path == nullptr || path[0] == '\0') return;

    std::ofstream f(path);
    if (!f) {
        fprintf(stderr, "[gpu_receiver] warning: cannot write stats file %s\n", path);
        return;
    }
    f << "flow_pkts=" << flow_pkts << '\n'
      << "gpu_rx_pkts=" << gpu.rx_pkts << '\n'
      << "gpu_bursts=" << gpu.bursts << '\n'
      << "gpu_polls=" << gpu.polls << '\n'
      << "gpu_ring_writes=" << gpu.ring_writes << '\n'
      << "gpu_addr_zero=" << gpu.addr_zero << '\n'
      << "gpu_port_miss=" << gpu.port_miss << '\n'
      << "cpu_forwarded=" << cpu_forwarded << '\n'
      << "ring_overflow=" << ring_overflow << '\n';
}

static size_t get_page_size(void)
{
    long ret = sysconf(_SC_PAGESIZE);
    return (ret > 0) ? (size_t)ret : 4096;
}

static int doca_init(DocaContext &doca, const char *nic_pcie, const char *gpu_pcie,
                     int cuda_device)
{
    CUDA_CHECK(cudaSetDevice(cuda_device));

    /* Open DOCA device by NIC PCIe address */
    struct doca_devinfo **dev_list;
    uint32_t nb_devs;
    DOCA_CHECK(doca_devinfo_create_list(&dev_list, &nb_devs));

    bool found = false;
    for (uint32_t i = 0; i < nb_devs; ++i) {
        uint8_t is_equal = 0;
        doca_error_t r = doca_devinfo_is_equal_pci_addr(dev_list[i], nic_pcie,
                                                         &is_equal);
        if (r == DOCA_SUCCESS && is_equal) {
            r = doca_dev_open(dev_list[i], &doca.dev);
            if (r == DOCA_SUCCESS) {
                fprintf(stderr, "[gpu_receiver] DOCA NIC device opened: %s\n",
                        nic_pcie);
                found = true;
                break;
            }
        }
    }
    doca_devinfo_destroy_list(dev_list);
    if (!found) {
        fprintf(stderr, "DOCA device for NIC PCIe '%s' not found\n", nic_pcie);
        return -1;
    }

    /* Create DOCA GPU context */
    doca_error_t err;

    fprintf(stderr, "[DBG] step 1: doca_gpu_create(%s)\n", gpu_pcie);
    err = doca_gpu_create(gpu_pcie, &doca.gpu_dev);
    fprintf(stderr, "[DBG]   -> %s (%d)\n", doca_error_get_descr(err), (int)err);
    if (err != DOCA_SUCCESS) return -1;

    /* DOCA Flow init — required before RXQ ctx_start (must run as root) */
    fprintf(stderr, "[DBG] step 1b: doca_flow_init + port_start\n");
    {
        struct doca_flow_cfg *flow_cfg = nullptr;
        err = doca_flow_cfg_create(&flow_cfg);
        fprintf(stderr, "[DBG]   flow_cfg_create -> %s (%d)\n", doca_error_get_descr(err), (int)err);
        if (err != DOCA_SUCCESS) return -1;

        err = doca_flow_cfg_set_pipe_queues(flow_cfg, 1);
        fprintf(stderr, "[DBG]   set_pipe_queues(1) -> %s (%d)\n", doca_error_get_descr(err), (int)err);
        if (err != DOCA_SUCCESS) { doca_flow_cfg_destroy(flow_cfg); return -1; }

        /* NOTE: "isolated" removed — it was preventing eswitch-redirected
         * (tc flower) packets from reaching the DOCA Flow pipe. Without
         * isolated, the kernel netdev path is still active (tcpdump works
         * alongside DOCA Flow), and eswitch-forwarded packets reach us. */
        err = doca_flow_cfg_set_mode_args(flow_cfg, "vnf,hws");
        fprintf(stderr, "[DBG]   set_mode_args -> %s (%d)\n", doca_error_get_descr(err), (int)err);
        if (err != DOCA_SUCCESS) { doca_flow_cfg_destroy(flow_cfg); return -1; }

        err = doca_flow_cfg_set_nr_counters(flow_cfg, 1024);
        fprintf(stderr, "[DBG]   set_nr_counters -> %s (%d)\n", doca_error_get_descr(err), (int)err);
        if (err != DOCA_SUCCESS) { doca_flow_cfg_destroy(flow_cfg); return -1; }

        err = doca_flow_init(flow_cfg);
        fprintf(stderr, "[DBG]   doca_flow_init -> %s (%d)\n", doca_error_get_descr(err), (int)err);
        doca_flow_cfg_destroy(flow_cfg);
        if (err != DOCA_SUCCESS) return -1;

        struct doca_flow_port_cfg *port_cfg = nullptr;
        err = doca_flow_port_cfg_create(&port_cfg);
        fprintf(stderr, "[DBG]   port_cfg_create -> %s (%d)\n", doca_error_get_descr(err), (int)err);
        if (err != DOCA_SUCCESS) return -1;

        err = doca_flow_port_cfg_set_port_id(port_cfg, 0);
        fprintf(stderr, "[DBG]   set_port_id(0) -> %s (%d)\n", doca_error_get_descr(err), (int)err);
        if (err != DOCA_SUCCESS) { doca_flow_port_cfg_destroy(port_cfg); return -1; }

        err = doca_flow_port_cfg_set_dev(port_cfg, doca.dev);
        fprintf(stderr, "[DBG]   set_dev -> %s (%d)\n", doca_error_get_descr(err), (int)err);
        if (err != DOCA_SUCCESS) { doca_flow_port_cfg_destroy(port_cfg); return -1; }

        err = doca_flow_port_start(port_cfg, &doca.flow_port);
        fprintf(stderr, "[DBG]   doca_flow_port_start -> %s (%d)\n", doca_error_get_descr(err), (int)err);
        doca_flow_port_cfg_destroy(port_cfg);
        if (err != DOCA_SUCCESS) return -1;
    }

    fprintf(stderr, "[DBG] step 2: doca_eth_rxq_create(MAX_PKT_NUM=%d, MAX_PKT_SIZE=%d)\n",
            MAX_PKT_NUM, MAX_PKT_SIZE);
    err = doca_eth_rxq_create(doca.dev, MAX_PKT_NUM, MAX_PKT_SIZE, &doca.rxq_cpu);
    fprintf(stderr, "[DBG]   -> %s (%d)\n", doca_error_get_descr(err), (int)err);
    if (err != DOCA_SUCCESS) return -1;

    fprintf(stderr, "[DBG] step 3: doca_eth_rxq_set_type(CYCLIC)\n");
    err = doca_eth_rxq_set_type(doca.rxq_cpu, DOCA_ETH_RXQ_TYPE_CYCLIC);
    fprintf(stderr, "[DBG]   -> %s (%d)\n", doca_error_get_descr(err), (int)err);
    if (err != DOCA_SUCCESS) return -1;

    uint32_t cyclic_buf_size = 0;
    fprintf(stderr, "[DBG] step 4: doca_eth_rxq_estimate_packet_buf_size\n");
    err = doca_eth_rxq_estimate_packet_buf_size(
        DOCA_ETH_RXQ_TYPE_CYCLIC, 0, 0, MAX_PKT_SIZE, MAX_PKT_NUM,
        0, 0, 0, &cyclic_buf_size);
    fprintf(stderr, "[DBG]   -> %s (%d), buf_size=%u\n", doca_error_get_descr(err), (int)err, cyclic_buf_size);
    if (err != DOCA_SUCCESS) return -1;

    size_t page_sz = get_page_size();
    cyclic_buf_size = ((cyclic_buf_size + page_sz - 1) / page_sz) * page_sz;
    fprintf(stderr, "[DBG]   aligned buf_size=%u, page_sz=%zu\n", cyclic_buf_size, page_sz);

    fprintf(stderr, "[DBG] step 5: doca_gpu_mem_alloc(%u bytes)\n", cyclic_buf_size);
    err = doca_gpu_mem_alloc(doca.gpu_dev, cyclic_buf_size, page_sz,
                              DOCA_GPU_MEM_TYPE_GPU, &doca.gpu_pkt_buf, NULL);
    fprintf(stderr, "[DBG]   -> %s (%d), ptr=%p\n", doca_error_get_descr(err), (int)err, doca.gpu_pkt_buf);
    if (err != DOCA_SUCCESS) return -1;

    fprintf(stderr, "[DBG] step 6: doca_mmap_create + add_dev\n");
    err = doca_mmap_create(&doca.pkt_mmap);
    fprintf(stderr, "[DBG]   create -> %s (%d)\n", doca_error_get_descr(err), (int)err);
    if (err != DOCA_SUCCESS) return -1;
    err = doca_mmap_add_dev(doca.pkt_mmap, doca.dev);
    fprintf(stderr, "[DBG]   add_dev -> %s (%d)\n", doca_error_get_descr(err), (int)err);
    if (err != DOCA_SUCCESS) return -1;

    fprintf(stderr, "[DBG] step 7: dmabuf or peermem\n");
    int dmabuf_fd = -1;
    doca_error_t dm_ret = doca_gpu_dmabuf_fd(doca.gpu_dev, doca.gpu_pkt_buf,
                                              cyclic_buf_size, &dmabuf_fd);
    if (dm_ret == DOCA_SUCCESS) {
        fprintf(stderr, "[DBG]   dmabuf fd=%d\n", dmabuf_fd);
        err = doca_mmap_set_dmabuf_memrange(doca.pkt_mmap, dmabuf_fd,
                                             doca.gpu_pkt_buf, 0, cyclic_buf_size);
        fprintf(stderr, "[DBG]   set_dmabuf_memrange -> %s (%d)\n", doca_error_get_descr(err), (int)err);
    } else {
        fprintf(stderr, "[DBG]   dmabuf failed (%s), using peermem\n", doca_error_get_descr(dm_ret));
        err = doca_mmap_set_memrange(doca.pkt_mmap, doca.gpu_pkt_buf, cyclic_buf_size);
        fprintf(stderr, "[DBG]   set_memrange -> %s (%d)\n", doca_error_get_descr(err), (int)err);
    }
    if (err != DOCA_SUCCESS) return -1;

    fprintf(stderr, "[DBG] step 8: mmap permissions + start\n");
    err = doca_mmap_set_permissions(doca.pkt_mmap,
        DOCA_ACCESS_FLAG_LOCAL_READ_WRITE | DOCA_ACCESS_FLAG_PCI_RELAXED_ORDERING);
    fprintf(stderr, "[DBG]   set_permissions -> %s (%d)\n", doca_error_get_descr(err), (int)err);
    if (err != DOCA_SUCCESS) return -1;
    err = doca_mmap_start(doca.pkt_mmap);
    fprintf(stderr, "[DBG]   mmap_start -> %s (%d)\n", doca_error_get_descr(err), (int)err);
    if (err != DOCA_SUCCESS) return -1;

    fprintf(stderr, "[DBG] step 9: doca_eth_rxq_set_pkt_buf\n");
    err = doca_eth_rxq_set_pkt_buf(doca.rxq_cpu, doca.pkt_mmap, 0, cyclic_buf_size);
    fprintf(stderr, "[DBG]   -> %s (%d)\n", doca_error_get_descr(err), (int)err);
    if (err != DOCA_SUCCESS) return -1;

    fprintf(stderr, "[DBG] step 10: doca_eth_rxq_as_doca_ctx\n");
    doca.rxq_ctx = doca_eth_rxq_as_doca_ctx(doca.rxq_cpu);
    fprintf(stderr, "[DBG]   -> ctx=%p\n", (void*)doca.rxq_ctx);
    if (!doca.rxq_ctx) return -1;

    fprintf(stderr, "[DBG] step 11: doca_ctx_set_datapath_on_gpu\n");
    err = doca_ctx_set_datapath_on_gpu(doca.rxq_ctx, doca.gpu_dev);
    fprintf(stderr, "[DBG]   -> %s (%d)\n", doca_error_get_descr(err), (int)err);
    if (err != DOCA_SUCCESS) return -1;

    fprintf(stderr, "[DBG] step 12: doca_ctx_start\n");
    err = doca_ctx_start(doca.rxq_ctx);
    fprintf(stderr, "[DBG]   -> %s (%d)\n", doca_error_get_descr(err), (int)err);
    if (err != DOCA_SUCCESS) return -1;

    fprintf(stderr, "[DBG] step 13: doca_eth_rxq_get_gpu_handle\n");
    err = doca_eth_rxq_get_gpu_handle(doca.rxq_cpu, &doca.rxq_gpu);
    fprintf(stderr, "[DBG]   -> %s (%d)\n", doca_error_get_descr(err), (int)err);
    if (err != DOCA_SUCCESS) return -1;

    /* step 14: assign queue ID for flow steering */
    err = doca_eth_rxq_apply_queue_id(doca.rxq_cpu, 0);
    fprintf(stderr, "[DBG] step 14: apply_queue_id(0) -> %s (%d)\n",
            doca_error_get_descr(err), (int)err);
    if (err != DOCA_SUCCESS) return -1;

    /* step 15: create DOCA Flow pipes (NVIDIA reference pattern).
     * Root CONTROL pipe matches IPv4/UDP and forwards to non-root BASIC pipe
     * which does RSS steering into the GPU RX queue. */
    fprintf(stderr, "[DBG] step 15: create flow pipes (CONTROL root + BASIC UDP)\n");
    {
        /* 15a: Non-root BASIC pipe — matches IPv4+UDP via parser_meta, RSS to queue 0 */
        struct doca_flow_match udp_match = {};
        udp_match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
        udp_match.parser_meta.outer_l4_type = DOCA_FLOW_L4_META_UDP;
        udp_match.outer.eth.type = htons(DOCA_FLOW_ETHER_TYPE_IPV4);
        udp_match.outer.ip4.dst_ip = htonl(inet_addr(TICK_MCAST_ADDR));
        udp_match.outer.ip4.next_proto = IPPROTO_UDP;
        udp_match.outer.ip4.version_ihl = 0;  /* unset, not required */

        struct doca_flow_monitor udp_monitor = {};
        udp_monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

        uint16_t rss_queues[1] = { 0 };
        struct doca_flow_fwd fwd = {};
        fwd.type = DOCA_FLOW_FWD_RSS;
        fwd.rss_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
        fwd.rss.queues_array = rss_queues;
        fwd.rss.outer_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_UDP;
        fwd.rss.nr_queues = 1;

        struct doca_flow_fwd miss_fwd = {};
        miss_fwd.type = DOCA_FLOW_FWD_DROP;

        struct doca_flow_pipe_cfg *pipe_cfg = nullptr;
        err = doca_flow_pipe_cfg_create(&pipe_cfg, doca.flow_port);
        fprintf(stderr, "[DBG]   15a: udp_pipe_cfg_create -> %s (%d)\n", doca_error_get_descr(err), (int)err);
        if (err != DOCA_SUCCESS) return -1;

        doca_flow_pipe_cfg_set_name(pipe_cfg, "GPU_RXQ_UDP_PIPE");
        doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
        doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
        err = doca_flow_pipe_cfg_set_match(pipe_cfg, &udp_match, NULL);
        fprintf(stderr, "[DBG]   udp_set_match -> %s (%d)\n", doca_error_get_descr(err), (int)err);
        if (err != DOCA_SUCCESS) { doca_flow_pipe_cfg_destroy(pipe_cfg); return -1; }
        doca_flow_pipe_cfg_set_monitor(pipe_cfg, &udp_monitor);

        struct doca_flow_pipe *udp_pipe = nullptr;
        err = doca_flow_pipe_create(pipe_cfg, &fwd, &miss_fwd, &udp_pipe);
        fprintf(stderr, "[DBG]   udp_pipe_create -> %s (%d)\n", doca_error_get_descr(err), (int)err);
        doca_flow_pipe_cfg_destroy(pipe_cfg);
        if (err != DOCA_SUCCESS) return -1;

        struct doca_flow_pipe_entry *udp_entry = nullptr;
        err = doca_flow_pipe_basic_add_entry(0, udp_pipe, &udp_match, 0, NULL, NULL, NULL,
                                              DOCA_FLOW_ENTRY_FLAGS_NO_WAIT, NULL, &udp_entry);
        fprintf(stderr, "[DBG]   udp_pipe_add_entry -> %s (%d)\n", doca_error_get_descr(err), (int)err);
        if (err != DOCA_SUCCESS) return -1;

        err = doca_flow_entries_process(doca.flow_port, 0, 10000, 0);
        fprintf(stderr, "[DBG]   udp_entries_process -> %s (%d)\n", doca_error_get_descr(err), (int)err);
        if (err != DOCA_SUCCESS) return -1;

        doca.flow_entry = udp_entry;  /* save for counter query */

        /* 15b: Root CONTROL pipe — matches outer IPv4/UDP headers, forwards to UDP pipe */
        struct doca_flow_monitor root_monitor = {};
        root_monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

        struct doca_flow_pipe_cfg *root_cfg = nullptr;
        err = doca_flow_pipe_cfg_create(&root_cfg, doca.flow_port);
        fprintf(stderr, "[DBG]   15b: root_pipe_cfg_create -> %s (%d)\n", doca_error_get_descr(err), (int)err);
        if (err != DOCA_SUCCESS) return -1;

        doca_flow_pipe_cfg_set_name(root_cfg, "ROOT_CONTROL_PIPE");
        doca_flow_pipe_cfg_set_type(root_cfg, DOCA_FLOW_PIPE_CONTROL);
        doca_flow_pipe_cfg_set_is_root(root_cfg, true);
        doca_flow_pipe_cfg_set_monitor(root_cfg, &root_monitor);

        struct doca_flow_pipe *root_pipe = nullptr;
        err = doca_flow_pipe_create(root_cfg, NULL, NULL, &root_pipe);
        fprintf(stderr, "[DBG]   root_pipe_create -> %s (%d)\n", doca_error_get_descr(err), (int)err);
        doca_flow_pipe_cfg_destroy(root_cfg);
        if (err != DOCA_SUCCESS) return -1;

        /* Add IPv4/UDP match entry to root pipe -> forward to UDP pipe */
        struct doca_flow_match root_match = {};
        root_match.outer.eth.type = htons(DOCA_FLOW_ETHER_TYPE_IPV4);
        root_match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
        root_match.outer.ip4.next_proto = IPPROTO_UDP;

        struct doca_flow_fwd root_fwd = {};
        root_fwd.type = DOCA_FLOW_FWD_PIPE;
        root_fwd.next_pipe = udp_pipe;

        struct doca_flow_pipe_entry *root_entry = nullptr;
        err = doca_flow_pipe_control_add_entry(0, root_pipe,
                                                &root_match, NULL, NULL, NULL, NULL,
                                                NULL, NULL, 1, &root_fwd, NULL, &root_entry);
        fprintf(stderr, "[DBG]   root_control_add_entry(UDP) -> %s (%d)\n",
                doca_error_get_descr(err), (int)err);
        if (err != DOCA_SUCCESS) return -1;

        err = doca_flow_entries_process(doca.flow_port, 0, 10000, 0);
        fprintf(stderr, "[DBG]   root_entries_process -> %s (%d)\n", doca_error_get_descr(err), (int)err);
        if (err != DOCA_SUCCESS) return -1;
    }

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

template<typename T>
static inline void send_many(int fd, sockaddr_in &dest, const T *items, int n)
{
    if (n <= 0) return;
    struct mmsghdr msgs[SEND_BATCH];
    struct iovec   iovs[SEND_BATCH];
    int sent = 0;
    while (sent < n) {
        int chunk = std::min(n - sent, SEND_BATCH);
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

/* ── main ───────────────────────────────────────────────────────────────── */
static volatile uint32_t g_quit = 0;
static void sig_handler(int) { g_quit = 1; }

int main(int argc, char **argv)
{
    const char *gpu_pcie      = "";
    const char *nic_pcie      = "";
    int         cuda_device   = 1;   /* GPU 1 (GPU 0 has VLLM) */
    uint8_t     tier          = 4;
    const char *harness_ip    = "127.0.0.1";
    const char *fillsim_ip    = "127.0.0.1";

    for (int i = 1; i < argc; ++i) {
        if      (!strcmp(argv[i],"--gpu-pcie")  && i+1<argc) gpu_pcie     = argv[++i];
        else if (!strcmp(argv[i],"--nic-pcie")  && i+1<argc) nic_pcie     = argv[++i];
        else if (!strcmp(argv[i],"--gpu")       && i+1<argc) cuda_device  = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--tier")      && i+1<argc) tier         = (uint8_t)atoi(argv[++i]);
        else if (!strcmp(argv[i],"--harness")   && i+1<argc) harness_ip   = argv[++i];
        else if (!strcmp(argv[i],"--fillsim")   && i+1<argc) fillsim_ip   = argv[++i];
        else if (!strcmp(argv[i],"--nic-t1"))                     g_use_nic_t1 = true;
        else if (!strcmp(argv[i],"--light-bench"))                g_light_bench = true;
        else if (!strcmp(argv[i],"--stats-file") && i+1<argc)     g_stats_file = argv[++i];
    }

    fprintf(stderr, "[T%d gpu_receiver] gpu=%d gpu_pcie=%s nic_pcie=%s\n",
            tier, cuda_device, gpu_pcie, nic_pcie);
    if (g_light_bench)
        fprintf(stderr, "[T4/T5] light benchmark mode enabled (Monte Carlo skipped)\n");

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    CUDA_CHECK(cudaSetDevice(cuda_device));

    /* Get GPU clock rate for ns conversion */
    int clock_khz = 0;
    CUDA_CHECK(cudaDeviceGetAttribute(&clock_khz, cudaDevAttrClockRate, cuda_device));
    double ns_per_cyc = 1e6 / (double)clock_khz;

    /* DOCA init */
    DocaContext doca{};
    if (doca_init(doca, nic_pcie, gpu_pcie, cuda_device) < 0) return 1;

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
    CUDA_CHECK(cudaHostAlloc(&ring.slots, ring.depth * sizeof(ResultSlot),
                              cudaHostAllocMapped));
    /* No WriteCombined — GPU writes this, CPU reads it */
    CUDA_CHECK(cudaHostAlloc(&ring.head,  sizeof(uint64_t),
                              cudaHostAllocMapped));
    *ring.head = 0;
    ring.tail  = 0;
    std::memset(ring.slots, 0, ring.depth * sizeof(ResultSlot));
    for (uint32_t i = 0; i < ring.depth; ++i) {
        ring.slots[i].seq = i;
    }

    /* GPU-visible pointers for host-mapped result ring */
    ResultSlot *d_ring_slots = nullptr;
    uint64_t *d_ring_head = nullptr;
    CUDA_CHECK(cudaHostGetDevicePointer(&d_ring_slots, ring.slots, 0));
    CUDA_CHECK(cudaHostGetDevicePointer(&d_ring_head, ring.head, 0));

    GpuKernelStats *h_gpu_stats = nullptr;
    GpuKernelStats *d_gpu_stats = nullptr;
    CUDA_CHECK(cudaHostAlloc(&h_gpu_stats, sizeof(GpuKernelStats),
                              cudaHostAllocMapped));
    std::memset(h_gpu_stats, 0, sizeof(GpuKernelStats));
    CUDA_CHECK(cudaHostGetDevicePointer(&d_gpu_stats, h_gpu_stats, 0));

    /* Quit flag — host-pinned mapped memory so CPU writes are
     * immediately visible to the GPU without cudaMemcpy */
    uint32_t *d_quit = nullptr;
    CUDA_CHECK(cudaHostAlloc(&d_quit, sizeof(uint32_t),
                              cudaHostAllocMapped | cudaHostAllocWriteCombined));
    *d_quit = 0;

    /* Output sockets */
    sockaddr_in harness_dest{}, signal_dest{};
    int harness_fd = make_udp_send(harness_ip, BENCH_RESULT_PORT, harness_dest);
    int signal_fd  = make_udp_send(fillsim_ip, SIGNAL_PORT, signal_dest);

    /* CPU forwarding thread context (thread launched below after the
     * clock anchor is captured, so the anchor is valid before any ring
     * entry is forwarded — no race). */
    ForwardCtx fwd_ctx{};
    fwd_ctx.ring         = &ring;
    fwd_ctx.ns_per_cyc   = ns_per_cyc;
    fwd_ctx.harness_fd   = harness_fd;
    fwd_ctx.signal_fd    = signal_fd;
    fwd_ctx.harness_dest = harness_dest;
    fwd_ctx.signal_dest  = signal_dest;
    fwd_ctx.t1_bypass_gpu_cycle_conversion = true;

    /* ── GPU-cycle ↔ host-wall-clock anchor ────────────────────────────────
     * t2/t3/t4 are stamped via clock64() inside the GPU kernel — that's a
     * per-SM cycle counter with no defined relationship to wall time. To
     * make (t4 - t1) and (t2 - t1) meaningful, we capture ONE pair of
     * (clock64() cycle, CLOCK_REALTIME ns) just before the persistent
     * kernel begins, and use it in cpu_forward_thread to translate every
     * stamp into Unix-epoch ns (the same frame as t1 from the sender). */
    uint64_t *h_cyc_anchor = nullptr;
    CUDA_CHECK(cudaHostAlloc(&h_cyc_anchor, sizeof(uint64_t),
                              cudaHostAllocMapped));
    *h_cyc_anchor = 0;
    clock64_anchor_kernel<<<1, 1>>>(h_cyc_anchor);
    CUDA_CHECK(cudaDeviceSynchronize());
    {
        auto now = std::chrono::system_clock::now();
        fwd_ctx.host_wall_anchor_ns = (uint64_t)
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                now.time_since_epoch()).count();
    }
    fwd_ctx.gpu_cyc_anchor = *h_cyc_anchor;
    cudaFreeHost(h_cyc_anchor);
    fprintf(stderr,
            "[gpu_receiver] clock anchor: gpu_cyc=%llu host_wall_ns=%llu "
            "ns_per_cyc=%.4f (clock_khz=%d)\n",
            (unsigned long long)fwd_ctx.gpu_cyc_anchor,
            (unsigned long long)fwd_ctx.host_wall_anchor_ns,
            ns_per_cyc, clock_khz);

    std::thread fwd_thread(cpu_forward_thread, &fwd_ctx);

    /* Begin profiling window BEFORE launching the persistent kernel, so that
     * nsys --capture-range=cudaProfilerApi observes the kernel launch and all
     * of its device activity. Starting the profiler after the launch would
     * leave the persistent kernel invisible to cuda_gpu_kern_sum. Orchestration
     * timing (warmup, duration) is owned by benchmark.py — we keep the
     * receiver window maximal and let the harness slice results by t1_ns. */
    cudaProfilerStart();
    nvtxRangePushA("steady_state");
    fprintf(stderr, "[gpu_receiver] cudaProfilerStart() — capturing from kernel launch\n");

    /* Launch persistent GPU receive kernel.
     * Launch shape: <<<1, 32>>> — a single warp. The kernel uses the
     * WARP-scope recv template which requires exactly one warp to
     * participate in the recv call. MAX_PKT_PER_BURST == 32 so each
     * thread handles at most one packet per poll. */
    fprintf(stderr, "[gpu_receiver] launching persistent GPU kernel (1 block x %d threads = 1 warp)...\n",
            MAX_PKT_PER_BURST);
    gpu_recv_process_kernel<<<1, MAX_PKT_PER_BURST>>>(
        doca.rxq_gpu,
        d_quit,
        d_fast_ema, d_slow_ema, d_avg_gain, d_avg_loss, d_last_mid,
        d_ring_slots,
        d_ring_head,
        ring.depth,
        d_gpu_stats,
        tier,
        g_use_nic_t1 ? 1 : 0,
        g_light_bench ? 1 : 0);

    /* Wait for SIGINT / SIGTERM — periodically query flow counters */
    int poll_sec = 0;
    while (!g_quit) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        poll_sec++;

        /* Query DOCA Flow entry counter every 5 seconds */
        if (poll_sec % 5 == 0 && doca.flow_entry) {
            struct doca_flow_resource_query stats = {};
            doca_error_t qerr = doca_flow_resource_query_entry(
                doca.flow_entry, &stats);
            fprintf(stderr, "[FLOW-COUNTER] %ds: query=%s total_bytes=%llu total_pkts=%llu\n",
                    poll_sec,
                    (qerr == DOCA_SUCCESS) ? "ok" : doca_error_get_descr(qerr),
                    (unsigned long long)stats.counter.total_bytes,
                    (unsigned long long)stats.counter.total_pkts);
        }

        /* Also process flow entries to ensure NIC updates */
        doca_flow_entries_process(doca.flow_port, 0, 100, 0);
    }

    fprintf(stderr, "[gpu_receiver] stopping...\n");

    /* Signal kernel to stop FIRST — d_quit is host-mapped, GPU sees it immediately.
     * nsys cudaProfilerStop() will hang if the GPU is still busy, so we drain it
     * before ending the profiling window. */
    *d_quit = 1;
    __sync_synchronize();  /* memory fence */

    /* Wait for kernel to exit */
    cudaError_t sync_err = cudaDeviceSynchronize();
    if (sync_err != cudaSuccess)
        fprintf(stderr, "[gpu_receiver] cudaDeviceSynchronize: %s\n",
                cudaGetErrorString(sync_err));
    fprintf(stderr, "[gpu_receiver] kernel exited, ending profile window\n");

    /* End profiling window now that GPU is idle */
    nvtxRangePop();              /* steady_state */
    cudaProfilerStop();
    fprintf(stderr, "[gpu_receiver] cudaProfilerStop()\n");

    /* Stop forwarding thread */
    fwd_ctx.stop = true;
    fwd_thread.join();

    uint64_t flow_pkts = 0;
    if (doca.flow_entry) {
        doca_flow_entries_process(doca.flow_port, 0, 100, 0);
        struct doca_flow_resource_query stats = {};
        doca_error_t qerr = doca_flow_resource_query_entry(doca.flow_entry, &stats);
        if (qerr == DOCA_SUCCESS)
            flow_pkts = stats.counter.total_pkts;
    }

    write_receiver_stats(g_stats_file,
                         flow_pkts,
                         *h_gpu_stats,
                         fwd_ctx.forwarded.load(std::memory_order_relaxed),
                         fwd_ctx.ring_overflow_drops.load(std::memory_order_relaxed));

    /* Cleanup */
    doca_ctx_stop(doca.rxq_ctx);
    doca_eth_rxq_destroy(doca.rxq_cpu);
    if (doca.flow_port) doca_flow_port_stop(doca.flow_port);
    doca_flow_destroy();
    doca_mmap_destroy(doca.pkt_mmap);
    if (doca.gpu_pkt_buf) doca_gpu_mem_free(doca.gpu_dev, doca.gpu_pkt_buf);
    doca_gpu_destroy(doca.gpu_dev);
    doca_dev_close(doca.dev);

    cudaFree(d_fast_ema);
    cudaFree(d_slow_ema);
    cudaFree(d_avg_gain);
    cudaFree(d_avg_loss);
    cudaFree(d_last_mid);
    cudaFreeHost(d_quit);
    cudaFreeHost(h_gpu_stats);
    cudaFreeHost(ring.slots);
    cudaFreeHost(ring.head);
    close(harness_fd);
    close(signal_fd);

    fprintf(stderr, "[gpu_receiver] done\n");
    return 0;
}
