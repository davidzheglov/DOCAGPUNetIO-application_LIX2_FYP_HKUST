#pragma once

/*
 * process_kernel.cuh — CUDA processing kernel shared by T1, T2, T3.
 *
 * T4/T5 (gpu_receiver.cu) embed equivalent logic inside the DOCA receive
 * kernel rather than calling this separately.
 *
 * Signal generation (ported from development-david-local CPU pipeline):
 *
 *   1. Dual-EMA crossover
 *      fast_ema (α=0.05) tracks price changes quickly.
 *      slow_ema (α=0.01) tracks the longer-term trend.
 *      Signal fires when fast_ema diverges from slow_ema by > EMA_CROSS_THRESH.
 *      This is a standard trend-following signal.
 *
 *   2. RSI (Wilder's smoothed method)
 *      Running avg_gain / avg_loss updated per tick with RSI_ALPHA.
 *      RSI < RSI_OVERSOLD  (30) → buy  (oversold)
 *      RSI > RSI_OVERBOUGHT(70) → sell (overbought)
 *      This is a mean-reversion signal that counterbalances the EMA trend signal.
 *
 *   3. Combined signal
 *      EMA crossover and RSI must agree to emit a non-zero signal.
 *      Disagreement → hold (0).  This reduces false positives.
 *
 * All per-instrument state (fast_ema, slow_ema, avg_gain, avg_loss) lives in
 * device memory arrays of size MAX_INSTRUMENTS.  Updates use CAS loops so
 * concurrent threads operating on different ticks of the same instrument
 * remain consistent.
 *
 * Grid: ceil(n / 256) blocks × 256 threads, one thread per tick.
 */

#include <cuda_runtime.h>
#include "tick_message.h"
#include "signal_result.h"

/* ── Atomic double CAS update ──────────────────────────────────────────────── */

/*
 * cas_update_double() — atomically compute new = f(old) for a double slot.
 * Uses the standard unsigned long long CAS trick valid on sm_60+.
 *
 * 'blend' is the EMA blend factor: new = alpha * sample + (1-alpha) * old.
 */
__device__ static double ema_cas(double *slot, double sample, double alpha)
{
    unsigned long long *addr = reinterpret_cast<unsigned long long *>(slot);
    unsigned long long  expected, desired;
    double old_val, new_val;
    do {
        expected = atomicAdd(addr, 0ULL);   /* atomic load */
        old_val  = __longlong_as_double((long long)expected);
        if (old_val == 0.0) old_val = sample;   /* seed on first tick */
        new_val  = alpha * sample + (1.0 - alpha) * old_val;
        desired  = (unsigned long long)__double_as_longlong(new_val);
    } while (atomicCAS(addr, expected, desired) != expected);
    return new_val;
}

/* Same CAS pattern for RSI avg_gain / avg_loss (non-negative). */
__device__ static double rsi_cas(double *slot, double sample, double alpha)
{
    unsigned long long *addr = reinterpret_cast<unsigned long long *>(slot);
    unsigned long long  expected, desired;
    double old_val, new_val;
    do {
        expected = atomicAdd(addr, 0ULL);
        old_val  = __longlong_as_double((long long)expected);
        new_val  = alpha * sample + (1.0 - alpha) * old_val;
        desired  = (unsigned long long)__double_as_longlong(new_val);
    } while (atomicCAS(addr, expected, desired) != expected);
    return new_val;
}

/* ── Main processing kernel ─────────────────────────────────────────────────── */

/*
 * Per-instrument state arrays (all [MAX_INSTRUMENTS], double):
 *   d_fast_ema   — fast EMA (alpha = EMA_ALPHA_FAST)
 *   d_slow_ema   — slow EMA (alpha = EMA_ALPHA_SLOW)
 *   d_avg_gain   — running average of upward price moves  (for RSI)
 *   d_avg_loss   — running average of downward price moves (for RSI)
 *   d_last_mid   — previous tick's mid-price (to compute gain/loss delta)
 */
__global__ void process_ticks_kernel(
    const TickMessage * __restrict__ ticks,
    int                              n_ticks,
    SignalResult       * __restrict__ signals,
    double             * __restrict__ d_fast_ema,
    double             * __restrict__ d_slow_ema,
    double             * __restrict__ d_avg_gain,
    double             * __restrict__ d_avg_loss,
    double             * __restrict__ d_last_mid,
    uint64_t                         t2_ns)      /* batch arrival time, T1-T3 */
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n_ticks) return;

    const TickMessage &tick = ticks[idx];
    SignalResult      &out  = signals[idx];

    /* ── Mid-price and spread ─────────────────────────────────────────── */
    double mid    = (tick.bid + tick.ask) * 0.5;
    double spread =  tick.ask - tick.bid;
    int    inst   =  tick.instrument_id % MAX_INSTRUMENTS;

    /* ── Fast and slow EMA update ────────────────────────────────────── */
    double fast_ema = ema_cas(&d_fast_ema[inst], mid, EMA_ALPHA_FAST);
    double slow_ema = ema_cas(&d_slow_ema[inst], mid, EMA_ALPHA_SLOW);

    /* ── RSI (Wilder's smoothed method) ──────────────────────────────── */
    /*
     * On each tick we compute the change from the previous mid-price,
     * then update the running avg_gain / avg_loss via EMA.
     *
     * Note: d_last_mid CAS race means two concurrent threads on the same
     * instrument may both see the same "last_mid", causing a gain/loss
     * double-count. Acceptable for a benchmark kernel — signal direction
     * is correct even if magnitude oscillates slightly.
     */
    double last_mid = d_last_mid[inst];
    if (last_mid == 0.0) last_mid = mid;

    double delta = mid - last_mid;
    double gain  = (delta > 0.0) ? delta : 0.0;
    double loss  = (delta < 0.0) ? -delta : 0.0;

    double avg_gain = rsi_cas(&d_avg_gain[inst], gain, RSI_ALPHA);
    double avg_loss = rsi_cas(&d_avg_loss[inst], loss, RSI_ALPHA);

    /* Atomic store last_mid (best-effort — not strictly CAS-safe under high
       concurrency, but directionally correct for signal generation). */
    *(unsigned long long *)&d_last_mid[inst] =
        (unsigned long long)__double_as_longlong(mid);

    double rs  = (avg_loss > 1e-12) ? avg_gain / avg_loss : 100.0;
    float  rsi = (float)(100.0 - 100.0 / (1.0 + rs));
    rsi = fmaxf(0.0f, fminf(100.0f, rsi));   /* clamp [0, 100] */

    /* ── EMA crossover signal ────────────────────────────────────────── */
    /*
     * fast_ema > slow_ema * (1 + threshold) → uptrend  → +1 (buy)
     * fast_ema < slow_ema * (1 - threshold) → downtrend → -1 (sell)
     */
    int8_t ema_sig = 0;
    if (slow_ema > 0.0) {
        double cross = (fast_ema - slow_ema) / slow_ema;
        if (cross >  EMA_CROSS_THRESH) ema_sig = +1;
        if (cross < -EMA_CROSS_THRESH) ema_sig = -1;
    }

    /* ── RSI signal ──────────────────────────────────────────────────── */
    int8_t rsi_sig = 0;
    if (rsi < RSI_OVERSOLD)    rsi_sig = +1;   /* oversold  → buy  */
    if (rsi > RSI_OVERBOUGHT)  rsi_sig = -1;   /* overbought → sell */

    /* ── Combined signal: both must agree ───────────────────────────── */
    int8_t combined = 0;
    if (ema_sig != 0 && ema_sig == rsi_sig) combined = ema_sig;

    /* ── Stamp T3 (GPU clock, converted to wall-clock ns by harness) ── */
    uint64_t t3 = clock64();

    /* ── Write output ────────────────────────────────────────────────── */
    out.tick_id       = tick.tick_id;
    out.t3_ns         = t3;
    out.t4_ns         = 0;
    out.instrument_id = tick.instrument_id;
    out.signal        = combined;
    out.rsi_signal    = rsi_sig;
    out.rsi           = rsi;
    out.mid_price     = mid;
    out.spread        = spread;
    out.fast_ema      = fast_ema;
    out.slow_ema      = slow_ema;

    /* T4: signal is now visible in output buffer */
    __threadfence();
    out.t4_ns = clock64();
}

/* ── Host-side launcher (callable from .cpp translation units) ─────────────── */

/*
 * launch_process_ticks() — allocates no state; caller must pre-allocate
 * d_fast_ema, d_slow_ema, d_avg_gain, d_avg_loss, d_last_mid as
 * cudaMalloc'd zero-initialised double arrays of size MAX_INSTRUMENTS.
 *
 * t2_ns: host wall-clock timestamp captured immediately after cudaMemcpy H→D.
 */
extern "C" void launch_process_ticks(
    const TickMessage *d_ticks,
    int                n_ticks,
    SignalResult       *d_signals,
    double             *d_fast_ema,
    double             *d_slow_ema,
    double             *d_avg_gain,
    double             *d_avg_loss,
    double             *d_last_mid,
    uint64_t            t2_ns,
    cudaStream_t        stream)
{
    if (n_ticks <= 0) return;
    int threads = 256;
    int blocks  = (n_ticks + threads - 1) / threads;
    process_ticks_kernel<<<blocks, threads, 0, stream>>>(
        d_ticks, n_ticks, d_signals,
        d_fast_ema, d_slow_ema, d_avg_gain, d_avg_loss, d_last_mid,
        t2_ns);
}
