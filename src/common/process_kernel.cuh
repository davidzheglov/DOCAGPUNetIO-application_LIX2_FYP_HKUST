#pragma once

/*
 * process_kernel.cuh — CUDA processing kernel shared by T1, T2, T3.
 *
 * T4/T5 (gpu_receiver.cu) embed equivalent logic inside the DOCA receive
 * kernel rather than calling this separately.
 *
 * Kernel signature:
 *   process_ticks_kernel(ticks, n, signals, ema_table, t2_ns, alpha, threshold)
 *
 * One thread per tick.  Grid: ceil(n/256) blocks of 256 threads.
 */

#include <cuda_runtime.h>
#include "tick_message.h"
#include "signal_result.h"

/*
 * Atomic EMA update using CAS loop (works for double on sm_60+).
 *
 * new_ema = alpha * price + (1 - alpha) * old_ema
 */
__device__ static void ema_update(double *slot, double price, double alpha)
{
    unsigned long long *addr = reinterpret_cast<unsigned long long *>(slot);
    unsigned long long expected, desired;
    do {
        expected = *addr;
        double old_ema = __longlong_as_double((long long)expected);
        double new_ema  = alpha * price + (1.0 - alpha) * old_ema;
        desired  = (unsigned long long)__double_as_longlong(new_ema);
    } while (atomicCAS(addr, expected, desired) != expected);
}

__global__ void process_ticks_kernel(
    const TickMessage * __restrict__ ticks,
    int                              n_ticks,
    SignalResult       * __restrict__ signals,
    double             * __restrict__ ema_table,   /* [MAX_INSTRUMENTS] */
    uint64_t                         t2_ns,        /* batch arrival time */
    double                           alpha,
    double                           threshold)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n_ticks) return;

    const TickMessage &tick = ticks[idx];
    SignalResult      &out  = signals[idx];

    /* --- compute mid-price and spread --- */
    double mid    = (tick.bid + tick.ask) * 0.5;
    double spread =  tick.ask - tick.bid;

    /* --- update per-instrument EMA --- */
    int   inst_idx = tick.instrument_id % MAX_INSTRUMENTS;
    ema_update(&ema_table[inst_idx], mid, alpha);
    double ema = ema_table[inst_idx];   /* read back (approximate) */

    /* --- mean-reversion signal --- */
    int8_t sig = 0;
    if (mid < ema - threshold * ema) sig = +1;   /* price below mean → buy */
    if (mid > ema + threshold * ema) sig = -1;   /* price above mean → sell */

    /* --- stamp T3 --- */
    uint64_t t3 = clock64();   /* GPU clock cycles — converted by harness */

    /* --- write output --- */
    out.tick_id       = tick.tick_id;
    out.t3_ns         = t3;
    out.t4_ns         = 0;          /* filled below after write is "done" */
    out.instrument_id = tick.instrument_id;
    out.signal        = sig;
    out.mid_price     = mid;
    out.spread        = spread;
    out.ema           = ema;

    /* T4: signal is now visible in output buffer */
    __threadfence();
    out.t4_ns = clock64();
}

/*
 * launch_process_ticks() — host-side wrapper callable from plain .cpp
 * translation units (extern "C" linkage).
 *
 * t2_ns: host timestamp (ns) captured right after cudaMemcpy H→D.
 * gpu_freq_hz: used by the harness to convert clock64() ticks to ns.
 */
extern "C" void launch_process_ticks(
    const TickMessage *d_ticks,
    int                n_ticks,
    SignalResult       *d_signals,
    double             *d_ema_table,
    uint64_t            t2_ns,
    double              alpha,
    double              threshold,
    cudaStream_t        stream)
{
    if (n_ticks <= 0) return;
    int threads = 256;
    int blocks  = (n_ticks + threads - 1) / threads;
    process_ticks_kernel<<<blocks, threads, 0, stream>>>(
        d_ticks, n_ticks, d_signals, d_ema_table, t2_ns, alpha, threshold);
}
