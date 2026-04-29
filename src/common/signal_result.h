#pragma once

#include <cstdint>

/*
 * SignalResult — output written by the CUDA kernel for each processed tick.
 * Forwarded by receivers to the fill simulator on UDP port 5006.
 *
 * Layout (96 bytes packed):
 *   [ 0.. 7] tick_id        — matches TickMessage::tick_id
 *   [ 8..15] t3_ns          — kernel completion timestamp
 *   [16..23] t4_ns          — signal write timestamp
 *   [24..25] instrument_id
 *   [26]     signal         — combined: +1 buy, -1 sell, 0 hold
 *   [27]     rsi_signal     — RSI: +1 oversold, -1 overbought, 0 neutral
 *   [28..31] rsi            — RSI value [0..100] as float
 *   [32..39] mid_price
 *   [40..47] spread
 *   [48..55] fast_ema       — EMA with alpha_fast
 *   [56..63] slow_ema       — EMA with alpha_slow
 *   [64..71] var_95         — 1-tick-ahead 95% Value-at-Risk (price level)
 *   [72..79] cvar_95        — 1-tick-ahead 95% Conditional VaR (expected shortfall)
 *   [80..87] mc_mean        — Monte Carlo mean of forecast price
 *   [88..95] mc_std         — Monte Carlo standard deviation of forecast price
 *
 * Risk fields are produced by an N_PATHS × N_STEPS Monte Carlo simulation in
 * the GPU kernel — see process_kernel.cuh::compute_risk_mc().
 */
#pragma pack(push, 1)
struct SignalResult {
    uint64_t tick_id;
    uint64_t t3_ns;
    uint64_t t4_ns;
    uint16_t instrument_id;
    int8_t   signal;        /* combined: +1 = buy, -1 = sell, 0 = hold */
    int8_t   rsi_signal;    /* RSI component: +1 oversold, -1 overbought */
    float    rsi;           /* RSI value [0..100] */
    double   mid_price;
    double   spread;
    double   fast_ema;      /* fast EMA (alpha ≈ 0.05) */
    double   slow_ema;      /* slow EMA (alpha ≈ 0.01) */
    /* ── Per-tick Monte Carlo risk forecast (new in this revision) ─── */
    double   var_95;        /* 95% Value-at-Risk: price below which 5% of paths fall */
    double   cvar_95;       /* 95% Conditional VaR (expected shortfall) */
    double   mc_mean;       /* mean of the simulated final-price distribution */
    double   mc_std;        /* stddev of the simulated final-price distribution */
};
#pragma pack(pop)

static_assert(sizeof(SignalResult) == 96, "SignalResult must be exactly 96 bytes");

#define SIGNAL_PORT        5006

/* EMA smoothing factors */
#define EMA_ALPHA_FAST     0.05     /* fast EMA — reacts quickly to price moves   */
#define EMA_ALPHA_SLOW     0.01     /* slow EMA — tracks longer-term trend        */

/* RSI parameters */
#define RSI_ALPHA          (2.0 / 15.0)   /* equivalent to 14-period Wilder EMA   */
#define RSI_OVERBOUGHT     70.0
#define RSI_OVERSOLD       30.0

/* EMA crossover threshold (fraction of slow EMA) */
#define EMA_CROSS_THRESH   0.0003   /* 3 bps — fast must clear slow by this much  */

/* ── Monte Carlo risk forecast parameters ──────────────────────────────────
 * Tuned so a single thread can finish all paths within the per-tick budget
 * even on T4 (one thread = one packet). Total ops/tick ≈ N_PATHS × N_STEPS
 * × ~12 ≈ 393K. At 1.5 GHz that's ~260 µs sequential per thread — but a warp
 * runs 32 threads in parallel, so ~260 µs / 32 ≈ 8 µs amortised per packet
 * for T4, and similar per-batch on T1/T2/T3 with 256 threads.
 *
 * Tunable: keep N_PATHS as a power of two to make the inner loop predictable. */
#define MC_N_PATHS         1024
#define MC_N_STEPS         32
#define MC_DT              (1.0 / 252.0)   /* 1 trading day per step (annualised) */
#define MC_BASE_VOL        0.20            /* 20% annualised, scaled by recent EMA dev */
