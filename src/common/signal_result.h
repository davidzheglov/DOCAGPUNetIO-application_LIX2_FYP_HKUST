#pragma once

#include <cstdint>

/*
 * SignalResult — output written by the CUDA kernel for each processed tick.
 * Forwarded by receivers to the fill simulator on UDP port 5006.
 *
 * Layout (64 bytes packed):
 *   [0..7]   tick_id        — matches TickMessage::tick_id
 *   [8..15]  t3_ns          — kernel completion timestamp (GPU clock64, converted)
 *   [16..23] t4_ns          — signal write timestamp
 *   [24..25] instrument_id
 *   [26]     signal         — combined signal: +1 buy, -1 sell, 0 hold
 *   [27]     rsi_signal     — RSI component: +1 oversold, -1 overbought, 0 neutral
 *   [28..31] rsi            — RSI value [0..100] as float
 *   [32..39] mid_price
 *   [40..47] spread
 *   [48..55] fast_ema       — EMA with alpha_fast (responds quickly to price)
 *   [56..63] slow_ema       — EMA with alpha_slow (tracks longer-term trend)
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
};
#pragma pack(pop)

static_assert(sizeof(SignalResult) == 64, "SignalResult must be exactly 64 bytes");

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
