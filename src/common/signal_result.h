#pragma once

#include <cstdint>

/*
 * SignalResult — output written by the CUDA kernel for each processed tick.
 * Forwarded by receivers to the fill simulator on UDP port 5006.
 *
 * Layout (56 bytes packed):
 *   [0..7]   tick_id        — matches TickMessage::tick_id
 *   [8..15]  t3_ns          — kernel completion timestamp
 *   [16..23] t4_ns          — signal write timestamp
 *   [24..25] instrument_id
 *   [26]     signal         — +1 buy, -1 sell, 0 hold
 *   [27..31] _pad
 *   [32..39] mid_price
 *   [40..47] spread
 *   [48..55] ema            — current EMA for this instrument
 */
#pragma pack(push, 1)
struct SignalResult {
    uint64_t tick_id;
    uint64_t t3_ns;
    uint64_t t4_ns;
    uint16_t instrument_id;
    int8_t   signal;        /* +1 = buy, -1 = sell, 0 = hold */
    uint8_t  _pad[5];
    double   mid_price;
    double   spread;
    double   ema;
};
#pragma pack(pop)

static_assert(sizeof(SignalResult) == 56, "SignalResult must be 56 bytes");

#define SIGNAL_PORT      5006
#define EMA_ALPHA        0.01   /* EMA smoothing factor */
#define SIGNAL_THRESHOLD 0.001  /* 10 bps mean-reversion threshold */
