#pragma once

#include <cstdint>
#include <cstring>

/*
 * TickMessage — 48-byte packed struct shared across ALL pipeline tiers.
 * Sent as UDP payload over multicast 239.0.0.1:5005.
 *
 * Layout (packed, no implicit padding):
 *   [0..7]   timestamp_ns    uint64_t  — wall-clock ns at sendto()  (T1)
 *   [8..11]  tick_id         uint32_t  — monotonic counter per session
 *   [12..13] instrument_id   uint16_t  — hash of symbol string
 *   [14]     source          uint8_t   — 0 = replay, 1 = live
 *   [15]     _pad            uint8_t   — reserved / zero
 *   [16..23] bid             double
 *   [24..31] ask             double
 *   [32..39] last_price      double
 *   [40..47] volume          double
 */
#pragma pack(push, 1)
struct TickMessage {
    uint64_t timestamp_ns;
    uint32_t tick_id;
    uint16_t instrument_id;
    uint8_t  source;
    uint8_t  _pad;
    double   bid;
    double   ask;
    double   last_price;
    double   volume;
};
#pragma pack(pop)

static_assert(sizeof(TickMessage) == 48, "TickMessage must be exactly 48 bytes");

#define TICK_MCAST_ADDR  "239.0.0.1"
#define TICK_MCAST_PORT  5005

#define TICK_SOURCE_REPLAY 0
#define TICK_SOURCE_LIVE   1

/* Maximum instruments tracked in the GPU EMA table. */
#define MAX_INSTRUMENTS 256

/*
 * symbol_to_id() — djb2-derived hash of an ASCII symbol string,
 * folded into [0, MAX_INSTRUMENTS).  Pure header-only, usable from
 * both C++ host code and CUDA device code (__host__ __device__).
 */
#if defined(__CUDACC__)
__host__ __device__
#endif
static inline uint16_t symbol_to_id(const char *sym)
{
    uint32_t h = 5381u;
    while (*sym)
        h = ((h << 5u) + h) ^ (uint8_t)(*sym++);
    return (uint16_t)(h % MAX_INSTRUMENTS);
}

/* Convenience: current wall-clock time in nanoseconds (POSIX CLOCK_REALTIME). */
#if !defined(__CUDACC__)
#include <time.h>
static inline uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
#endif
