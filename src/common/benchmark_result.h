#pragma once

#include <cstdint>

/*
 * BenchmarkResult — sent by EVERY receiver tier to the benchmark harness
 * on UDP port 5010 after each tick is fully processed.
 *
 * All five tiers (T1–T5) send this same struct so the harness can collect
 * results identically regardless of tier.
 *
 * Layout (56 bytes packed):
 *   [0..7]   tick_id   — matches TickMessage::tick_id
 *   [8..15]  t1_ns     — timestamp at sendto() (copied from TickMessage)
 *   [16..23] t2_ns     — timestamp when tick arrived in GPU memory
 *   [24..31] t3_ns     — timestamp when CUDA kernel finished (per-tick)
 *   [32..39] t4_ns     — timestamp when SignalResult written to output
 *   [40..47] compute_ns — per-tick compute duration in nanoseconds
 *   [48]     tier      — 1..5
 *   [49]     dropped   — 1 if this result represents a dropped packet
 *   [50..55] _pad      — zero
 */
#pragma pack(push, 1)
struct BenchmarkResult {
    uint64_t tick_id;
    uint64_t t1_ns;
    uint64_t t2_ns;
    uint64_t t3_ns;
    uint64_t t4_ns;
    uint64_t compute_ns;
    uint8_t  tier;
    uint8_t  dropped;
    uint8_t  _pad[6];
};
#pragma pack(pop)

static_assert(sizeof(BenchmarkResult) == 56, "BenchmarkResult must be 56 bytes");

#define BENCH_RESULT_PORT 5010
