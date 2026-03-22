#pragma once

/*
 * benchmark.h — Latency and throughput measurement infrastructure.
 *
 * Ported from development-david-local/common/benchmark.h and adapted for the
 * five-tier pipeline.  All three CPU tiers (T1-T3) and the DOCA receiver (T4/T5)
 * use these structs so benchmark results are directly comparable.
 *
 * Classes:
 *   LatencyStats    — records per-batch latency samples, computes percentiles
 *   ThroughputMeter — tracks events/sec over the measurement window
 *   BenchmarkResult — CSV-serialisable summary of one complete run
 */

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

/* ── Timer ─────────────────────────────────────────────────────────────────── */

static inline uint64_t bench_now_ns()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ── Latency histogram ─────────────────────────────────────────────────────── */

struct LatencyStats {
    std::vector<double> samples_us;   /* one entry per batch/tick */

    void record(uint64_t start_ns, uint64_t end_ns)
    {
        samples_us.push_back((double)(end_ns - start_ns) / 1000.0);
    }

    void record_us(double us) { samples_us.push_back(us); }

    void compute(double *p50, double *p95, double *p99, double *p999,
                 double *mean_out, double *stddev_out) const
    {
        if (samples_us.empty()) {
            *p50 = *p95 = *p99 = *p999 = *mean_out = *stddev_out = 0.0;
            return;
        }

        std::vector<double> s = samples_us;
        std::sort(s.begin(), s.end());
        int n = (int)s.size();

        auto pct = [&](double p) -> double {
            int idx = (int)(p * (n - 1));
            return s[std::max(0, std::min(idx, n - 1))];
        };

        *p50  = pct(0.50);
        *p95  = pct(0.95);
        *p99  = pct(0.99);
        *p999 = pct(0.999);

        double sum = 0;
        for (double v : s) sum += v;
        *mean_out = sum / n;

        double var = 0;
        for (double v : s) var += (v - *mean_out) * (v - *mean_out);
        *stddev_out = std::sqrt(var / n);
    }

    void print(const char *label) const
    {
        double p50, p95, p99, p999, mean, sd;
        compute(&p50, &p95, &p99, &p999, &mean, &sd);
        printf("  %-28s  p50=%7.1fµs  p95=%7.1fµs  p99=%7.1fµs"
               "  p99.9=%7.1fµs  mean=%7.1fµs  σ=%5.1fµs  n=%zu\n",
               label, p50, p95, p99, p999, mean, sd, samples_us.size());
    }

    size_t count() const { return samples_us.size(); }
};

/* ── Throughput meter ──────────────────────────────────────────────────────── */

struct ThroughputMeter {
    uint64_t total_events  = 0;
    uint64_t total_batches = 0;
    uint64_t start_ns      = 0;

    void start() { start_ns = bench_now_ns(); }

    void add_batch(int n)
    {
        if (start_ns == 0) start();
        total_events  += (uint64_t)n;
        total_batches += 1;
    }

    double events_per_sec() const
    {
        if (start_ns == 0) return 0.0;
        double elapsed_s = (double)(bench_now_ns() - start_ns) / 1e9;
        return elapsed_s > 0 ? (double)total_events / elapsed_s : 0.0;
    }

    double elapsed_sec() const
    {
        return start_ns ? (double)(bench_now_ns() - start_ns) / 1e9 : 0.0;
    }

    void print(const char *label) const
    {
        printf("  %-28s  %.0f events/sec  (%llu events, %llu batches, %.2fs)\n",
               label, events_per_sec(),
               (unsigned long long)total_events,
               (unsigned long long)total_batches,
               elapsed_sec());
    }
};

/* ── Run result (CSV row) ──────────────────────────────────────────────────── */

struct BenchmarkResult {
    int         tier;
    int         run_id;
    uint64_t    rate_hz;
    int         repetition;

    uint64_t    n_ticks;
    double      drop_rate;

    /* Latency percentiles (µs) */
    double      e2e_p50, e2e_p95, e2e_p99, e2e_mean;
    double      ingest_p50, ingest_p95, ingest_p99, ingest_mean;
    double      compute_p50, compute_p95, compute_p99, compute_mean;

    double      throughput_per_sec;

    /* Populate from LatencyStats objects captured during a run. */
    void fill(int _tier, int _run, uint64_t _rate, int _rep,
              const LatencyStats &e2e,
              const LatencyStats &ingest,
              const LatencyStats &compute,
              const ThroughputMeter &tp,
              double _drop_rate = 0.0)
    {
        tier = _tier; run_id = _run; rate_hz = _rate; repetition = _rep;
        drop_rate = _drop_rate;
        n_ticks   = (uint64_t)e2e.count();

        double p999_unused, sd_unused;
        e2e.compute(&e2e_p50, &e2e_p95, &e2e_p99, &p999_unused, &e2e_mean, &sd_unused);
        ingest.compute(&ingest_p50, &ingest_p95, &ingest_p99,
                       &p999_unused, &ingest_mean, &sd_unused);
        compute.compute(&compute_p50, &compute_p95, &compute_p99,
                        &p999_unused, &compute_mean, &sd_unused);
        throughput_per_sec = tp.events_per_sec();
    }

    static void write_csv_header(FILE *f)
    {
        fprintf(f, "run_id,tier,rate_hz,repetition,n_ticks,drop_rate,"
                   "e2e_p50_us,e2e_p95_us,e2e_p99_us,e2e_mean_us,"
                   "ingest_p50_us,ingest_p95_us,ingest_p99_us,ingest_mean_us,"
                   "compute_p50_us,compute_p95_us,compute_p99_us,compute_mean_us,"
                   "throughput_per_sec\n");
    }

    void write_csv_row(FILE *f) const
    {
        fprintf(f, "%d,%d,%llu,%d,%llu,%.4f,"
                   "%.2f,%.2f,%.2f,%.2f,"
                   "%.2f,%.2f,%.2f,%.2f,"
                   "%.2f,%.2f,%.2f,%.2f,"
                   "%.1f\n",
                run_id, tier, (unsigned long long)rate_hz, repetition,
                (unsigned long long)n_ticks, drop_rate,
                e2e_p50, e2e_p95, e2e_p99, e2e_mean,
                ingest_p50, ingest_p95, ingest_p99, ingest_mean,
                compute_p50, compute_p95, compute_p99, compute_mean,
                throughput_per_sec);
    }

    void print_summary() const
    {
        printf("  T%d  rate=%-7llu  n=%-8llu  "
               "e2e p50=%.1fµs p99=%.1fµs  "
               "ingest p50=%.1fµs  compute p50=%.1fµs  "
               "%.0f ticks/s\n",
               tier, (unsigned long long)rate_hz, (unsigned long long)n_ticks,
               e2e_p50, e2e_p99, ingest_p50, compute_p50,
               throughput_per_sec);
    }
};
