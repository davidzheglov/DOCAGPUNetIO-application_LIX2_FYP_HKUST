#!/usr/bin/env python3
"""
benchmark_cpu.py — Single-run benchmark driver for local-host T1 (cpu_receiver).

Produces bench.csv + summary.json in the SAME format as benchmark.py (T4/T5),
so the same analyze.py and compare_t1_t4.py scripts work on both.

Key difference from T4:
    sender and receiver share the same wall clock — ingest (T2-T1) and
    e2e (T4-T1) are FULLY TRUSTWORTHY.  clock_cal.applied = False.

Compute latency:
    All ticks in a batch share the same t2/t3 (one kernel launch per batch).
    Raw (t3-t2) would give batch time ~2270 μs for batch=256.
    We divide by the actual number of ticks in each batch to get per-tick cost.

Usage:
    python3 scripts/benchmark_cpu.py --rate 50000
    python3 scripts/benchmark_cpu.py --rate 100000 --repetition 2 --duration 30
"""

import argparse
import csv
import json
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from statistics import mean

BENCH_FMT  = "=QQQQQBBxxxxxx"
BENCH_SIZE = 48
BENCH_PORT = 5010

REPO_ROOT = Path(__file__).resolve().parent.parent


# ── Helpers ───────────────────────────────────────────────────────────────────

def pct(values, p):
    """values must be pre-sorted.  p in [0, 100]."""
    if not values:
        return float("nan")
    k  = (len(values) - 1) * (p / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(values) - 1)
    return values[lo] * (1 - (k - lo)) + values[hi] * (k - lo)


def fmt_us(x):
    return f"{x:8.2f}" if x == x else "     NaN"


def stats(lst):
    if not lst:
        return {"n": 0, "mean": float("nan"),
                "p50": float("nan"), "p95": float("nan"),
                "p99": float("nan"), "p999": float("nan"),
                "max": float("nan")}
    return {
        "n":    len(lst),
        "mean": mean(lst),
        "p50":  pct(lst, 50),
        "p95":  pct(lst, 95),
        "p99":  pct(lst, 99),
        "p999": pct(lst, 99.9),
        "max":  lst[-1],
    }


# ── Runner ────────────────────────────────────────────────────────────────────

class BenchRunnerCPU:
    def __init__(self, args):
        self.args = args

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.run_name    = f"T1_{args.rate}hz_rep{args.repetition}_{ts}"
        self.run_dir     = REPO_ROOT / "results" / "single" / self.run_name
        self.run_dir.mkdir(parents=True, exist_ok=True)

        self.bench_csv    = self.run_dir / "bench.csv"
        self.summary_json = self.run_dir / "summary.json"
        self.receiver_log = self.run_dir / "receiver.log"
        self.sender_log   = self.run_dir / "sender.log"

        self.rx_proc      = None
        self.sender_proc  = None
        self.rx_log_fh    = None
        self.sender_log_fh = None

    # ── Binary discovery ─────────────────────────────────────────────────────

    def resolve_receiver_bin(self):
        a = self.args
        if a.receiver_bin != "auto":
            p = Path(a.receiver_bin)
            if not p.is_absolute():
                p = REPO_ROOT / p
            if p.exists():
                return p
            sys.exit(f"[benchmark_cpu] receiver binary not found: {p}")
        for p in [REPO_ROOT / "bin" / "cpu_receiver",
                  REPO_ROOT / "build" / "bin" / "cpu_receiver"]:
            if p.exists():
                return p
        sys.exit("[benchmark_cpu] cpu_receiver not found — run `make t1`")

    # ── Start ─────────────────────────────────────────────────────────────────

    def start_receiver(self):
        a   = self.args
        bin_ = self.resolve_receiver_bin()
        rx_cmd = [
            str(bin_),
            "--mcast",   a.mcast_addr,
            "--port",    str(a.mcast_port),
            "--batch",   str(a.batch),
            "--tier",    "1",
            "--harness", a.harness_ip,
            "--fillsim", a.fillsim_ip,
        ]

        print(f"[benchmark_cpu] starting cpu_receiver: {' '.join(rx_cmd)}")
        self.rx_log_fh = open(self.receiver_log, "w")
        self.rx_proc   = subprocess.Popen(
            rx_cmd,
            stdout=self.rx_log_fh,
            stderr=subprocess.STDOUT,
            cwd=str(REPO_ROOT),
        )

        # Wait for ready banner
        deadline = time.time() + a.receiver_init_sec
        while time.time() < deadline:
            if self.rx_proc.poll() is not None:
                self.rx_log_fh.close()
                err = self.receiver_log.read_text(errors="replace").strip()
                print(f"[benchmark_cpu] ERROR: cpu_receiver exited rc={self.rx_proc.returncode}")
                print("--- receiver.log ---\n" + err + "\n--------------------")
                sys.exit("[benchmark_cpu] cpu_receiver failed to start")
            time.sleep(0.2)
            try:
                log = self.receiver_log.read_text(errors="replace")
            except OSError:
                log = ""
            if "[T1 cpu_receiver] ready" in log:
                print("[benchmark_cpu] cpu_receiver ready")
                return
        print("[benchmark_cpu] WARN: ready banner not seen — continuing anyway")

    def start_sender(self):
        a     = self.args
        count = a.rate * (a.warmup + a.duration + a.sender_tail_sec)
        send_cmd = [
            "python3", str(REPO_ROOT / "scripts" / "send_ticks.py"),
            "--mode",  "generate",
            "--rate",  str(a.rate),
            "--iface", a.sender_iface,
            "--count", str(count),
        ]

        print(f"[benchmark_cpu] starting sender: {' '.join(send_cmd)}")
        self.sender_log_fh = open(self.sender_log, "w")
        self.sender_proc   = subprocess.Popen(
            send_cmd,
            stdout=self.sender_log_fh,
            stderr=subprocess.STDOUT,
            cwd=str(REPO_ROOT),
        )

        time.sleep(0.5)
        if self.sender_proc.poll() is not None:
            self.sender_log_fh.close()
            err = self.sender_log.read_text(errors="replace").strip()
            print(f"[benchmark_cpu] ERROR: sender exited rc={self.sender_proc.returncode}")
            print("--- sender.log ---\n" + err + "\n------------------")
            sys.exit("[benchmark_cpu] sender failed to start")

    # ── Collect ───────────────────────────────────────────────────────────────

    def collect(self):
        import socket, struct

        a       = self.args
        sock    = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((a.host_bind, BENCH_PORT))
        sock.settimeout(0.5)

        results    = []
        t_start    = time.time()
        deadline   = t_start + a.warmup + a.duration + a.collector_tail_sec
        last_print = t_start

        print(f"[benchmark_cpu] collecting on {a.host_bind}:{BENCH_PORT} for "
              f"{a.warmup}s warmup + {a.duration}s measure (+{a.collector_tail_sec}s tail)")

        while time.time() < deadline:
            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                data = None

            now = time.time()
            if data and len(data) >= BENCH_SIZE:
                tick_id, t1, t2, t3, t4, tier, dropped = struct.unpack(
                    BENCH_FMT, data[:BENCH_SIZE])
                results.append({
                    "recv_ns": time.time_ns(),
                    "tick_id": tick_id,
                    "t1_ns": t1, "t2_ns": t2, "t3_ns": t3, "t4_ns": t4,
                    "tier": tier, "dropped": dropped,
                })

            if now - last_print >= 2.0:
                n = len(results)
                elapsed = now - t_start
                print(f"  [{elapsed:5.1f}s] received={n:>8,}  "
                      f"({n / max(elapsed, 0.001):>8,.0f}/s)", flush=True)
                last_print = now

            if self.rx_proc and self.rx_proc.poll() is not None:
                print("[benchmark_cpu] cpu_receiver exited during collection")
                break

        sock.close()

        with open(self.bench_csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=[
                "recv_ns","tick_id","t1_ns","t2_ns","t3_ns","t4_ns","tier","dropped"])
            w.writeheader()
            w.writerows(results)
        print(f"[benchmark_cpu] wrote {len(results):,} rows → {self.bench_csv}")
        return results, t_start

    # ── Analyze ───────────────────────────────────────────────────────────────

    def analyze(self, results, _collect_start):
        a = self.args
        if not results:
            print("[benchmark_cpu] no rows — nothing to analyze")
            return None

        # ── Measurement window (anchor on first t1_ns, same as benchmark.py) ─
        first_t1  = results[0]["t1_ns"]
        win_start = first_t1 + a.warmup              * 1_000_000_000
        win_end   = first_t1 + (a.warmup + a.duration) * 1_000_000_000
        window = [r for r in results if win_start <= r["t1_ns"] < win_end]
        if not window:
            print("[benchmark_cpu] WARN: no rows inside measurement window")
            return None
        window.sort(key=lambda r: r["tick_id"])

        # ── Throughput ───────────────────────────────────────────────────────
        tid_first = window[0]["tick_id"]
        tid_last  = window[-1]["tick_id"]
        expected  = tid_last - tid_first + 1
        received  = len(window)
        drop_rate = 1.0 - received / expected if expected > 0 else 0.0

        # ── Per-stage latencies ──────────────────────────────────────────────
        def lat(rows, a_ns, b_ns):
            out = []
            for r in rows:
                ta, tb = r[a_ns], r[b_ns]
                if ta > 0 and tb > ta:
                    out.append((tb - ta) / 1000.0)
            out.sort()
            return out

        e2e    = lat(window, "t1_ns", "t4_ns")
        ingest = lat(window, "t1_ns", "t2_ns")
        egress = lat(window, "t3_ns", "t4_ns")

        # ── Per-TICK compute latency ─────────────────────────────────────────
        # In cpu_receiver every tick in a batch gets the same t2 and t3 (one
        # kernel launch per batch).  Raw (t3-t2) is the BATCH time (~2270 μs
        # at batch=256).  We divide by the actual tick count in each batch to
        # get per-tick cost (~8-9 μs), which is the fair comparison to T4's
        # per-tick persistent-kernel time.
        batch_buckets: Counter = Counter()
        for r in window:
            t2, t3 = r["t2_ns"], r["t3_ns"]
            if t2 > 0 and t3 > t2:
                batch_buckets[(t2, t3)] += 1

        compute_per_tick  = []   # (t3-t2) / n_ticks_in_batch  — reported as "compute"
        compute_per_batch = []   # raw (t3-t2)                  — kept for reference

        for (t2, t3), n in batch_buckets.items():
            dur_us = (t3 - t2) / 1000.0
            compute_per_batch.append(dur_us)
            compute_per_tick.append(dur_us / max(n, 1))

        compute_per_tick.sort()
        compute_per_batch.sort()

        # ── Ingest jitter (clock-independent, identical to benchmark.py) ─────
        expected_ns   = 1_000_000_000.0 / a.rate if a.rate > 0 else 0.0
        jitter_signed = []
        prev = window[0]
        for cur in window[1:]:
            if cur["tick_id"] == prev["tick_id"] + 1:
                d = cur["t2_ns"] - prev["t2_ns"]
                jitter_signed.append((d - expected_ns) / 1000.0)
            prev = cur
        jitter_signed.sort()
        jitter_abs = sorted(abs(x) for x in jitter_signed)

        # ── Build summary ────────────────────────────────────────────────────
        summary = {
            "run": {
                "run_name":     self.run_name,
                "timestamp":    datetime.now().isoformat(),
                "tier":         1,
                "rate_hz":      a.rate,
                "repetition":   a.repetition,
                "warmup_sec":   a.warmup,
                "duration_sec": a.duration,
                "mode":         "local_host",
                "receiver":     "cpu_receiver",
                "batch_size":   a.batch,
                "sender_iface": a.sender_iface,
                "nsys":         False,
            },
            # T1 sender and receiver share the same wall clock — no correction.
            "clock_cal": {
                "applied":       False,
                "offset_ns":     0,
                "offset_slope":  0.0,
                "offset_source": "none (T1 same-host clock)",
                "ntp_offset_ns": 0,
                "oneway_ns_min": 0,
                "cal_ip":        None,
            },
            "throughput": {
                "expected":      expected,
                "received":      received,
                "drop_rate":     drop_rate,
                "achieved_hz":   received / a.duration if a.duration else 0.0,
                "target_hz":     a.rate,
                "tick_id_first": tid_first,
                "tick_id_last":  tid_last,
            },
            "latency_us": {
                "e2e":           stats(e2e),
                "ingest":        stats(ingest),
                # "compute" = per-tick (batch time / ticks in batch).
                # Comparable to T4's per-tick persistent-kernel time.
                "compute":       stats(compute_per_tick),
                # "compute_batch" = raw batch kernel time (all 256 ticks share it).
                # Useful to verify: compute * batch_size ≈ compute_batch.
                "compute_batch": stats(compute_per_batch),
                "egress":        stats(egress),
            },
            "ingest_jitter_us": {
                "n":                    len(jitter_signed),
                "expected_interval_us": expected_ns / 1000.0 if expected_ns else None,
                "signed_p01":   pct(jitter_signed, 1),
                "signed_p50":   pct(jitter_signed, 50),
                "signed_p99":   pct(jitter_signed, 99),
                "abs_p50":      pct(jitter_abs, 50),
                "abs_p95":      pct(jitter_abs, 95),
                "abs_p99":      pct(jitter_abs, 99),
                "abs_p999":     pct(jitter_abs, 99.9),
                "abs_max":      jitter_abs[-1] if jitter_abs else float("nan"),
            },
        }

        with open(self.summary_json, "w") as f:
            json.dump(summary, f, indent=2)

        self.print_summary(summary)
        return summary

    # ── Print — matches benchmark.py format ───────────────────────────────────

    def print_summary(self, s):
        r = s["run"]
        t = s["throughput"]
        L = s["latency_us"]

        print()
        print("=" * 72)
        print(f"  {r['run_name']}")
        print("=" * 72)
        print(f"  tier={r['tier']}  target={r['rate_hz']:,} Hz  rep={r['repetition']}  "
              f"batch={r['batch_size']}  nsys=off")
        print(f"  window: {r['warmup_sec']}s warmup + {r['duration_sec']}s measure")
        print(f"  clock offset: NOT APPLIED — T1 same-host clock, all latencies reliable")
        print()
        print(f"  Throughput:")
        print(f"    expected   : {t['expected']:>10,}")
        print(f"    received   : {t['received']:>10,}")
        print(f"    drop rate  : {t['drop_rate']*100:>10.3f} %")
        print(f"    achieved   : {t['achieved_hz']:>10,.0f} Hz  (target {t['target_hz']:,})")
        print()
        print(f"  Latency (μs):          n       mean      p50      p95      p99     p99.9     max")
        rows = [
            ("  ingest(t2-t1)",  "ingest",        "  [UDP loopback + cudaMemcpy H→D, same-host clock]"),
            ("  compute/tick",   "compute",        f"  [per-tick: batch÷{r['batch_size']} — compare to T4]"),
            ("  compute/batch",  "compute_batch",  "  [raw batch kernel time, all ticks share t2/t3]"),
            ("  egress (t4-t3)", "egress",         "  [cudaMemcpy D→H + sendto]"),
            ("  e2e    (t4-t1)", "e2e",            "  [fully trustworthy, same-host clock]"),
        ]
        for name, key, note in rows:
            x = L[key]
            print(f"  {name:14s}  {x['n']:>7,}  {fmt_us(x['mean'])}  "
                  f"{fmt_us(x['p50'])}  {fmt_us(x['p95'])}  "
                  f"{fmt_us(x['p99'])}  {fmt_us(x['p999'])}  {fmt_us(x['max'])}"
                  f"{note}")

        j = s.get("ingest_jitter_us") or {}
        if j.get("n"):
            print()
            print(f"  Ingest jitter (host-only, clock-independent):")
            print(f"    expected interval : {j['expected_interval_us']:.2f} μs")
            print(f"    |p50|             : {fmt_us(j['abs_p50'])}")
            print(f"    |p95|             : {fmt_us(j['abs_p95'])}")
            print(f"    |p99|             : {fmt_us(j['abs_p99'])}")
            print(f"    signed p01..p99   : {fmt_us(j['signed_p01'])} .. {fmt_us(j['signed_p99'])}")

        print()
        print(f"  Files:")
        print(f"    {self.bench_csv}")
        print(f"    {self.summary_json}")
        print(f"    {self.receiver_log}")
        print(f"    {self.sender_log}")
        print("=" * 72)

    # ── Cleanup ───────────────────────────────────────────────────────────────

    def cleanup(self):
        for proc in (self.sender_proc, self.rx_proc):
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
        subprocess.run(["pkill", "-f", "cpu_receiver"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-f", "send_ticks.py"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for fh in (self.rx_log_fh, self.sender_log_fh):
            if fh:
                fh.close()

    # ── Orchestrate ───────────────────────────────────────────────────────────

    def run(self):
        print(f"[benchmark_cpu] run → {self.run_dir}")
        results = []
        t_start = time.time()
        try:
            self.start_receiver()
            self.start_sender()
            results, t_start = self.collect()
        finally:
            self.cleanup()
        return self.analyze(results, t_start)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="T1 cpu_receiver benchmark — same output format as benchmark.py.")
    p.add_argument("--rate", type=int, required=True)
    p.add_argument("--repetition", type=int, default=1)
    p.add_argument("--warmup",             type=int,   default=5)
    p.add_argument("--duration",           type=int,   default=30)
    p.add_argument("--sender-tail-sec",    type=int,   default=3)
    p.add_argument("--collector-tail-sec", type=int,   default=2)
    p.add_argument("--receiver-init-sec",  type=int,   default=10)
    p.add_argument("--receiver-bin",       default="auto")
    p.add_argument("--mcast-addr",         default="239.0.0.1")
    p.add_argument("--mcast-port",         type=int,   default=5005)
    p.add_argument("--batch",              type=int,   default=256)
    p.add_argument("--harness-ip",         default="127.0.0.1")
    p.add_argument("--fillsim-ip",         default="127.0.0.1")
    p.add_argument("--sender-iface",       default="10.10.10.2",
                   help="IP for send_ticks.py --iface.  10.10.10.2 = host PF1 "
                        "(default, NIC loopback).  127.0.0.1 = pure lo (needs "
                        "cpu_receiver --iface lo).")
    p.add_argument("--host-bind",          default="127.0.0.1")
    args = p.parse_args()

    runner  = BenchRunnerCPU(args)
    summary = runner.run()
    sys.exit(0 if summary else 1)


if __name__ == "__main__":
    main()
