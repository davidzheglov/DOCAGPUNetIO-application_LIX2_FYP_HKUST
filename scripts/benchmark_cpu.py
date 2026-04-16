#!/usr/bin/env python3
"""
benchmark_cpu.py — Single-run benchmark driver for local-host T1 (cpu_receiver).

Runs ONE (rate, repetition) combination end-to-end and writes raw BenchmarkResult
rows plus a computed summary.

Pipeline (all on host):
    send_ticks.py (local) -> cpu_receiver (local) -> benchmark_cpu.py (local UDP collector)

Usage:
    python3 scripts/benchmark_cpu.py --rate 50000
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

BENCH_FMT = "=QQQQQBBxxxxxx"
BENCH_SIZE = 48
BENCH_PORT = 5010

REPO_ROOT = Path(__file__).resolve().parent.parent


def pct(values, p):
    """values must be pre-sorted. p in [0,100]."""
    if not values:
        return float("nan")
    k = (len(values) - 1) * (p / 100.0)
    lo, hi = int(k), min(int(k) + 1, len(values) - 1)
    frac = k - lo
    return values[lo] * (1 - frac) + values[hi] * frac


def fmt_us(x):
    return f"{x:8.2f}" if x == x else "   NaN  "


class BenchRunnerCPU:
    def __init__(self, args):
        self.args = args

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.run_name = f"T1_{args.rate}hz_rep{args.repetition}_{ts}"
        self.run_dir = REPO_ROOT / "results" / "single" / self.run_name
        self.run_dir.mkdir(parents=True, exist_ok=True)

        self.bench_csv = self.run_dir / "bench.csv"
        self.summary_json = self.run_dir / "summary.json"
        self.receiver_log = self.run_dir / "receiver.log"
        self.sender_log = self.run_dir / "sender.log"

        self.rx_proc = None
        self.sender_proc = None
        self.rx_log_fh = None
        self.sender_log_fh = None

    def resolve_local_receiver_bin(self):
        a = self.args
        if a.receiver_bin != "auto":
            p = Path(a.receiver_bin)
            if not p.is_absolute():
                p = REPO_ROOT / p
            if p.exists() and p.is_file():
                return p
            sys.exit(f"[benchmark_cpu] receiver binary not found: {p}")

        candidates = [
            REPO_ROOT / "bin" / "cpu_receiver",
            REPO_ROOT / "build" / "bin" / "cpu_receiver",
            REPO_ROOT / "build" / "cpu_receiver",
        ]
        for p in candidates:
            if p.exists() and p.is_file():
                return p

        msg = (
            "[benchmark_cpu] could not find local cpu_receiver binary.\n"
            "  checked: bin/cpu_receiver, build/bin/cpu_receiver, build/cpu_receiver\n"
            "  build it locally with one of:\n"
            "    make t1\n"
            "    or\n"
            "    cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j$(nproc) --target cpu_receiver\n"
            "  or pass --receiver-bin with an explicit path."
        )
        sys.exit(msg)

    def start_receiver(self):
        a = self.args
        receiver_bin = self.resolve_local_receiver_bin()
        rx_cmd = [
            str(receiver_bin),
            "--mcast", a.mcast_addr,
            "--port", str(a.mcast_port),
            "--batch", str(a.batch),
            "--tier", "1",
            "--harness", a.harness_ip,
            "--fillsim", a.fillsim_ip,
        ]

        print(f"[benchmark_cpu] starting local cpu_receiver: {' '.join(rx_cmd)}")
        self.rx_log_fh = open(self.receiver_log, "w")
        self.rx_proc = subprocess.Popen(
            rx_cmd,
            stdout=self.rx_log_fh,
            stderr=subprocess.STDOUT,
            cwd=str(REPO_ROOT),
        )

        time.sleep(1.5)
        if self.rx_proc.poll() is not None:
            self.rx_log_fh.close()
            err = self.receiver_log.read_text(errors="replace").strip()
            print(f"[benchmark_cpu] ERROR: local cpu_receiver exited rc={self.rx_proc.returncode}")
            print("--- receiver.log ---")
            print(err)
            print("--------------------")
            sys.exit("[benchmark_cpu] failed to start local cpu_receiver")

    def start_sender(self):
        a = self.args
        total_sec = a.warmup + a.duration + a.sender_tail_sec
        count = a.rate * total_sec

        sender_script = REPO_ROOT / "scripts" / "send_ticks.py"
        send_cmd = [
            "python3", str(sender_script),
            "--mode", "generate",
            "--rate", str(a.rate),
            "--iface", a.sender_iface,
            "--count", str(count),
        ]

        print(f"[benchmark_cpu] starting local sender: {' '.join(send_cmd)}")
        self.sender_log_fh = open(self.sender_log, "w")
        self.sender_proc = subprocess.Popen(
            send_cmd,
            stdout=self.sender_log_fh,
            stderr=subprocess.STDOUT,
            cwd=str(REPO_ROOT),
        )

        time.sleep(1.0)
        if self.sender_proc.poll() is not None:
            self.sender_log_fh.close()
            err = self.sender_log.read_text(errors="replace").strip()
            print(f"[benchmark_cpu] ERROR: local sender exited rc={self.sender_proc.returncode}")
            print("--- sender.log ---")
            print(err)
            print("------------------")
            sys.exit("[benchmark_cpu] failed to start local sender")

    def collect(self):
        import socket
        import struct

        a = self.args
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((a.host_bind, BENCH_PORT))
        sock.settimeout(0.5)

        results = []
        collect_start = time.time()
        deadline = collect_start + a.warmup + a.duration + a.collector_tail_sec
        last_progress = time.time()

        print(
            f"[benchmark_cpu] collecting on {a.host_bind}:{BENCH_PORT} for "
            f"{a.warmup}s warmup + {a.duration}s measure (+{a.collector_tail_sec}s tail)"
        )

        while time.time() < deadline:
            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                data = None

            now = time.time()
            if data is not None and len(data) >= BENCH_SIZE:
                recv_ns = time.time_ns()
                tick_id, t1, t2, t3, t4, tier, dropped = struct.unpack(BENCH_FMT, data[:BENCH_SIZE])
                results.append(
                    {
                        "recv_ns": recv_ns,
                        "tick_id": tick_id,
                        "t1_ns": t1,
                        "t2_ns": t2,
                        "t3_ns": t3,
                        "t4_ns": t4,
                        "tier": tier,
                        "dropped": dropped,
                    }
                )

            if now - last_progress >= 2.0:
                elapsed = now - collect_start
                n = len(results)
                rate = n / max(elapsed, 0.001)
                print(f"  [{elapsed:5.1f}s] received={n:>8,} ({rate:>8,.0f}/s)", flush=True)
                last_progress = now

            if self.rx_proc and self.rx_proc.poll() is not None:
                print("[benchmark_cpu] local cpu_receiver exited during collection", flush=True)
                break

        sock.close()

        with open(self.bench_csv, "w", newline="") as f:
            w = csv.DictWriter(
                f,
                fieldnames=["recv_ns", "tick_id", "t1_ns", "t2_ns", "t3_ns", "t4_ns", "tier", "dropped"],
            )
            w.writeheader()
            w.writerows(results)

        print(f"[benchmark_cpu] wrote {len(results):,} rows -> {self.bench_csv}")
        return results, collect_start

    def analyze(self, results, collect_start):
        a = self.args
        if not results:
            print("[benchmark_cpu] no rows — nothing to analyze")
            return None

        win_start_ns = int((collect_start + a.warmup) * 1e9)
        win_end_ns = int((collect_start + a.warmup + a.duration) * 1e9)
        window = [r for r in results if win_start_ns <= r["recv_ns"] < win_end_ns]
        if not window:
            print("[benchmark_cpu] WARN: no rows inside measurement window")
            return None

        window.sort(key=lambda r: r["tick_id"])

        tid_first = window[0]["tick_id"]
        tid_last = window[-1]["tick_id"]
        expected = tid_last - tid_first + 1
        received = len(window)
        drop_rate = 1.0 - (received / expected) if expected > 0 else 0.0

        def lat(rows, a_ns, b_ns):
            out = []
            for r in rows:
                ta, tb = r[a_ns], r[b_ns]
                if ta > 0 and tb > ta:
                    out.append((tb - ta) / 1000.0)
            out.sort()
            return out

        def compute_latencies(rows):
            # In cpu_receiver, all ticks in a batch share one (t2, t3), so
            # raw (t3-t2) is batch kernel time. Report both batch and
            # amortized per-tick compute latency.
            batch_counter = Counter()
            for r in rows:
                t2, t3 = r["t2_ns"], r["t3_ns"]
                if t2 > 0 and t3 > t2:
                    batch_counter[(t2, t3)] += 1

            batch_us = []
            per_tick_us = []
            for (t2, t3), n in batch_counter.items():
                dur_us = (t3 - t2) / 1000.0
                batch_us.append(dur_us)
                per_tick_us.append(dur_us / max(n, 1))

            batch_us.sort()
            per_tick_us.sort()
            return per_tick_us, batch_us

        e2e = lat(window, "t1_ns", "t4_ns")
        ingest = lat(window, "t1_ns", "t2_ns")
        compute, compute_batch = compute_latencies(window)
        egress = lat(window, "t3_ns", "t4_ns")

        def stats(lst):
            if not lst:
                return {
                    "n": 0,
                    "mean": float("nan"),
                    "p50": float("nan"),
                    "p95": float("nan"),
                    "p99": float("nan"),
                    "p999": float("nan"),
                    "max": float("nan"),
                }
            return {
                "n": len(lst),
                "mean": mean(lst),
                "p50": pct(lst, 50),
                "p95": pct(lst, 95),
                "p99": pct(lst, 99),
                "p999": pct(lst, 99.9),
                "max": lst[-1],
            }

        summary = {
            "run": {
                "run_name": self.run_name,
                "timestamp": datetime.now().isoformat(),
                "tier": 1,
                "rate_hz": a.rate,
                "repetition": a.repetition,
                "warmup_sec": a.warmup,
                "duration_sec": a.duration,
                "mode": "local_host",
                "receiver": "cpu_receiver",
            },
            "throughput": {
                "expected": expected,
                "received": received,
                "drop_rate": drop_rate,
                "achieved_hz": received / a.duration if a.duration else 0.0,
                "target_hz": a.rate,
                "tick_id_first": tid_first,
                "tick_id_last": tid_last,
            },
            "latency_us": {
                "e2e": stats(e2e),
                "ingest": stats(ingest),
                "compute": stats(compute),
                "compute_batch": stats(compute_batch),
                "egress": stats(egress),
            },
        }

        with open(self.summary_json, "w") as f:
            json.dump(summary, f, indent=2)

        self.print_summary(summary)
        return summary

    def print_summary(self, s):
        r = s["run"]
        t = s["throughput"]
        L = s["latency_us"]

        print()
        print("=" * 72)
        print(f"  {r['run_name']}")
        print("=" * 72)
        print(
            f"  tier={r['tier']} target={r['rate_hz']:,} Hz rep={r['repetition']} "
            f"mode={r['mode']}"
        )
        print(f"  window: {r['warmup_sec']}s warmup + {r['duration_sec']}s measure")
        print()
        print("  Throughput:")
        print(f"    expected   : {t['expected']:>10,}")
        print(f"    received   : {t['received']:>10,}")
        print(f"    drop rate  : {t['drop_rate']*100:>10.3f} %")
        print(f"    achieved   : {t['achieved_hz']:>10,.0f} Hz (target {t['target_hz']:,})")
        print()
        print("  Latency (us):          n       mean      p50      p95      p99     p99.9     max")
        for name, key in [
            ("  ingest(t2-t1)", "ingest"),
            ("  compute/tick", "compute"),
            ("  compute/batch", "compute_batch"),
            ("  egress (t4-t3)", "egress"),
            ("  e2e    (t4-t1)", "e2e"),
        ]:
            x = L[key]
            print(
                f"  {name:14s}  {x['n']:>7,}  {fmt_us(x['mean'])}  "
                f"{fmt_us(x['p50'])}  {fmt_us(x['p95'])}  "
                f"{fmt_us(x['p99'])}  {fmt_us(x['p999'])}  {fmt_us(x['max'])}"
            )
        print()
        print("  Files:")
        print(f"    {self.bench_csv}")
        print(f"    {self.summary_json}")
        print(f"    {self.receiver_log}")
        print(f"    {self.sender_log}")
        print("=" * 72)

    def cleanup(self):
        if self.sender_proc and self.sender_proc.poll() is None:
            self.sender_proc.terminate()
            try:
                self.sender_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.sender_proc.kill()

        if self.rx_proc and self.rx_proc.poll() is None:
            self.rx_proc.terminate()
            try:
                self.rx_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.rx_proc.kill()

        # Belt-and-suspenders cleanup on host side.
        subprocess.run(["pkill", "-f", "cpu_receiver"],
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-f", "send_ticks.py"],
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)

        if self.rx_log_fh:
            self.rx_log_fh.close()
        if self.sender_log_fh:
            self.sender_log_fh.close()

    def run(self):
        print(f"[benchmark_cpu] run -> {self.run_dir}")
        results = []
        collect_start = time.time()
        try:
            self.start_receiver()
            self.start_sender()
            results, collect_start = self.collect()
        finally:
            self.cleanup()

        return self.analyze(results, collect_start)


def main():
    p = argparse.ArgumentParser(
        description="Run ONE local-host T1 benchmark and emit bench.csv + summary.json."
    )
    p.add_argument("--rate", type=int, required=True,
                   help="Target send rate in ticks/sec (e.g. 10000, 50000)")
    p.add_argument("--repetition", type=int, default=1)

    p.add_argument("--warmup", type=int, default=5,
                   help="Seconds of warmup to skip in analysis")
    p.add_argument("--duration", type=int, default=30,
                   help="Measurement window length in seconds")
    p.add_argument("--sender-tail-sec", type=int, default=3,
                   help="Extra seconds of ticks to send past measurement window")
    p.add_argument("--collector-tail-sec", type=int, default=2,
                   help="Extra seconds to keep collector listening past measurement")

    # Local receiver args
    p.add_argument("--receiver-bin", default="auto",
                   help="Local receiver binary path, or auto")
    p.add_argument("--mcast-addr", default="239.0.0.1")
    p.add_argument("--mcast-port", type=int, default=5005)
    p.add_argument("--batch", type=int, default=256)
    p.add_argument("--harness-ip", default="127.0.0.1",
                   help="IP cpu_receiver uses for --harness")
    p.add_argument("--fillsim-ip", default="127.0.0.1",
                   help="IP cpu_receiver uses for --fillsim")

    # Local sender args
    p.add_argument("--sender-iface", default="10.10.10.2",
                   help="Interface IP used by local send_ticks.py --iface")

    # Local collector bind
    p.add_argument("--host-bind", default="127.0.0.1",
                   help="Host bind address for BenchmarkResult UDP listener")

    args = p.parse_args()

    runner = BenchRunnerCPU(args)
    summary = runner.run()
    sys.exit(0 if summary else 1)


if __name__ == "__main__":
    main()
