#!/usr/bin/env python3
"""
benchmark.py — Single-run benchmark driver for the T4 / T5 GPUNetIO pipeline.

Runs ONE (tier, rate, repetition) combination end-to-end and writes the raw
BenchmarkResult stream plus a computed summary. Meant to be invoked manually
one run at a time — the user decides when to step up the rate.

Pipeline (T4):
    DPU send_ticks.py  ──multicast──▶  host gpu_receiver  ──UDP──▶  this script
    (SSH'd from host,                   (launched by this                 │
     or started manually                 script, sudo + env)              │
     via --manual)                                                        ▼
                                                          results/single/<run>/
                                                              bench.csv
                                                              summary.json
                                                              receiver.log
                                                              run.nsys-rep  (optional)

Usage:
    # Standard run, SSH-driven sender on DPU:
    sudo -E python3 scripts/benchmark.py --tier 4 --rate 50000

    # Manual sender (you start send_ticks.py on the DPU yourself):
    sudo -E python3 scripts/benchmark.py --tier 4 --rate 50000 --manual

    # Profiled run (wraps gpu_receiver in nsys):
    sudo -E python3 scripts/benchmark.py --tier 4 --rate 50000 --nsys

All command targets:
  - This script runs ON HOST (needs sudo for DOCA + to kill gpu_receiver).
  - gpu_receiver is started ON HOST by this script.
  - send_ticks.py runs ON DPU ARM (either via SSH from this script, or manually).
"""

import argparse
import csv
import json
import os
import shlex
import signal
import socket
import struct
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from statistics import mean

# ── Wire format: BenchmarkResult from gpu_receiver (see benchmark_result.h) ──
BENCH_FMT  = "=QQQQQBBxxxxxx"
BENCH_SIZE = 48
BENCH_PORT = 5010

REPO_ROOT = Path(__file__).resolve().parent.parent


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def pct(values, p):
    """values must be pre-sorted. p in [0,100]."""
    if not values:
        return float("nan")
    k = (len(values) - 1) * (p / 100.0)
    lo, hi = int(k), min(int(k) + 1, len(values) - 1)
    frac = k - lo
    return values[lo] * (1 - frac) + values[hi] * frac


def fmt_us(x):
    return f"{x:8.2f}" if x == x else "   NaN  "   # x != x is True for NaN


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────

class BenchRunner:
    def __init__(self, args):
        self.args = args

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.run_name = f"T{args.tier}_{args.rate}hz_rep{args.repetition}_{ts}"
        self.run_dir  = REPO_ROOT / "results" / "single" / self.run_name
        self.run_dir.mkdir(parents=True, exist_ok=True)

        self.bench_csv    = self.run_dir / "bench.csv"
        self.summary_json = self.run_dir / "summary.json"
        self.receiver_log = self.run_dir / "receiver.log"
        self.sender_log   = self.run_dir / "sender.log"
        self.nsys_report  = self.run_dir / "run.nsys-rep"

        # Child processes
        self.rx_proc       = None
        self.rx_log_fh     = None
        self.ssh_proc      = None
        self.sender_log_fh = None

        # SIGINT/SIGTERM → graceful shutdown
        self._interrupted = False
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, self._on_signal)

    def _on_signal(self, signum, frame):
        if self._interrupted:
            return
        self._interrupted = True
        print(f"\n[benchmark] caught signal {signum} — shutting down", flush=True)

    # ── gpu_receiver (host) ──────────────────────────────────────────────────
    def start_receiver(self):
        receiver_bin = REPO_ROOT / "bin" / "gpu_receiver"
        if not receiver_bin.exists():
            sys.exit(f"[benchmark] ERROR: {receiver_bin} not found — run `make t4` first")

        args = self.args
        rx_cmd = [
            str(receiver_bin),
            "--tier", str(args.tier),
            "--gpu", str(args.gpu_index),
            "--gpu-pcie", args.gpu_pcie,
            "--nic-pcie", args.nic_pcie,
            "--harness", "127.0.0.1",
            "--fillsim", "127.0.0.1",
        ]

        # We are already running as root (script requires sudo). Pass through
        # the env the receiver needs (LD_LIBRARY_PATH for DOCA, PATH for nsys).
        env = os.environ.copy()

        if args.nsys:
            nsys_bin = args.nsys_bin or "nsys"
            rx_cmd = [
                nsys_bin, "profile",
                "--capture-range=cudaProfilerApi",
                "--capture-range-end=stop-shutdown",
                "--trace=cuda,nvtx,osrt",
                "--force-overwrite=true",
                "-o", str(self.nsys_report.with_suffix("")),  # nsys adds .nsys-rep
            ] + rx_cmd

        print(f"[benchmark] starting gpu_receiver: {' '.join(shlex.quote(a) for a in rx_cmd)}")
        self.rx_log_fh = open(self.receiver_log, "w")
        self.rx_proc = subprocess.Popen(
            rx_cmd,
            stdout=self.rx_log_fh,
            stderr=subprocess.STDOUT,
            env=env,
            cwd=str(REPO_ROOT),
        )

        # Wait for receiver to print "cudaProfilerStart" or hit init timeout
        deadline = time.time() + args.receiver_init_sec
        while time.time() < deadline:
            if self.rx_proc.poll() is not None:
                sys.exit(f"[benchmark] ERROR: gpu_receiver exited during init "
                         f"(rc={self.rx_proc.returncode}); see {self.receiver_log}")
            # Light sleep; receiver streams to log file which we read below
            time.sleep(0.2)
            try:
                log = self.receiver_log.read_text(errors="replace")
            except OSError:
                log = ""
            if "launching persistent GPU kernel" in log:
                print("[benchmark] gpu_receiver initialized")
                return
        print("[benchmark] WARN: gpu_receiver init banner not seen — continuing anyway")

    # ── send_ticks (DPU) ─────────────────────────────────────────────────────
    def start_sender(self):
        a = self.args
        # Send enough ticks to cover warmup + measure + safety margin
        total_sec = a.warmup + a.duration + a.sender_tail_sec
        count = a.rate * total_sec

        send_cmd = (
            f"cd {shlex.quote(a.dpu_repo)} && "
            f"python3 scripts/send_ticks.py "
            f"--mode generate "
            f"--rate {a.rate} "
            f"--iface {shlex.quote(a.dpu_bind_ip)} "
            f"--count {count}"
        )

        if a.manual:
            print("\n" + "=" * 70)
            print("MANUAL SENDER MODE — run this ON DPU ARM, then press Enter here:")
            print("=" * 70)
            print(send_cmd)
            print("=" * 70)
            input(">>> Press Enter once send_ticks is running on the DPU... ")
            return

        ssh_target = a.ssh
        print(f"[benchmark] launching sender via SSH: {ssh_target}")
        print(f"[benchmark]   remote cmd: {send_cmd}")

        ssh_opts = ["-o", "StrictHostKeyChecking=no"]
        if a.ssh_batch:
            # Non-interactive: fail fast if no key auth. Otherwise the ssh client
            # would hang inside Popen waiting for a password on a closed stdin.
            ssh_opts += ["-o", "BatchMode=yes"]

        self.sender_log_fh = open(self.sender_log, "w")
        self.ssh_proc = subprocess.Popen(
            ["ssh", *ssh_opts, ssh_target, send_cmd],
            stdout=self.sender_log_fh,
            stderr=subprocess.STDOUT,
        )

        # Give ssh a moment to either authenticate + start send_ticks, or fail.
        # If it dies immediately, surface the log so the user sees why.
        time.sleep(1.5)
        if self.ssh_proc.poll() is not None:
            rc = self.ssh_proc.returncode
            try:
                err = self.sender_log.read_text(errors="replace").strip()
            except OSError:
                err = "(sender log unreadable)"
            self.sender_log_fh.close()
            print(f"[benchmark] ERROR: ssh sender exited rc={rc}")
            print("─── sender.log ───")
            print(err)
            print("──────────────────")
            sys.exit(
                "[benchmark] Could not start send_ticks on DPU.\n"
                "  Fix: either (a) set up key-based SSH to the DPU once with\n"
                "           ssh-copy-id ubuntu@192.168.100.2\n"
                "       or (b) re-run with --manual and start send_ticks by hand,\n"
                "       or (c) re-run with --no-ssh-batch to let ssh prompt for a\n"
                "           password on this terminal (you must type it before\n"
                "           the ~1.5s startup window elapses)."
            )

    # ── Collector (this process) ─────────────────────────────────────────────
    def collect(self):
        """Listen on BENCH_PORT for the full warmup+duration window and write
        bench.csv. Returns list of dicts."""
        a = self.args
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", BENCH_PORT))
        sock.settimeout(0.5)

        results = []
        deadline = time.time() + a.warmup + a.duration + a.collector_tail_sec
        print(f"[benchmark] collecting for {a.warmup}s warmup + {a.duration}s measure "
              f"(+ {a.collector_tail_sec}s drain)...")
        last_progress = time.time()
        collect_start = time.time()

        while time.time() < deadline and not self._interrupted:
            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                data = None
            now = time.time()

            if data is not None and len(data) >= BENCH_SIZE:
                recv_ns = time.time_ns()
                tick_id, t1, t2, t3, t4, tier, dropped = struct.unpack(
                    BENCH_FMT, data[:BENCH_SIZE])
                results.append({
                    "recv_ns": recv_ns,
                    "tick_id": tick_id,
                    "t1_ns":   t1,
                    "t2_ns":   t2,
                    "t3_ns":   t3,
                    "t4_ns":   t4,
                    "tier":    tier,
                    "dropped": dropped,
                })

            if now - last_progress >= 2.0:
                elapsed = now - collect_start
                n = len(results)
                rate = n / max(elapsed, 0.001)
                print(f"  [{elapsed:5.1f}s]  received={n:>8,}  "
                      f"({rate:>8,.0f}/s)", flush=True)
                last_progress = now

            # Receiver dead?
            if self.rx_proc and self.rx_proc.poll() is not None:
                print("[benchmark] gpu_receiver exited during collection", flush=True)
                break

        sock.close()

        # Write raw CSV (everything, unfiltered)
        with open(self.bench_csv, "w", newline="") as f:
            w = csv.DictWriter(
                f,
                fieldnames=["recv_ns", "tick_id",
                            "t1_ns", "t2_ns", "t3_ns", "t4_ns",
                            "tier", "dropped"])
            w.writeheader()
            w.writerows(results)

        print(f"[benchmark] wrote {len(results):,} rows → {self.bench_csv}")
        return results

    # ── Analysis ─────────────────────────────────────────────────────────────
    def analyze(self, results):
        a = self.args
        if not results:
            print("[benchmark] no rows — nothing to analyze")
            return None

        # Anchor the measurement window on the first observed t1_ns.
        # This lines up with the DPU sender's wall clock (t1 = send timestamp).
        first_t1 = results[0]["t1_ns"]
        win_start = first_t1 + a.warmup   * 1_000_000_000
        win_end   = first_t1 + (a.warmup + a.duration) * 1_000_000_000

        window = [r for r in results if win_start <= r["t1_ns"] < win_end]
        if not window:
            print("[benchmark] WARN: no rows inside measurement window "
                  f"(first_t1={first_t1}, warmup={a.warmup}s, duration={a.duration}s)")
            return None

        # Ordered by send time (tick_id is monotonic in send_ticks).
        window.sort(key=lambda r: r["tick_id"])

        # Drop-rate: expected vs received within the window.
        tid_first = window[0]["tick_id"]
        tid_last  = window[-1]["tick_id"]
        expected  = tid_last - tid_first + 1
        received  = len(window)
        drop_rate = 1.0 - (received / expected) if expected > 0 else 0.0

        # Per-stage latencies (μs). Zero-timestamp entries (e.g. from legacy
        # receivers) are dropped defensively.
        def lat(rows, a_ns, b_ns):
            out = []
            for r in rows:
                ta, tb = r[a_ns], r[b_ns]
                if ta > 0 and tb > ta:
                    out.append((tb - ta) / 1000.0)
            out.sort()
            return out

        e2e      = lat(window, "t1_ns", "t4_ns")
        ingest   = lat(window, "t1_ns", "t2_ns")   # send → GPU mem
        compute  = lat(window, "t2_ns", "t3_ns")   # GPU mem → kernel done
        egress   = lat(window, "t3_ns", "t4_ns")   # kernel done → UDP out

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

        summary = {
            "run": {
                "run_name":    self.run_name,
                "timestamp":   datetime.now().isoformat(),
                "tier":        a.tier,
                "rate_hz":     a.rate,
                "repetition":  a.repetition,
                "warmup_sec":  a.warmup,
                "duration_sec":a.duration,
                "mode":        "manual" if a.manual else "ssh",
                "nsys":        bool(a.nsys),
                "dpu_bind_ip": a.dpu_bind_ip,
                "ssh":         a.ssh if not a.manual else None,
            },
            "throughput": {
                "expected":       expected,
                "received":       received,
                "drop_rate":      drop_rate,
                "achieved_hz":    received / a.duration if a.duration else 0.0,
                "target_hz":      a.rate,
                "tick_id_first":  tid_first,
                "tick_id_last":   tid_last,
            },
            "latency_us": {
                "e2e":     stats(e2e),
                "ingest":  stats(ingest),
                "compute": stats(compute),
                "egress":  stats(egress),
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
        print(f"  tier={r['tier']}  target={r['rate_hz']:,} Hz  rep={r['repetition']}  "
              f"nsys={'on' if r['nsys'] else 'off'}")
        print(f"  window: {r['warmup']}s warmup + {r['duration']}s measure")
        print()
        print(f"  Throughput:")
        print(f"    expected   : {t['expected']:>10,}")
        print(f"    received   : {t['received']:>10,}")
        print(f"    drop rate  : {t['drop_rate']*100:>10.3f} %")
        print(f"    achieved   : {t['achieved_hz']:>10,.0f} Hz  "
              f"(target {t['target_hz']:,})")
        print()
        print(f"  Latency (μs):          n       mean      p50      p95      p99     p99.9     max")
        for name, key in [("  ingest(t2-t1)", "ingest"),
                          ("  compute(t3-t2)", "compute"),
                          ("  egress (t4-t3)", "egress"),
                          ("  e2e    (t4-t1)", "e2e")]:
            x = L[key]
            print(f"  {name:14s}  {x['n']:>7,}  {fmt_us(x['mean'])}  "
                  f"{fmt_us(x['p50'])}  {fmt_us(x['p95'])}  "
                  f"{fmt_us(x['p99'])}  {fmt_us(x['p999'])}  {fmt_us(x['max'])}")
        print()
        print(f"  Files:")
        print(f"    {self.bench_csv}")
        print(f"    {self.summary_json}")
        print(f"    {self.receiver_log}")
        if r["nsys"]:
            print(f"    {self.nsys_report}")
        print("=" * 72)

    # ── Cleanup ──────────────────────────────────────────────────────────────
    def cleanup(self):
        # 1) Remote sender (SSH): closing the channel causes remote python to
        #    receive SIGHUP and exit. If not, we send SIGTERM via pkill.
        if self.ssh_proc and self.ssh_proc.poll() is None:
            print("[benchmark] terminating SSH sender channel...")
            try:
                self.ssh_proc.terminate()
                self.ssh_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.ssh_proc.kill()
        # Belt-and-suspenders: ask the DPU to kill any lingering send_ticks.py
        a = self.args
        if not a.manual and a.ssh:
            subprocess.run(
                ["ssh", "-o", "BatchMode=yes", a.ssh,
                 "pkill -f send_ticks.py || true"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5,
            )

        # 2) gpu_receiver: send SIGINT first so it runs its clean-shutdown path
        #    (drains kernel, closes DOCA, and — crucially — lets nsys finalize).
        if self.rx_proc and self.rx_proc.poll() is None:
            print("[benchmark] sending SIGINT to gpu_receiver (pid %d)..." % self.rx_proc.pid)
            try:
                self.rx_proc.send_signal(signal.SIGINT)
                # nsys finalization can take a while — give it room
                self.rx_proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                print("[benchmark] gpu_receiver did not exit — SIGTERM")
                self.rx_proc.terminate()
                try:
                    self.rx_proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    print("[benchmark] gpu_receiver still alive — SIGKILL")
                    self.rx_proc.kill()
                    self.rx_proc.wait()

        if self.rx_log_fh:
            self.rx_log_fh.close()
        if self.sender_log_fh:
            self.sender_log_fh.close()

        # 3) Anything stray (only kills what we own since we are sudo).
        subprocess.run(["pkill", "-f", "gpu_receiver"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # ── Main sequence ────────────────────────────────────────────────────────
    def run(self):
        print(f"[benchmark] run → {self.run_dir}")
        try:
            self.start_receiver()
            self.start_sender()
            results = self.collect()
            # Sender should exit on its own (finite count). Receiver we stop.
        finally:
            self.cleanup()

        try:
            return self.analyze(results)
        except UnboundLocalError:
            return None


# ─────────────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="Run ONE T4/T5 benchmark and emit bench.csv + summary.json.")
    p.add_argument("--tier", type=int, required=True, choices=[4, 5])
    p.add_argument("--rate", type=int, required=True,
                   help="Target send rate in ticks/sec (e.g. 10000, 50000)")
    p.add_argument("--repetition", type=int, default=1)

    p.add_argument("--warmup",   type=int, default=5,
                   help="Seconds of warmup to skip in analysis")
    p.add_argument("--duration", type=int, default=30,
                   help="Measurement window length in seconds")

    # Receiver-side (host)
    p.add_argument("--gpu-index", type=int, default=1)
    p.add_argument("--gpu-pcie",  default="0000:ac:00.0")
    p.add_argument("--nic-pcie",  default="0000:bd:00.1")
    p.add_argument("--receiver-init-sec", type=int, default=15,
                   help="How long to wait for gpu_receiver to reach steady state")

    # Sender-side (DPU)
    p.add_argument("--ssh", default="ubuntu@192.168.100.2",
                   help="SSH target for DPU ARM (mgmt network, not data path)")
    p.add_argument("--dpu-repo", default="/home/ubuntu/DOCAGPUNetIO-application_LIX2_FYP_HKUST",
                   help="Path to project repo on DPU ARM")
    p.add_argument("--dpu-bind-ip", default="10.10.10.1",
                   help="IP on DPU to bind multicast sender (data path, not mgmt)")
    p.add_argument("--manual", action="store_true",
                   help="Don't SSH — print send_ticks command and wait for you to run it")
    p.add_argument("--no-ssh-batch", dest="ssh_batch",
                   action="store_false", default=True,
                   help="Allow ssh to prompt for a password on this terminal "
                        "(default: BatchMode=yes, fails fast if no key auth)")
    p.add_argument("--sender-tail-sec", type=int, default=3,
                   help="Extra seconds of ticks to send past measurement window")
    p.add_argument("--collector-tail-sec", type=int, default=2,
                   help="Extra seconds to keep the collector listening past measurement")

    # Nsight Systems
    p.add_argument("--nsys", action="store_true",
                   help="Wrap gpu_receiver in `nsys profile`")
    p.add_argument("--nsys-bin", default=None,
                   help="Override path to nsys binary (default: PATH lookup)")

    args = p.parse_args()

    # gpu_receiver + DOCA need root; nsys-recorded perf counters need root too.
    if os.geteuid() != 0:
        sys.exit("[benchmark] ERROR: run with sudo (gpu_receiver requires root). "
                 "Try: sudo -E python3 scripts/benchmark.py ...")

    runner = BenchRunner(args)
    summary = runner.run()
    sys.exit(0 if summary else 1)


if __name__ == "__main__":
    main()
