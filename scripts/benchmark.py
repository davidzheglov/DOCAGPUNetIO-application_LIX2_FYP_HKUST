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
import getpass
import json
import os
import shlex
import shutil
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


def ssh_user_prefix():
    """If we're running as root under sudo, prepend `sudo -u $SUDO_USER -H` so
    that ssh/scp use the invoking user's keys, known_hosts, and ssh-agent
    instead of root's empty ~/.ssh. Returns [] when no wrapping is needed."""
    sudo_user = os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and sudo_user and sudo_user != "root":
        return ["sudo", "-u", sudo_user, "-H"]
    return []


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
        self.cal_ssh_proc  = None
        self.ssh_password  = None   # set by prompt_ssh_password() if --ask-pass
        self.clock_offset_ns = 0    # set by calibrate_clock_offset(); DPU→host
        self.clock_oneway_ns = 0    # estimated one-way network delay
        self.clock_cal_ip    = None # which IP we pinged (mgmt vs data-path)
        self.clock_offset_applied_ns = 0   # set by collect() — what we actually used
        self.clock_offset_slope      = 0.0 # ns of drift per ns of t2 (drift-aware only)
        self.clock_offset_source     = "none"  # "none" | "ntp" | "empirical_*" | "drift_linear"

        # SIGINT/SIGTERM → graceful shutdown
        self._interrupted = False
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, self._on_signal)

    def _on_signal(self, signum, frame):
        if self._interrupted:
            return
        self._interrupted = True
        print(f"\n[benchmark] caught signal {signum} — shutting down", flush=True)

    # ── SSH helper (same auth as the sender) ─────────────────────────────────
    def _build_ssh(self, remote_cmd, log_fh=None, background=False):
        """Return (argv, env) for an ssh call to self.args.ssh that uses the
        same auth approach as start_sender()."""
        a = self.args
        ssh_opts = ["-o", "StrictHostKeyChecking=no"]
        env = os.environ.copy()
        if self.ssh_password is not None:
            env["SSHPASS"] = self.ssh_password
            ssh_opts += ["-o", "PreferredAuthentications=password",
                         "-o", "PubkeyAuthentication=no"]
            cmd = ["sshpass", "-e", "ssh", *ssh_opts, a.ssh, remote_cmd]
        else:
            if a.ssh_batch:
                ssh_opts += ["-o", "BatchMode=yes"]
            cmd = ssh_user_prefix() + ["ssh", *ssh_opts, a.ssh, remote_cmd]
        return cmd, env

    # ── Clock offset calibration ─────────────────────────────────────────────
    def calibrate_clock_offset(self):
        """NTP-style 4-timestamp round-trip over the data path to estimate the
        DPU↔host clock offset. Saves results in self.clock_offset_ns so that
        analyze() can correct t1_ns into the host frame."""
        a = self.args
        if not a.calibrate or a.manual:
            if a.manual and a.calibrate:
                print("[benchmark] skipping clock calibration (manual mode)")
            return

        # Tier 1 runs the sender on the host (same machine as cpu_receiver), so
        # T1 and T2 are both captured on the same wall clock. No DPU↔host offset
        # to measure — skip the remote cal server handshake.
        if a.tier == 1:
            print("[benchmark] skipping clock calibration (tier 1: host-only sender, same clock)")
            return

        cal_ip = a.cal_ip or a.ssh.split("@")[-1]

        # Bind the server to 0.0.0.0 so that whatever IP the client picks
        # reaches it (mgmt path or data path).
        cal_cmd = (f"cd {shlex.quote(a.dpu_repo)} && "
                   f"python3 scripts/clock_cal_server.py "
                   f"--ip 0.0.0.0 "
                   f"--port {a.cal_port}")

        print(f"[benchmark] clock calibration — starting cal server on DPU, "
              f"pinging {cal_ip}:{a.cal_port}")
        cal_log = self.run_dir / "cal.log"
        cal_log_fh = open(cal_log, "w")
        argv, env = self._build_ssh(cal_cmd)
        self.cal_ssh_proc = subprocess.Popen(
            argv, stdout=cal_log_fh, stderr=subprocess.STDOUT, env=env)
        # Give the remote Python + socket.bind a moment
        time.sleep(1.5)
        if self.cal_ssh_proc.poll() is not None:
            cal_log_fh.close()
            err = cal_log.read_text(errors="replace").strip()
            print(f"[benchmark] ERROR: cal server failed (rc={self.cal_ssh_proc.returncode})")
            print(f"─── cal.log ───\n{err}\n──────────────")
            sys.exit("[benchmark] cannot calibrate — aborting. "
                     "Use --no-calibrate to skip (but then e2e/ingest will be NaN).")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.5)

        samples = []  # list of (offset_ns, one_way_ns)
        for i in range(a.cal_samples):
            try:
                t_a = time.time_ns()
                sock.sendto(struct.pack("=Q", t_a),
                            (cal_ip, a.cal_port))
                data, _ = sock.recvfrom(32)
                t_d = time.time_ns()
            except socket.timeout:
                continue
            if len(data) < 24:
                continue
            _, t_b, t_c = struct.unpack("=QQQ", data[:24])
            offset  = ((t_b - t_a) + (t_c - t_d)) // 2
            one_way = ((t_d - t_a) - (t_c - t_b)) // 2
            samples.append((offset, one_way))
            time.sleep(0.002)  # small gap so we're not rate-limited

        sock.close()

        # Kill the cal server on the DPU
        kill_argv, kill_env = self._build_ssh("pkill -f clock_cal_server.py || true")
        subprocess.run(kill_argv, env=kill_env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=5)
        try:
            self.cal_ssh_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.cal_ssh_proc.terminate()
        cal_log_fh.close()

        if not samples:
            sys.exit("[benchmark] calibration got 0 replies — check data path "
                     f"to {a.dpu_bind_ip}:{a.cal_port}")

        # Pick the sample with the smallest round-trip (least jitter →
        # best offset estimate). This is the standard NTP / PTP trick.
        samples.sort(key=lambda x: x[1])
        # Use the median of the lowest-jitter decile for robustness
        best_n = max(5, len(samples) // 10)
        best = samples[:best_n]
        best.sort(key=lambda x: x[0])
        offset_ns  = best[len(best) // 2][0]
        oneway_ns  = samples[0][1]

        self.clock_offset_ns = int(offset_ns)
        self.clock_oneway_ns = int(oneway_ns)
        self.clock_cal_ip    = cal_ip

        # Human-readable description of the offset direction.
        if offset_ns > 0:
            direction = f"DPU is AHEAD of host by {offset_ns/1e9:.3f} s"
        elif offset_ns < 0:
            direction = f"DPU is BEHIND host by {-offset_ns/1e9:.3f} s"
        else:
            direction = "clocks appear synchronized"

        print(f"[benchmark] clock offset: {offset_ns/1000:+.2f} μs   "
              f"({direction}; min-RTT one-way ≈ {oneway_ns/1000:.2f} μs, "
              f"{len(samples)}/{a.cal_samples} samples via {cal_ip})")
        if abs(offset_ns) > 60_000_000_000:   # >60 s is weird
            print(f"[benchmark] NOTE: clock offset is >{abs(offset_ns)/1e9:.0f}s "
                  f"— the DPU's wall clock is badly misset. The math still "
                  f"works, but you probably want to `sudo date -s ...` on the "
                  f"DPU or run chronyd on it before the real report runs.")

    # ── gpu_receiver (host) ──────────────────────────────────────────────────
    def start_receiver(self):
        args = self.args

        # Tier 1 uses the CPU naive receiver (recvfrom + cudaMemcpy). Tiers
        # 4/5 use the persistent DOCA GPUNetIO kernel. Both binaries share
        # --tier / --harness / --fillsim flags; only the DOCA one needs the
        # GPU/NIC PCIe addresses.
        if args.tier == 1:
            receiver_bin = REPO_ROOT / "bin" / "cpu_receiver"
            if not receiver_bin.exists():
                sys.exit(f"[benchmark] ERROR: {receiver_bin} not found — "
                         f"build with `cmake --build build --target cpu_receiver`")
            rx_cmd = [
                str(receiver_bin),
                "--tier", str(args.tier),
                "--harness", "127.0.0.1",
                "--fillsim", "127.0.0.1",
            ]
            receiver_label = "cpu_receiver"
            init_sentinel  = "[T1 cpu_receiver] ready"
        else:
            receiver_bin = REPO_ROOT / "bin" / "gpu_receiver"
            if not receiver_bin.exists():
                sys.exit(f"[benchmark] ERROR: {receiver_bin} not found — run `make t4` first")
            rx_cmd = [
                str(receiver_bin),
                "--tier", str(args.tier),
                "--gpu", str(args.gpu_index),
                "--gpu-pcie", args.gpu_pcie,
                "--nic-pcie", args.nic_pcie,
                "--harness", "127.0.0.1",
                "--fillsim", "127.0.0.1",
            ]
            receiver_label = "gpu_receiver"
            init_sentinel  = "launching persistent GPU kernel"

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

        print(f"[benchmark] starting {receiver_label}: {' '.join(shlex.quote(a) for a in rx_cmd)}")
        self.rx_log_fh = open(self.receiver_log, "w")
        self.rx_proc = subprocess.Popen(
            rx_cmd,
            stdout=self.rx_log_fh,
            stderr=subprocess.STDOUT,
            env=env,
            cwd=str(REPO_ROOT),
        )

        # Wait for receiver to print its ready banner, or hit init timeout
        deadline = time.time() + args.receiver_init_sec
        while time.time() < deadline:
            if self.rx_proc.poll() is not None:
                sys.exit(f"[benchmark] ERROR: {receiver_label} exited during init "
                         f"(rc={self.rx_proc.returncode}); see {self.receiver_log}")
            # Light sleep; receiver streams to log file which we read below
            time.sleep(0.2)
            try:
                log = self.receiver_log.read_text(errors="replace")
            except OSError:
                log = ""
            if init_sentinel in log:
                print(f"[benchmark] {receiver_label} initialized")
                return
        print(f"[benchmark] WARN: {receiver_label} init banner not seen — continuing anyway")

    # ── send_ticks (DPU) ─────────────────────────────────────────────────────
    def start_sender(self):
        a = self.args
        # Send enough ticks to cover warmup + measure + safety margin
        total_sec = a.warmup + a.duration + a.sender_tail_sec
        count = a.rate * total_sec

        # Tier 1: sender runs on the host alongside cpu_receiver. The kernel
        # loops multicast back to any locally-joined socket (IP_MULTICAST_LOOP
        # default on), so binding to 127.0.0.1 is the minimal-noise path. No
        # SSH, no DPU — this is why tier 1 skips clock calibration.
        if a.tier == 1:
            local_cmd = [
                "python3", str(REPO_ROOT / "scripts" / "send_ticks.py"),
                "--mode", "generate",
                "--rate", str(a.rate),
                "--iface", "127.0.0.1",
                "--count", str(count),
            ]
            print(f"[benchmark] launching local sender (tier 1): "
                  f"{' '.join(shlex.quote(x) for x in local_cmd)}")
            self.sender_log_fh = open(self.sender_log, "w")
            self.ssh_proc = subprocess.Popen(       # reuse the field for cleanup
                local_cmd,
                stdout=self.sender_log_fh,
                stderr=subprocess.STDOUT,
                cwd=str(REPO_ROOT),
            )
            time.sleep(0.5)  # let the socket bind
            if self.ssh_proc.poll() is not None:
                rc = self.ssh_proc.returncode
                try:
                    err = self.sender_log.read_text(errors="replace").strip()
                except OSError:
                    err = "(sender log unreadable)"
                self.sender_log_fh.close()
                print(f"[benchmark] ERROR: local sender exited rc={rc}")
                print("─── sender.log ───")
                print(err)
                print("──────────────────")
                sys.exit("[benchmark] tier-1 local sender failed to start.")
            return

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
        # Only use BatchMode when we have neither a password nor an interactive
        # terminal — otherwise we want ssh to be allowed to authenticate.
        use_sshpass = self.ssh_password is not None
        if a.ssh_batch and not use_sshpass:
            ssh_opts += ["-o", "BatchMode=yes"]

        env = os.environ.copy()
        if use_sshpass:
            env["SSHPASS"] = self.ssh_password
            # -o PreferredAuthentications speeds things up and makes failures
            # explicit (if the DPU refuses passwords we want to see that, not
            # hang trying gssapi etc.)
            ssh_opts += ["-o", "PreferredAuthentications=password",
                         "-o", "PubkeyAuthentication=no"]
            cmd = ["sshpass", "-e", "ssh", *ssh_opts, ssh_target, send_cmd]
        else:
            # Drop to the invoking user for ssh so it uses their ~/.ssh/ —
            # root usually has no keys set up for the DPU.
            cmd = ssh_user_prefix() + ["ssh", *ssh_opts, ssh_target, send_cmd]
            if ssh_user_prefix():
                print(f"[benchmark]   (ssh as '{os.environ['SUDO_USER']}' via sudo -u)")

        self.sender_log_fh = open(self.sender_log, "w")
        self.ssh_proc = subprocess.Popen(
            cmd,
            stdout=self.sender_log_fh,
            stderr=subprocess.STDOUT,
            env=env,
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

        # ── Clock-offset correction ──────────────────────────────────────
        # t1_ns comes from the DPU (sender wall clock) and t2/t3/t4 come
        # from the host (receiver wall clock). If the two machines' clocks
        # disagree by even a few ms, (t4 - t1) and (t2 - t1) can be negative,
        # which our downstream filter (`tb > ta`) throws out — producing
        # n=0 on e2e and ingest.
        #
        # We try TWO sources for the correction and pick whichever produces
        # sensible post-correction values:
        #   (1) NTP-style round-trip via clock_cal_server.py (self.clock_offset_ns)
        #   (2) EMPIRICAL: assume median ingestion latency is small and
        #       positive (tens of μs at most), so median(t2 - t1) should
        #       be ≈ 0 after correction. Any large median skew is clock
        #       drift, not real latency. Compute:
        #           empirical_offset = median(t1 - t2)
        #       and subtract it from every t1.
        #
        # NTP is checked first because it's the "proper" answer; but if NTP
        # calibration is obviously wrong (e.g. data-path blocked the UDP,
        # or the DPU clock drifted between calibration and capture), the
        # empirical number is the safety net.
        def _median(xs):
            xs = sorted(xs)
            m = len(xs) // 2
            return xs[m] if len(xs) % 2 else (xs[m - 1] + xs[m]) // 2

        def _percentile(xs, p):
            xs = sorted(xs)
            k = int(round(p / 100.0 * (len(xs) - 1)))
            return xs[k]

        if results:
            # Pre-correction snapshot (first row + median skew across a sample)
            r0 = results[0]
            t1_raw, t2_raw = r0["t1_ns"], r0["t2_ns"]
            # Stratified sample spanning the WHOLE run (not just the first
            # 5k rows). A first-5k-only sample would make constant-offset
            # corrections look as good as drift-aware ones because there's
            # no measurable drift in 100 ms.
            target_n = 5000
            step = max(1, len(results) // target_n)
            sample = results[::step][:target_n]
            skew_vals = [r["t1_ns"] - r["t2_ns"] for r in sample]
            pre_median_skew = _median(skew_vals)
            # Least-negative = smallest real latency = best estimate of pure
            # clock skew. 99th percentile for robustness against glitches.
            pre_tight_skew  = _percentile(skew_vals, 99)
            print(f"[benchmark] PRE-correction first row: "
                  f"t1={t1_raw} t2={t2_raw} "
                  f"t2-t1={(t2_raw - t1_raw)/1e9:+.6f} s")
            print(f"[benchmark] PRE-correction (t1-t2) over {len(sample)} rows: "
                  f"median={pre_median_skew/1e9:+.6f} s  "
                  f"p99={pre_tight_skew/1e9:+.6f} s  "
                  f"(p99 ≈ clock skew; median - p99 ≈ typical real latency)")

            # Candidate offsets
            ntp_off     = int(self.clock_offset_ns)   # from NTP calibration
            emp_med_off = int(pre_median_skew)        # biased — half rows go neg
            emp_min_off = int(pre_tight_skew)         # physical floor, post-min ≈ 0

            # Plausible latency bounds. t2-t1 (ingest) and t4-t1 (e2e) on
            # a working GPUNetIO data path are tens of μs — at most a few
            # ms on outliers. Anything in the hundreds of ms or seconds is
            # clock skew, not real latency. The scoring function rewards
            # offsets that land most rows inside these bounds.
            INGEST_MIN_NS =          0        # must be ≥ 0 (send before recv)
            INGEST_MAX_NS = 50_000_000        # 50 ms ceiling for ingest
            E2E_MAX_NS    = 100_000_000       # 100 ms ceiling for end-to-end

            def _score(off_ns):
                """Count rows where post-correction (t2-t1) and (t4-t1) are
                both in the plausible-latency range. This rejects offsets
                that leave t2 - t1 stuck at seconds (clock skew) even
                though t2 > t1 technically holds."""
                ok = 0
                for r in sample:
                    t1c = r["t1_ns"] - off_ns
                    ing = r["t2_ns"] - t1c
                    e2e = r["t4_ns"] - t1c
                    if (INGEST_MIN_NS <= ing <= INGEST_MAX_NS and
                            INGEST_MIN_NS <= e2e <= E2E_MAX_NS):
                        ok += 1
                return ok

            n_sample = len(sample)
            ntp_score      = _score(ntp_off)     if ntp_off     else -1
            emp_med_score  = _score(emp_med_off) if emp_med_off else -1
            emp_min_score  = _score(emp_min_off)
            zero_score     = _score(0)
            print(f"[benchmark] offset candidates (rows with 0 ≤ ingest ≤ 50ms "
                  f"AND 0 ≤ e2e ≤ 100ms, out of {n_sample}):")
            print(f"             no-correction:    score={zero_score:>6,}  off=0")
            if ntp_off:
                print(f"             NTP calibration:  score={ntp_score:>6,}  "
                      f"off={ntp_off/1e9:+.6f} s")
            print(f"             empirical median: score={emp_med_score:>6,}  "
                  f"off={emp_med_off/1e9:+.6f} s")
            print(f"             empirical p99:    score={emp_min_score:>6,}  "
                  f"off={emp_min_off/1e9:+.6f} s")

            # ── Drift-aware candidate: linear fit of (t1-t2) vs t2 ──────
            # If the DPU clock is running at a different rate from the host,
            # the offset isn't a constant — it changes during the run. Fit
            # a line  (t1 - t2) = a + b*t2  to the UPPER ENVELOPE (smallest
            # real latency) of (t1 - t2), then correct per packet:
            #     t1' = t1 - (a + b * t2)
            # This collapses linear drift to zero while leaving real
            # per-packet latency variation intact.
            #
            # The fit uses a sparse, high-percentile sample: we bin by t2
            # into 50 buckets, take each bucket's p99 of (t1-t2), and fit
            # an ordinary least-squares line through those 50 points.
            drift_slope = 0.0
            drift_intercept = 0
            drift_score = -1
            full_sample = results if len(results) <= 200_000 else results[::max(1, len(results)//200_000)]
            if len(full_sample) >= 1000:
                t2_min = full_sample[0]["t2_ns"]
                t2_max = full_sample[-1]["t2_ns"]
                if t2_max > t2_min:
                    n_bins = 50
                    bin_width = (t2_max - t2_min) / n_bins
                    bins = [[] for _ in range(n_bins)]
                    for r in full_sample:
                        idx = min(n_bins - 1,
                                  int((r["t2_ns"] - t2_min) / bin_width))
                        bins[idx].append(r["t1_ns"] - r["t2_ns"])
                    xs, ys = [], []
                    for i, b in enumerate(bins):
                        if len(b) >= 10:
                            xs.append(t2_min + (i + 0.5) * bin_width)
                            ys.append(_percentile(b, 99))
                    if len(xs) >= 5:
                        # OLS linear fit
                        n = len(xs)
                        mx = sum(xs) / n
                        my = sum(ys) / n
                        num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
                        den = sum((x - mx) ** 2 for x in xs)
                        if den > 0:
                            drift_slope = num / den
                            drift_intercept = int(my - drift_slope * mx)
                            # Score the drift-aware correction using the
                            # same plausible-latency criterion.
                            ok = 0
                            for r in sample:
                                t1c = r["t1_ns"] - (drift_intercept
                                      + int(drift_slope * r["t2_ns"]))
                                ing = r["t2_ns"] - t1c
                                e2e = r["t4_ns"] - t1c
                                if (INGEST_MIN_NS <= ing <= INGEST_MAX_NS and
                                        INGEST_MIN_NS <= e2e <= E2E_MAX_NS):
                                    ok += 1
                            drift_score = ok
                            print(f"             drift (linear fit): "
                                  f"score={drift_score:>6,}  "
                                  f"intercept={drift_intercept/1e9:+.6f} s  "
                                  f"slope={drift_slope*1e9:+.3f} ns/s "
                                  f"({len(xs)} bins fit)")

            # Pick the best. Prefer p99-based empirical (post-correction
            # min ≈ 0, which is what we want). Drift-aware wins if present.
            candidates = [("none", 0, 0, zero_score),
                          ("empirical_median", 0, emp_med_off, emp_med_score),
                          ("empirical_p99",    0, emp_min_off, emp_min_score)]
            if ntp_off:
                candidates.append(("ntp", 0, ntp_off, ntp_score))
            if drift_score >= 0:
                candidates.append(("drift_linear",
                                    drift_slope, drift_intercept,
                                    drift_score))
            candidates.sort(key=lambda c: c[3], reverse=True)
            chosen_label, chosen_slope, chosen_off, chosen_score = candidates[0]

            if chosen_score < n_sample // 2:
                print(f"[benchmark] WARN: best offset only fits "
                      f"{chosen_score}/{n_sample} rows — data may be corrupt")

            self.clock_offset_applied_ns = chosen_off
            self.clock_offset_slope      = chosen_slope
            self.clock_offset_source     = chosen_label
            if chosen_slope != 0.0:
                print(f"[benchmark] APPLYING drift-aware correction: "
                      f"{chosen_label}  intercept={chosen_off/1e9:+.6f} s  "
                      f"slope={chosen_slope*1e9:+.3f} ns/s")
            else:
                print(f"[benchmark] APPLYING offset: {chosen_label} "
                      f"({chosen_off/1e9:+.6f} s = {chosen_off} ns)")

            if chosen_off != 0 or chosen_slope != 0.0:
                for r in results:
                    correction = chosen_off + int(chosen_slope * r["t2_ns"])
                    r["t1_ns"] = r["t1_ns"] - correction

            # Post-correction verification — print real latency distribution
            # so the user can tell at a glance whether the offset was sane.
            r0 = results[0]
            post_ingest = sorted(r["t2_ns"] - r["t1_ns"]
                                 for r in sample
                                 if r["t2_ns"] > r["t1_ns"])
            post_e2e    = sorted(r["t4_ns"] - r["t1_ns"]
                                 for r in sample
                                 if r["t4_ns"] > r["t1_ns"])
            t4gt1 = sum(1 for r in results if r["t4_ns"] > r["t1_ns"])
            t2gt1 = sum(1 for r in results if r["t2_ns"] > r["t1_ns"])
            n = len(results)
            print(f"[benchmark] POST-correction first row: "
                  f"t1={r0['t1_ns']} t2={r0['t2_ns']} "
                  f"t2-t1={(r0['t2_ns'] - r0['t1_ns'])/1e3:+.3f} μs")
            if post_ingest:
                imin = post_ingest[0]
                imed = _percentile(post_ingest, 50)
                i95  = _percentile(post_ingest, 95)
                print(f"[benchmark] POST-correction ingest (t2-t1) over "
                      f"{len(post_ingest)} sample rows: "
                      f"min={imin/1e3:.2f} μs  p50={imed/1e3:.2f} μs  "
                      f"p95={i95/1e3:.2f} μs")
            if post_e2e:
                emin = post_e2e[0]
                emed = _percentile(post_e2e, 50)
                e95  = _percentile(post_e2e, 95)
                print(f"[benchmark] POST-correction e2e    (t4-t1) over "
                      f"{len(post_e2e)} sample rows: "
                      f"min={emin/1e3:.2f} μs  p50={emed/1e3:.2f} μs  "
                      f"p95={e95/1e3:.2f} μs")
            print(f"[benchmark] POST-correction filters: "
                  f"t2>t1 on {t2gt1:,}/{n:,} rows, "
                  f"t4>t1 on {t4gt1:,}/{n:,} rows")
        else:
            self.clock_offset_applied_ns = 0
            self.clock_offset_source     = "none"

        # Write CSV with corrected timestamps (single source of truth)
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

        # t1_ns was already corrected in collect() if calibration ran.
        # (we track both what was applied AND the raw NTP number for audit)
        off = self.clock_offset_applied_ns
        # (slope is stored on the runner too — used by summary.json)

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

        # ── Clock-INDEPENDENT ingest quality ─────────────────────────────
        # DPU↔host wall-clock drift (~925 μs/s) inflates ingest (t2-t1) and
        # e2e (t4-t1) by tens of ms in a 30 s run, even after drift_linear
        # correction. Jitter uses ONLY host-side t2_ns: for consecutive
        # tick_ids, jitter = (t2[N+1] - t2[N]) - (1e9 / rate_hz).
        # Positive = packet arrived later than ideal cadence; negative = early.
        expected_ns = 1_000_000_000.0 / a.rate if a.rate > 0 else 0.0
        jitter_us_signed = []
        window_by_tid = sorted(window, key=lambda r: r["tick_id"])
        prev = window_by_tid[0]
        for cur in window_by_tid[1:]:
            if cur["tick_id"] == prev["tick_id"] + 1:
                d = cur["t2_ns"] - prev["t2_ns"]
                jitter_us_signed.append((d - expected_ns) / 1000.0)
            prev = cur
        jitter_us_signed.sort()
        jitter_us_abs = sorted(abs(x) for x in jitter_us_signed)

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
            "clock_cal": {
                "applied":          bool(off) or bool(self.clock_offset_slope),
                "offset_ns":        int(off),
                "offset_slope":     float(self.clock_offset_slope),
                "offset_source":    self.clock_offset_source,
                "ntp_offset_ns":    int(self.clock_offset_ns),
                "oneway_ns_min":    int(self.clock_oneway_ns),
                "cal_ip":           self.clock_cal_ip,
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
            # Clock-independent ingest quality. Always trustworthy, regardless
            # of DPU↔host clock alignment. |p99| is the report metric for
            # "how consistently does GPUNetIO deliver at the target cadence".
            "ingest_jitter_us": {
                "n":                    len(jitter_us_signed),
                "expected_interval_us": (expected_ns / 1000.0) if expected_ns else None,
                "signed_p01":           pct(jitter_us_signed, 1),
                "signed_p50":           pct(jitter_us_signed, 50),
                "signed_p99":           pct(jitter_us_signed, 99),
                "abs_p50":              pct(jitter_us_abs, 50),
                "abs_p95":              pct(jitter_us_abs, 95),
                "abs_p99":              pct(jitter_us_abs, 99),
                "abs_p999":             pct(jitter_us_abs, 99.9),
                "abs_max":              jitter_us_abs[-1] if jitter_us_abs else float("nan"),
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
        print(f"  window: {r['warmup_sec']}s warmup + {r['duration_sec']}s measure")
        cal = s.get("clock_cal", {})
        if cal.get("applied"):
            src  = cal.get("offset_source", "?")
            off_s = cal["offset_ns"] / 1e9
            slope = cal.get("offset_slope", 0.0)
            ntp_s = cal.get("ntp_offset_ns", 0) / 1e9
            drift_line = ""
            if slope != 0.0:
                drift_line = f"  +  slope={slope*1e9:+.3f} ns/s (drift-corrected)"
            print(f"  clock offset: {off_s:+.6f} s  (source={src}){drift_line}")
            print(f"                NTP said {ntp_s:+.6f} s, "
                  f"min-RTT one-way ≈ {cal['oneway_ns_min']/1000:.2f} μs")
        else:
            print(f"  clock offset: NOT APPLIED — e2e/ingest are meaningless")
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
            tag = "  [cross-machine, clock-limited]" if key in ("ingest", "e2e") else ""
            print(f"  {name:14s}  {x['n']:>7,}  {fmt_us(x['mean'])}  "
                  f"{fmt_us(x['p50'])}  {fmt_us(x['p95'])}  "
                  f"{fmt_us(x['p99'])}  {fmt_us(x['p999'])}  {fmt_us(x['max'])}"
                  f"{tag}")
        # Clock-independent ingest quality — the trustworthy number.
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
        # (tier 1 runs the sender locally — ssh_proc.terminate() above already
        # killed it, and there's no DPU process to reach).
        a = self.args
        if not a.manual and a.ssh and a.tier != 1:
            env = os.environ.copy()
            if self.ssh_password is not None:
                env["SSHPASS"] = self.ssh_password
                kill_cmd = ["sshpass", "-e", "ssh",
                            "-o", "StrictHostKeyChecking=no",
                            "-o", "PreferredAuthentications=password",
                            "-o", "PubkeyAuthentication=no",
                            a.ssh, "pkill -f send_ticks.py || true"]
            else:
                kill_cmd = ssh_user_prefix() + [
                    "ssh", "-o", "BatchMode=yes", a.ssh,
                    "pkill -f send_ticks.py || true"]
            subprocess.run(
                kill_cmd,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5, env=env,
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

        if self.cal_ssh_proc and self.cal_ssh_proc.poll() is None:
            try:
                self.cal_ssh_proc.terminate()
                self.cal_ssh_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.cal_ssh_proc.kill()

        if self.rx_log_fh:
            self.rx_log_fh.close()
        if self.sender_log_fh:
            self.sender_log_fh.close()

        # 3) Anything stray (only kills what we own since we are sudo).
        subprocess.run(["pkill", "-f", "gpu_receiver"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-f", "cpu_receiver"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # ── Main sequence ────────────────────────────────────────────────────────
    def run(self):
        print(f"[benchmark] run → {self.run_dir}")
        try:
            self.start_receiver()
            self.calibrate_clock_offset()
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
        description="Run ONE T1/T4/T5 benchmark and emit bench.csv + summary.json.")
    p.add_argument("--tier", type=int, required=True, choices=[1, 4, 5],
                   help="1 = CPU naive (cpu_receiver, host-only); "
                        "4 = GPUNetIO host (gpu_receiver); "
                        "5 = GPUNetIO + DPU (gpu_receiver, DPU-side sender)")
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
    p.add_argument("--ask-pass", action="store_true",
                   help="Prompt once for the DPU ssh password and use sshpass "
                        "for every ssh call. Requires `sshpass` to be installed.")

    # Clock calibration
    p.add_argument("--calibrate", dest="calibrate", action="store_true",
                   default=True,
                   help="Estimate DPU↔host clock offset before the run (default on)")
    p.add_argument("--no-calibrate", dest="calibrate", action="store_false",
                   help="Skip clock calibration (e2e/ingest will be NaN).")
    p.add_argument("--cal-samples", type=int, default=200,
                   help="Number of NTP-style round-trips for calibration")
    p.add_argument("--cal-port", type=int, default=6006,
                   help="UDP port for clock_cal_server.py on DPU")
    p.add_argument("--cal-ip", default=None,
                   help="IP to reach clock_cal_server on the DPU. "
                        "Default: host-part of --ssh (mgmt path), which is "
                        "known to work. Data-path IPs can work too but some "
                        "OVS/br-pf1 configs drop unicast.")
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

    if args.ask_pass and not args.manual:
        if shutil.which("sshpass") is None:
            sys.exit("[benchmark] ERROR: --ask-pass requires `sshpass`. "
                     "Install with: sudo apt-get install -y sshpass")
        runner.ssh_password = getpass.getpass(
            f"DPU ssh password for {args.ssh}: ")
        if not runner.ssh_password:
            sys.exit("[benchmark] empty password — aborting")

    summary = runner.run()
    sys.exit(0 if summary else 1)


if __name__ == "__main__":
    main()
