#!/usr/bin/env python3
"""
analyze.py — Visualize a single benchmark run produced by scripts/benchmark.py.

Reads   results/single/<run_name>/bench.csv
        results/single/<run_name>/summary.json

Writes  results/single/<run_name>/plots/
            01_latency_hist.png     — e2e + per-stage histograms
            02_stage_stack.png      — stacked bar (p50/p95/p99) per stage
            03_latency_timeline.png — tick_id vs e2e latency (detects tail drift)
            04_throughput.png       — receive rate over time
            05_drop_map.png         — gaps in tick_id sequence
            06_ingest_jitter.png    — clock-INDEPENDENT ingest quality
                                       (host-only t2 inter-arrival; does NOT
                                       depend on DPU↔host clock alignment)

NOTE on cross-machine latency: ingest (t2-t1) and e2e (t4-t1) cross the
DPU↔host boundary, so they are limited by the ~925 μs/s DPU wall-clock
drift vs host. The benchmark.py drift_linear correction removes first-order
slope, but residual non-linear drift means these figures carry a noise
floor of tens of ms and should be read as upper bounds. The jitter plot
(#06) uses only host-side t2 timestamps and is the definitive "ingest
quality" metric for report purposes — see docs/SPECIFICATION.md §12.5.

Usage:
    python3 scripts/analyze.py results/single/T4_50000hz_rep1_20260416_143022
    python3 scripts/analyze.py --latest                   # newest run
    python3 scripts/analyze.py --run T4_50000hz_rep1_...  # by run name
"""

import argparse
import csv
import json
import sys
from pathlib import Path

import numpy as np
import matplotlib
matplotlib.use("Agg")  # no display on headless host
import matplotlib.pyplot as plt

REPO_ROOT   = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO_ROOT / "results" / "single"


# ─────────────────────────────────────────────────────────────────────────────
# I/O
# ─────────────────────────────────────────────────────────────────────────────

def resolve_run_dir(args) -> Path:
    if args.run_dir:
        p = Path(args.run_dir).resolve()
        if not p.exists():
            sys.exit(f"[analyze] run dir not found: {p}")
        return p
    if args.run:
        p = RESULTS_DIR / args.run
        if not p.exists():
            sys.exit(f"[analyze] run not found: {p}")
        return p
    if args.latest:
        candidates = sorted(RESULTS_DIR.glob("T*"),
                            key=lambda q: q.stat().st_mtime)
        if not candidates:
            sys.exit(f"[analyze] no runs in {RESULTS_DIR}")
        return candidates[-1]
    sys.exit("[analyze] pass a run directory, --run NAME, or --latest")


def load_bench_csv(run_dir: Path) -> np.ndarray:
    csv_path = run_dir / "bench.csv"
    if not csv_path.exists():
        sys.exit(f"[analyze] missing bench.csv in {run_dir}")

    rows = []
    with open(csv_path, newline="") as f:
        for r in csv.DictReader(f):
            rows.append((
                int(r["recv_ns"]), int(r["tick_id"]),
                int(r["t1_ns"]),   int(r["t2_ns"]),
                int(r["t3_ns"]),   int(r["t4_ns"]),
                int(r["tier"]),    int(r["dropped"]),
            ))
    if not rows:
        sys.exit(f"[analyze] empty bench.csv in {run_dir}")

    dtype = np.dtype([
        ("recv_ns", "u8"), ("tick_id", "u8"),
        ("t1_ns", "u8"),   ("t2_ns", "u8"),
        ("t3_ns", "u8"),   ("t4_ns", "u8"),
        ("tier", "u1"),    ("dropped", "u1"),
    ])
    return np.array(rows, dtype=dtype)


def load_summary(run_dir: Path) -> dict:
    sp = run_dir / "summary.json"
    if not sp.exists():
        print(f"[analyze] WARN: no summary.json in {run_dir} — generating from CSV only")
        return {}
    with open(sp) as f:
        return json.load(f)


def filter_to_window(data: np.ndarray, summary: dict) -> np.ndarray:
    """Apply the same warmup/duration window benchmark.py used."""
    if not summary:
        return data
    warmup   = summary["run"]["warmup_sec"]
    duration = summary["run"]["duration_sec"]
    first_t1 = int(data[0]["t1_ns"])
    start = first_t1 + warmup * 1_000_000_000
    end   = first_t1 + (warmup + duration) * 1_000_000_000
    mask  = (data["t1_ns"] >= start) & (data["t1_ns"] < end)
    return data[mask]


# ─────────────────────────────────────────────────────────────────────────────
# Plots
# ─────────────────────────────────────────────────────────────────────────────

def plot_latency_hist(data: np.ndarray, run_name: str, out: Path):
    e2e     = (data["t4_ns"].astype(np.int64) - data["t1_ns"].astype(np.int64)) / 1000.0
    ingest  = (data["t2_ns"].astype(np.int64) - data["t1_ns"].astype(np.int64)) / 1000.0
    compute = (data["t3_ns"].astype(np.int64) - data["t2_ns"].astype(np.int64)) / 1000.0
    egress  = (data["t4_ns"].astype(np.int64) - data["t3_ns"].astype(np.int64)) / 1000.0

    # Drop obvious junk (zero timestamps etc.)
    def clean(arr):
        arr = arr[np.isfinite(arr)]
        return arr[(arr > 0) & (arr < 1e7)]  # < 10 seconds

    series = [
        ("e2e  (t4 − t1)", clean(e2e)),
        ("ingest (t2 − t1)", clean(ingest)),
        ("compute (t3 − t2)", clean(compute)),
        ("egress (t4 − t3)", clean(egress)),
    ]

    fig, axes = plt.subplots(2, 2, figsize=(12, 8))
    for ax, (label, arr) in zip(axes.flat, series):
        if len(arr) == 0:
            ax.set_title(f"{label}  (no data)")
            continue
        # Clip to p99.9 so the histogram isn't ruined by tail outliers
        clip = np.percentile(arr, 99.9)
        ax.hist(np.clip(arr, None, clip), bins=80, alpha=0.85,
                color="#3a7ca5", edgecolor="white", linewidth=0.3)
        p50, p95, p99 = np.percentile(arr, [50, 95, 99])
        for x, c, lbl in [(p50, "#4CAF50", "p50"),
                          (p95, "#FF9800", "p95"),
                          (p99, "#F44336", "p99")]:
            ax.axvline(x, color=c, linestyle="--", linewidth=1.2,
                       label=f"{lbl} = {x:.1f} μs")
        ax.set_title(label, fontsize=11)
        ax.set_xlabel("latency (μs)")
        ax.set_ylabel("count")
        ax.legend(loc="upper right", fontsize=9)
        ax.grid(alpha=0.25)

    fig.suptitle(f"Latency distributions — {run_name}", fontsize=13)
    fig.tight_layout()
    fig.savefig(out, dpi=130)
    plt.close(fig)
    print(f"  wrote {out}")


def plot_stage_stack(data: np.ndarray, run_name: str, out: Path):
    ingest  = (data["t2_ns"].astype(np.int64) - data["t1_ns"].astype(np.int64)) / 1000.0
    compute = (data["t3_ns"].astype(np.int64) - data["t2_ns"].astype(np.int64)) / 1000.0
    egress  = (data["t4_ns"].astype(np.int64) - data["t3_ns"].astype(np.int64)) / 1000.0

    stages = [("ingest (t2-t1)", ingest, "#3a7ca5"),
              ("compute (t3-t2)", compute, "#f4a261"),
              ("egress (t4-t3)", egress, "#e76f51")]

    percentiles = [50, 95, 99, 99.9]
    values = np.zeros((len(stages), len(percentiles)))
    for i, (_, arr, _) in enumerate(stages):
        clean = arr[np.isfinite(arr)]
        clean = clean[(clean > 0) & (clean < 1e7)]
        if len(clean):
            values[i] = np.percentile(clean, percentiles)

    fig, ax = plt.subplots(figsize=(10, 6))
    x = np.arange(len(percentiles))
    bottom = np.zeros(len(percentiles))
    for i, (name, _, color) in enumerate(stages):
        ax.bar(x, values[i], bottom=bottom, label=name, color=color,
               edgecolor="white", linewidth=1.0)
        for xi, (h, b) in enumerate(zip(values[i], bottom)):
            if h > 0:
                ax.text(xi, b + h / 2, f"{h:.1f}",
                        ha="center", va="center", fontsize=9, color="white",
                        fontweight="bold")
        bottom += values[i]

    ax.set_xticks(x)
    ax.set_xticklabels([f"p{p}" for p in percentiles])
    ax.set_ylabel("latency (μs)")
    ax.set_title(f"Stage breakdown — {run_name}")
    ax.legend(loc="upper left")
    ax.grid(alpha=0.25, axis="y")
    fig.tight_layout()
    fig.savefig(out, dpi=130)
    plt.close(fig)
    print(f"  wrote {out}")


def plot_latency_timeline(data: np.ndarray, run_name: str, out: Path):
    e2e = (data["t4_ns"].astype(np.int64) - data["t1_ns"].astype(np.int64)) / 1000.0
    # Seconds relative to first tick's t1
    first_t1 = data["t1_ns"][0]
    t_sec = (data["t1_ns"].astype(np.int64) - int(first_t1)) / 1e9

    mask = (e2e > 0) & (e2e < 1e7) & np.isfinite(e2e)
    e2e = e2e[mask]; t_sec = t_sec[mask]

    fig, ax = plt.subplots(figsize=(12, 5))
    ax.scatter(t_sec, e2e, s=2, alpha=0.35, color="#3a7ca5")
    if len(e2e):
        for pct, color, label in [(50, "#4CAF50", "p50"),
                                  (99, "#F44336", "p99")]:
            y = np.percentile(e2e, pct)
            ax.axhline(y, color=color, linestyle="--", linewidth=1.0,
                       label=f"{label} = {y:.1f} μs")
    ax.set_xlabel("time since first tick (s)")
    ax.set_ylabel("e2e latency (μs)")
    ax.set_title(f"E2E latency over time — {run_name}")
    ax.set_yscale("log")
    ax.legend(loc="upper right")
    ax.grid(alpha=0.25, which="both")
    fig.tight_layout()
    fig.savefig(out, dpi=130)
    plt.close(fig)
    print(f"  wrote {out}")


def plot_throughput(data: np.ndarray, run_name: str, out: Path, bin_ms: int = 100):
    first_t1 = data["t1_ns"][0]
    t_sec = (data["t1_ns"].astype(np.int64) - int(first_t1)) / 1e9
    if len(t_sec) == 0 or t_sec.max() <= 0:
        print("  [plot_throughput] insufficient data — skip")
        return

    bins = np.arange(0, t_sec.max() + bin_ms / 1000.0, bin_ms / 1000.0)
    counts, edges = np.histogram(t_sec, bins=bins)
    rate_hz = counts / (bin_ms / 1000.0)
    centers = 0.5 * (edges[:-1] + edges[1:])

    fig, ax = plt.subplots(figsize=(12, 5))
    ax.plot(centers, rate_hz, color="#3a7ca5", linewidth=1.0)
    ax.fill_between(centers, rate_hz, alpha=0.2, color="#3a7ca5")
    ax.set_xlabel("time since first tick (s)")
    ax.set_ylabel(f"receive rate (ticks/s, {bin_ms} ms bins)")
    ax.set_title(f"Throughput over time — {run_name}")
    ax.grid(alpha=0.25)
    fig.tight_layout()
    fig.savefig(out, dpi=130)
    plt.close(fig)
    print(f"  wrote {out}")


def compute_ingest_jitter(data: np.ndarray, rate_hz: int):
    """Clock-INDEPENDENT ingest quality.

    Computes inter-arrival jitter on host-side t2 timestamps only — the DPU
    clock is NOT involved, so this metric is immune to the cross-machine
    clock drift that inflates (t2-t1) ingest latency.

    For consecutive tick_ids N, N+1:
        observed_interval = t2[N+1] - t2[N]                (host ns)
        expected_interval = 1e9 / rate_hz                  (host ns)
        jitter            = observed - expected            (signed)

    Returns (jitter_us, cum_drift_us, t_sec_for_drift). All three arrays are
    aligned to the **consecutive-pair** subset so they can be plotted directly.
    Empty arrays are returned when rate_hz is unknown or data is too short.
    """
    empty = (np.array([], dtype=np.float64),) * 3
    if rate_hz <= 0 or len(data) < 2:
        return empty

    order = np.argsort(data["tick_id"])
    tids  = data["tick_id"][order].astype(np.int64)
    t2    = data["t2_ns"][order].astype(np.int64)

    d_tid = np.diff(tids)
    d_t2  = np.diff(t2)
    mask  = d_tid == 1                 # consecutive ids only (skip drops)
    if not mask.any():
        return empty

    expected_ns = 1_000_000_000.0 / float(rate_hz)
    jitter_us   = (d_t2[mask].astype(np.float64) - expected_ns) / 1000.0

    # Cumulative drift: how far the receiver's arrival clock has wandered
    # from the ideal cadence since the first tick.
    idx_keep = np.flatnonzero(mask) + 1     # t2 index for every kept sample
    t2_kept  = t2[idx_keep]
    tid_kept = tids[idx_keep]
    t_sec    = (t2_kept - t2_kept[0]) / 1e9
    expected_elapsed_s = (tid_kept - tid_kept[0]).astype(np.float64) * expected_ns / 1e9
    cum_drift_us = (t_sec - expected_elapsed_s) * 1e6

    return jitter_us, cum_drift_us, t_sec


def plot_ingest_jitter(data: np.ndarray, summary: dict, run_name: str, out: Path):
    """Plot 06 — clock-independent ingest quality."""
    rate_hz = (summary.get("run", {}) or {}).get("rate_hz", 0)
    jitter_us, cum_drift_us, t_sec = compute_ingest_jitter(data, rate_hz)
    if len(jitter_us) == 0:
        print("  [plot_ingest_jitter] insufficient data (need rate_hz + >=2 consecutive ticks) — skip")
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    # ── Left: jitter histogram, symmetric clip for readability ──────────
    clip = max(abs(np.percentile(jitter_us, 0.1)),
               abs(np.percentile(jitter_us, 99.9)))
    clip = max(clip, 1.0)  # avoid zero-width axis on a perfectly-timed sender
    ax1.hist(np.clip(jitter_us, -clip, clip),
             bins=120, color="#6a4c93", edgecolor="white", linewidth=0.3)
    abs_j = np.abs(jitter_us)
    ap50, ap95, ap99 = np.percentile(abs_j, [50, 95, 99])
    ax1.axvline(0, color="black", linestyle="-", linewidth=0.8, alpha=0.5)
    for mag, c, lbl in [(ap50, "#4CAF50", f"|p50| = {ap50:.2f} μs"),
                        (ap95, "#FF9800", f"|p95| = {ap95:.2f} μs"),
                        (ap99, "#F44336", f"|p99| = {ap99:.2f} μs")]:
        ax1.axvline(-mag, color=c, linestyle="--", linewidth=1.0)
        ax1.axvline(+mag, color=c, linestyle="--", linewidth=1.0, label=lbl)
    expected_us = 1e6 / rate_hz
    ax1.set_xlabel("inter-arrival jitter (μs)  [host-only, clock-independent]")
    ax1.set_ylabel("count")
    ax1.set_title(f"Ingest jitter — expected interval {expected_us:.2f} μs @ {rate_hz:,} Hz")
    ax1.legend(loc="upper right", fontsize=9)
    ax1.grid(alpha=0.25)

    # ── Right: cumulative arrival drift vs ideal cadence ─────────────────
    # Downsample line for huge runs so rendering stays snappy.
    stride = max(1, len(t_sec) // 10000)
    ax2.plot(t_sec[::stride], cum_drift_us[::stride],
             color="#6a4c93", linewidth=0.8)
    ax2.axhline(0, color="black", linewidth=0.5, alpha=0.5)
    ax2.set_xlabel("time since first tick (s)")
    ax2.set_ylabel("cumulative arrival drift (μs)\n"
                   "(< 0 = receiver ahead of schedule, > 0 = behind)")
    ax2.set_title("Cumulative ingest drift — receiver vs ideal cadence")
    ax2.grid(alpha=0.25)

    fig.suptitle(f"Ingest quality (clock-independent) — {run_name}", fontsize=12)
    fig.tight_layout()
    fig.savefig(out, dpi=130)
    plt.close(fig)
    print(f"  wrote {out}")


def plot_drop_map(data: np.ndarray, run_name: str, out: Path):
    tids = np.sort(data["tick_id"].astype(np.int64))
    if len(tids) < 2:
        print("  [plot_drop_map] not enough ticks — skip")
        return
    expected = np.arange(tids[0], tids[-1] + 1, dtype=np.int64)
    received = np.isin(expected, tids)

    # Bin into ~400 cells for display
    n_bins = min(400, len(expected))
    bin_size = max(1, len(expected) // n_bins)
    truncated = (len(expected) // bin_size) * bin_size
    grid = received[:truncated].reshape(-1, bin_size).mean(axis=1)

    total_expected = len(expected)
    total_received = int(received.sum())
    drop_rate = 1.0 - total_received / total_expected

    fig, ax = plt.subplots(figsize=(12, 3.2))
    ax.imshow(grid.reshape(1, -1), aspect="auto",
              cmap="RdYlGn", vmin=0, vmax=1,
              extent=[int(expected[0]), int(expected[-1]), 0, 1])
    ax.set_yticks([])
    ax.set_xlabel("tick_id")
    ax.set_title(f"Delivery map — {run_name}   "
                 f"(expected={total_expected:,}  received={total_received:,}  "
                 f"drop={drop_rate*100:.3f}%)")
    cbar = fig.colorbar(ax.images[0], ax=ax, orientation="horizontal",
                        pad=0.35, fraction=0.08)
    cbar.set_label("fraction delivered per bin (1.0 = all delivered)")
    fig.tight_layout()
    fig.savefig(out, dpi=130)
    plt.close(fig)
    print(f"  wrote {out}")


# ─────────────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="Visualize a single benchmark run.")
    p.add_argument("run_dir", nargs="?",
                   help="Path to run dir (results/single/<run_name>/)")
    p.add_argument("--run", help="Run name under results/single/")
    p.add_argument("--latest", action="store_true",
                   help="Use the most recent run under results/single/")
    p.add_argument("--no-window", action="store_true",
                   help="Plot the entire capture, ignoring warmup/duration window")
    args = p.parse_args()

    run_dir = resolve_run_dir(args)
    run_name = run_dir.name
    print(f"[analyze] {run_dir}")

    data    = load_bench_csv(run_dir)
    summary = load_summary(run_dir)
    if not args.no_window:
        data = filter_to_window(data, summary)
    if len(data) == 0:
        sys.exit("[analyze] no rows left after windowing")

    plots_dir = run_dir / "plots"
    plots_dir.mkdir(exist_ok=True)

    plot_latency_hist(data, run_name, plots_dir / "01_latency_hist.png")
    plot_stage_stack(data, run_name, plots_dir / "02_stage_stack.png")
    plot_latency_timeline(data, run_name, plots_dir / "03_latency_timeline.png")
    plot_throughput(data, run_name, plots_dir / "04_throughput.png")
    plot_drop_map(data, run_name, plots_dir / "05_drop_map.png")
    plot_ingest_jitter(data, summary, run_name, plots_dir / "06_ingest_jitter.png")

    # Small text summary printed so the user can sanity-check without opening PNGs.
    e2e = (data["t4_ns"].astype(np.int64) - data["t1_ns"].astype(np.int64)) / 1000.0
    e2e = e2e[(e2e > 0) & (e2e < 1e7)]
    if len(e2e):
        p50, p95, p99 = np.percentile(e2e, [50, 95, 99])
        print(f"[analyze] e2e  n={len(e2e):,}  "
              f"p50={p50:.1f}μs  p95={p95:.1f}μs  p99={p99:.1f}μs  "
              f"max={e2e.max():.1f}μs  (cross-machine, clock-limited)")

    # Clock-independent ingest quality — this is the trustworthy number.
    rate_hz = (summary.get("run", {}) or {}).get("rate_hz", 0)
    jitter_us, _, _ = compute_ingest_jitter(data, rate_hz)
    if len(jitter_us):
        abs_j = np.abs(jitter_us)
        p50, p95, p99 = np.percentile(abs_j, [50, 95, 99])
        print(f"[analyze] ingest jitter  n={len(jitter_us):,}  "
              f"|p50|={p50:.2f}μs  |p95|={p95:.2f}μs  |p99|={p99:.2f}μs  "
              f"(host-only, clock-independent)")
    print(f"[analyze] plots → {plots_dir}")


if __name__ == "__main__":
    main()
