#!/usr/bin/env python3
"""
plot_benchmark.py — produce FYP-presentation plots from a benchmark CSV.

Reads the CSV emitted by bin/benchmark_harness (one row per tier/rate/rep)
and writes 6 PNGs to results/plots_<timestamp>/:

  01_compute_latency.png    — per-tier per-tick GPU compute p50/p99 vs rate
  02_drop_curve.png         — sender-vs-processed drop rate vs offered rate
  03_throughput.png         — achieved tick throughput vs offered rate
  04_signal_rate.png        — total + actionable signal rate vs offered rate
  05_stage_breakdown.png    — stacked p50 ingress/compute/egress per tier @ 100k Hz
  06_e2e_latency.png        — receiver-ingress-to-output p50/p99

Current benchmark definition for T1-T4 uses sender-side T1 in TickMessage,
then reconciles sender/receiver clocks in the harness:
  ingress = T2 - T1
  compute = T3 - T2
  e2e = T4 - T1

Usage:
  python3 scripts/plot_benchmark.py results/benchmark_20260428_193500.csv
  python3 scripts/plot_benchmark.py --latest                 # newest CSV
  python3 scripts/plot_benchmark.py --out results/my_plots   # custom outdir
"""

from __future__ import annotations
import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path
from datetime import datetime

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO_ROOT / "results"

TIER_LABEL = {
    1: "T1  CPU recvfrom (3 copies)",
    2: "T2  DPDK PMD (2 copies)",
    3: "T3  GPU RDMA (0 copies)",
    4: "T4  DOCA GPUNetIO (0 copies)",
}
TIER_COLOR = {
    1: "#e76f51",  # orange-red
    2: "#f4a261",  # sand
    3: "#2a9d8f",  # teal
    4: "#264653",  # dark
}
TIER_MARKER = {1: "o", 2: "s", 3: "^", 4: "D"}


# ─── I/O ──────────────────────────────────────────────────────────────────────

def load(csv_path: Path):
    rows = []
    with open(csv_path) as f:
        for r in csv.DictReader(f):
            rows.append({
                "tier":     int(r["tier"]),
                "rate":     int(r["rate_hz"]),
                "rep":      int(r["repetition"]),
                "n_ticks":  int(r["n_ticks"]),
                "drop":     float(r["drop_rate"]),
                "e2e_p50":      float(r["e2e_p50_us"]),
                "e2e_p99":      float(r["e2e_p99_us"]),
                "ingest_p50":   float(r["ingest_p50_us"]),
                "ingest_p99":   float(r["ingest_p99_us"]),
                "compute_p50":  float(r["compute_p50_us"]),
                "compute_p99":  float(r["compute_p99_us"]),
                "throughput":   float(r["throughput_per_sec"]),
                "sig_total":    float(r.get("signals_total_per_sec", 0.0)),
                "sig_actionable": float(r.get("signals_actionable_per_sec", 0.0)),
                "clock_rtt_us": float(r.get("clock_rtt_us", 0.0) or 0.0),
            })
    return rows


def cross_host_noise_floor_us(rows) -> float:
    """Worst-case half-RTT across all runs in the CSV.
    Cross-machine ingest/e2e measurements below this floor are not
    statistically meaningful — they're inside the SSH-clock-sample noise. """
    rtts = [r["clock_rtt_us"] for r in rows if r.get("clock_rtt_us", 0) > 0]
    if not rtts:
        return 0.0
    return max(rtts) / 2.0


def aggregate(rows):
    """Group by (tier, rate), median across reps."""
    grouped = defaultdict(list)
    for r in rows:
        grouped[(r["tier"], r["rate"])].append(r)
    out = {}
    for key, runs in grouped.items():
        out[key] = {
            k: float(np.median([r[k] for r in runs]))
            for k in ("drop", "e2e_p50", "e2e_p99",
                     "ingest_p50", "ingest_p99",
                     "compute_p50", "compute_p99",
                     "throughput", "sig_total", "sig_actionable")
        }
    return out


def tier_series(agg, tier, key):
    rates = sorted(r for (t, r) in agg.keys() if t == tier)
    return rates, [agg[(tier, r)][key] for r in rates]


# ─── Plot helpers ─────────────────────────────────────────────────────────────

def setup_axes(ax, title, xlabel, ylabel, xlog=True, ylog=False):
    ax.set_title(title, fontsize=12, pad=10)
    ax.set_xlabel(xlabel, fontsize=10)
    ax.set_ylabel(ylabel, fontsize=10)
    if xlog:
        ax.set_xscale("log")
        ax.xaxis.set_major_formatter(mticker.FuncFormatter(
            lambda v, _: f"{int(v/1000)}k" if v < 1e6 else f"{v/1e6:g}M"))
    if ylog:
        ax.set_yscale("log")
    ax.grid(True, which="both", alpha=0.25)
    ax.tick_params(labelsize=9)


def save(fig, outdir: Path, name: str):
    path = outdir / name
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  → {path.relative_to(REPO_ROOT)}")


# ─── Plot functions ───────────────────────────────────────────────────────────

def plot_compute_latency(agg, outdir):
    """Per-tick GPU compute comparison."""
    fig, ax = plt.subplots(figsize=(8, 5))
    for tier in sorted({t for (t, _) in agg.keys()}):
        rates, p50 = tier_series(agg, tier, "compute_p50")
        _,     p99 = tier_series(agg, tier, "compute_p99")
        c, m = TIER_COLOR[tier], TIER_MARKER[tier]
        ax.plot(rates, p50, color=c, marker=m, linewidth=2,
                label=f"{TIER_LABEL[tier]}  p50")
        ax.plot(rates, p99, color=c, marker=m, linestyle="--",
                alpha=0.6, label=f"{TIER_LABEL[tier]}  p99")
    setup_axes(ax, "Per-tick GPU compute latency",
               "Offered tick rate (Hz)", "Per-tick compute latency (µs)")
    ax.legend(fontsize=8, loc="upper left", framealpha=0.95)
    save(fig, outdir, "01_compute_latency.png")


def plot_drop_curve(agg, outdir):
    """Sender-vs-processed completion loss."""
    fig, ax = plt.subplots(figsize=(8, 5))
    for tier in sorted({t for (t, _) in agg.keys()}):
        rates, drop = tier_series(agg, tier, "drop")
        ax.plot(rates, [d * 100 for d in drop],
                color=TIER_COLOR[tier], marker=TIER_MARKER[tier],
                linewidth=2, label=TIER_LABEL[tier])
    setup_axes(ax, "Completion loss vs offered rate",
               "Offered tick rate (Hz)", "Unprocessed ticks / sent ticks (%)")
    ax.set_ylim(bottom=-0.5)
    ax.legend(fontsize=9, loc="upper left", framealpha=0.95)
    save(fig, outdir, "02_drop_curve.png")


def plot_throughput(agg, outdir):
    """Achieved vs offered — where the line bends down = saturation."""
    fig, ax = plt.subplots(figsize=(8, 5))
    all_rates = sorted({r for (_, r) in agg.keys()})
    ax.plot(all_rates, all_rates, color="black", linestyle=":",
            linewidth=1, label="Ideal y=x")
    for tier in sorted({t for (t, _) in agg.keys()}):
        rates, tput = tier_series(agg, tier, "throughput")
        ax.plot(rates, tput, color=TIER_COLOR[tier],
                marker=TIER_MARKER[tier], linewidth=2, label=TIER_LABEL[tier])
    setup_axes(ax, "Achieved tick throughput vs offered rate",
               "Offered tick rate (Hz)", "Achieved throughput (ticks/sec)",
               xlog=True, ylog=True)
    ax.legend(fontsize=9, loc="upper left", framealpha=0.95)
    save(fig, outdir, "03_throughput.png")


def plot_signal_rate(agg, outdir):
    """Useful work output of the pipeline (post-kernel)."""
    fig, axes = plt.subplots(1, 2, figsize=(13, 5), sharey=False)

    for tier in sorted({t for (t, _) in agg.keys()}):
        rates, sig_t = tier_series(agg, tier, "sig_total")
        _,     sig_a = tier_series(agg, tier, "sig_actionable")
        c, m = TIER_COLOR[tier], TIER_MARKER[tier]
        axes[0].plot(rates, sig_t, color=c, marker=m, linewidth=2,
                     label=TIER_LABEL[tier])
        axes[1].plot(rates, sig_a, color=c, marker=m, linewidth=2,
                     label=TIER_LABEL[tier])

    setup_axes(axes[0], "Total signals/sec (post-kernel emission)",
               "Offered tick rate (Hz)", "SignalResult emissions/sec",
               xlog=True, ylog=True)
    setup_axes(axes[1], "Actionable signals/sec (signal ≠ 0)",
               "Offered tick rate (Hz)", "Buy/sell decisions/sec",
               xlog=True, ylog=True)
    axes[0].legend(fontsize=8, loc="upper left", framealpha=0.95)
    save(fig, outdir, "04_signal_rate.png")


def plot_stage_breakdown(agg, outdir, target_rate=100000):
    """Stacked bar of where time goes per tier at a fixed rate."""
    rates_avail = sorted({r for (_, r) in agg.keys()})
    if target_rate not in rates_avail:
        target_rate = min(rates_avail, key=lambda r: abs(r - target_rate))

    tiers = sorted({t for (t, _) in agg.keys()})
    ingest  = [agg[(t, target_rate)]["ingest_p50"]  for t in tiers]
    compute = [agg[(t, target_rate)]["compute_p50"] for t in tiers]
    # egress = e2e - ingress - compute
    e2e_v   = [agg[(t, target_rate)]["e2e_p50"]     for t in tiers]
    egress  = [max(0.0, e2e_v[i] - ingest[i] - compute[i]) for i in range(len(tiers))]

    fig, ax = plt.subplots(figsize=(8, 5))
    labels = [TIER_LABEL[t] for t in tiers]
    x = np.arange(len(tiers))
    ax.bar(x, ingest,  label="Ingress (T2−T1)", color="#cccccc")
    ax.bar(x, compute, bottom=ingest, label="Compute (T3−T2)",
           color="#2a9d8f")
    ax.bar(x, egress,  bottom=[i+c for i, c in zip(ingest, compute)],
           label="Egress (T4−T3)", color="#264653")
    ax.set_xticks(x)
    ax.set_xticklabels([l.split(" ")[0] for l in labels], fontsize=9)
    ax.set_title(f"p50 stage breakdown @ {target_rate:,} Hz "
                 f"(receiver-side single clock)", fontsize=11, pad=10)
    ax.set_ylabel("Latency (µs)", fontsize=10)
    ax.grid(True, axis="y", alpha=0.25)
    ax.legend(fontsize=9, loc="upper right")
    save(fig, outdir, "05_stage_breakdown.png")


def _shade_noise_floor(ax, floor_us: float):
    """Draw a translucent band over latency values below the cross-host
    measurement floor, so readers see at a glance which numbers are
    statistically meaningful and which sit inside the SSH-clock-sample noise.
    No-op when floor_us == 0 (local-sender runs)."""
    if floor_us <= 0:
        return
    ax.axhspan(0.0, floor_us, color="#cccccc", alpha=0.25, zorder=0)
    ax.axhline(floor_us, color="#888888", linestyle=":", linewidth=1, zorder=0)
    ax.text(0.99, floor_us, f"  cross-host noise floor ≈ {floor_us:.0f} µs",
            transform=ax.get_yaxis_transform(),
            ha="right", va="bottom", fontsize=8, color="#555555")


def plot_e2e_latency(agg, outdir, noise_floor_us: float = 0.0):
    """Receiver-ingress-to-output latency, with cross-host noise floor band."""
    fig, ax = plt.subplots(figsize=(8, 5))
    for tier in sorted({t for (t, _) in agg.keys()}):
        rates, p50 = tier_series(agg, tier, "e2e_p50")
        _,     p99 = tier_series(agg, tier, "e2e_p99")
        c, m = TIER_COLOR[tier], TIER_MARKER[tier]
        ax.plot(rates, p50, color=c, marker=m, linewidth=2,
                label=f"{TIER_LABEL[tier]}  p50")
        ax.plot(rates, p99, color=c, marker=m, linestyle="--",
                alpha=0.6, label=f"{TIER_LABEL[tier]}  p99")
    setup_axes(ax,
               "End-to-end latency (receiver ingress → output)",
               "Offered tick rate (Hz)", "E2E latency T4−T1 (µs)",
               xlog=True, ylog=True)
    _shade_noise_floor(ax, noise_floor_us)
    ax.legend(fontsize=8, loc="upper left", framealpha=0.95)
    save(fig, outdir, "06_e2e_latency.png")


# ─── Main ─────────────────────────────────────────────────────────────────────

def find_latest():
    csvs = sorted(RESULTS_DIR.glob("benchmark_*.csv"))
    if not csvs:
        print("No benchmark CSVs found in results/", file=sys.stderr)
        sys.exit(1)
    return csvs[-1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="?", help="benchmark CSV from run_benchmark.sh")
    ap.add_argument("--latest", action="store_true", help="use newest results/benchmark_*.csv")
    ap.add_argument("--out", help="output directory (default: results/plots_<ts>/)")
    args = ap.parse_args()

    if args.latest or not args.csv:
        csv_path = find_latest()
    else:
        csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"Not found: {csv_path}", file=sys.stderr); sys.exit(1)

    if args.out:
        outdir = Path(args.out)
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        outdir = RESULTS_DIR / f"plots_{ts}"
    outdir.mkdir(parents=True, exist_ok=True)

    print(f"Reading {csv_path}")
    rows = load(csv_path)
    if not rows:
        print("CSV has no data rows", file=sys.stderr); sys.exit(1)
    agg = aggregate(rows)

    floor_us = cross_host_noise_floor_us(rows)
    if floor_us > 0:
        print(f"Cross-host clock-sync noise floor: ≈{floor_us:.0f} µs "
              f"(half of the worst RTT seen across runs). "
              f"Latency claims below this on cross-machine metrics (ingest, e2e) "
              f"should be reported as 'below the floor'.")

    print(f"Writing plots to {outdir.relative_to(REPO_ROOT)}/")
    plot_compute_latency(agg, outdir)
    plot_drop_curve(agg, outdir)
    plot_throughput(agg, outdir)
    plot_signal_rate(agg, outdir)
    plot_stage_breakdown(agg, outdir)
    plot_e2e_latency(agg, outdir, noise_floor_us=floor_us)
    print(f"\nDone. {len(rows)} runs across "
          f"{len({t for t,_ in agg})} tier(s) × {len({r for _,r in agg})} rate(s).")


if __name__ == "__main__":
    main()
