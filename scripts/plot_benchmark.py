#!/usr/bin/env python3
"""
plot_benchmark.py — produce FYP-presentation plots from a benchmark CSV.

Reads the CSV emitted by bin/benchmark_harness (one row per tier/rate/rep)
and writes PNGs to results/plots_<timestamp>/:

  01_compute_latency.png    — per-tier per-tick GPU compute p50/p99 vs rate
  02_drop_curve.png         — sender-vs-processed drop rate vs offered rate
  03_throughput.png         — achieved tick throughput vs offered rate
  04_signal_rate.png        — total + actionable signal rate vs offered rate
  05_stage_components_50k.png
  05_stage_components_100k.png
                            — p50 stage components per tier at healthy/overload rates
  06_e2e_latency.png        — receiver-ingress-to-output p50/p99

Current benchmark definition for T1-T4 uses sender-side T1 translated into the
receiver clock domain:
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


METRIC_KEYS = ("drop", "e2e_p50", "e2e_p99",
               "ingest_p50", "ingest_p99",
               "compute_p50", "compute_p99",
               "throughput", "sig_total", "sig_actionable")


def aggregate(rows):
    """Group by (tier, rate). Return median, min and max for each metric across
    reps. Median preserves the existing behaviour; min/max are added so plots
    can shade the run-to-run spread without changing any existing call site."""
    grouped = defaultdict(list)
    for r in rows:
        grouped[(r["tier"], r["rate"])].append(r)
    out = {}
    for key, runs in grouped.items():
        entry = {}
        for k in METRIC_KEYS:
            vals = [r[k] for r in runs]
            entry[k] = float(np.median(vals))
            entry[k + "_min"] = float(np.min(vals))
            entry[k + "_max"] = float(np.max(vals))
        entry["_n_reps"] = len(runs)
        out[key] = entry
    return out


def tier_series(agg, tier, key):
    rates = sorted(r for (t, r) in agg.keys() if t == tier)
    return rates, [agg[(tier, r)][key] for r in rates]


def tier_band(agg, tier, key):
    """Return (rates, lo, hi) for shading the min/max band across reps. lo and
    hi collapse to the median when there's only one rep, so calling this is
    safe even when --reps 1."""
    rates = sorted(r for (t, r) in agg.keys() if t == tier)
    lo = [agg[(tier, r)][key + "_min"] for r in rates]
    hi = [agg[(tier, r)][key + "_max"] for r in rates]
    return rates, lo, hi


def _shade_band(ax, tier, agg, key, color, alpha=0.15):
    """No-op when reps==1 or all values match (zero-area band)."""
    rates, lo, hi = tier_band(agg, tier, key)
    if not rates:
        return
    if all(abs(h - l) < 1e-9 for l, h in zip(lo, hi)):
        return
    ax.fill_between(rates, lo, hi, color=color, alpha=alpha, linewidth=0)


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
    """Per-tick GPU compute comparison. Shaded band = min/max across reps."""
    fig, ax = plt.subplots(figsize=(8, 5))
    for tier in sorted({t for (t, _) in agg.keys()}):
        rates, p50 = tier_series(agg, tier, "compute_p50")
        _,     p99 = tier_series(agg, tier, "compute_p99")
        c, m = TIER_COLOR[tier], TIER_MARKER[tier]
        _shade_band(ax, tier, agg, "compute_p50", c)
        ax.plot(rates, p50, color=c, marker=m, linewidth=2,
                label=f"{TIER_LABEL[tier]}  p50")
        ax.plot(rates, p99, color=c, marker=m, linestyle="--",
                alpha=0.6, label=f"{TIER_LABEL[tier]}  p99")
    setup_axes(ax, "Per-tick GPU compute latency",
               "Offered tick rate (Hz)", "Per-tick compute latency (µs)",
               xlog=True, ylog=True)
    ax.legend(fontsize=8, loc="upper left", framealpha=0.95)
    save(fig, outdir, "01_compute_latency.png")


def plot_drop_curve(agg, outdir):
    """Sender-vs-processed completion loss."""
    fig, ax = plt.subplots(figsize=(8, 5))
    for tier in sorted({t for (t, _) in agg.keys()}):
        rates, drop = tier_series(agg, tier, "drop")
        c = TIER_COLOR[tier]
        # Manual fill_between in percent — drop is fraction in agg.
        rates_b, lo, hi = tier_band(agg, tier, "drop")
        if rates_b and any(abs(h - l) > 1e-9 for l, h in zip(lo, hi)):
            ax.fill_between(rates_b, [l * 100 for l in lo], [h * 100 for h in hi],
                            color=c, alpha=0.15, linewidth=0)
        ax.plot(rates, [d * 100 for d in drop],
                color=c, marker=TIER_MARKER[tier],
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
        c = TIER_COLOR[tier]
        _shade_band(ax, tier, agg, "throughput", c)
        ax.plot(rates, tput, color=c,
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
        _shade_band(axes[0], tier, agg, "sig_total",      c)
        _shade_band(axes[1], tier, agg, "sig_actionable", c)
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


def plot_stage_breakdown(agg, outdir, target_rate=50000, filename=None):
    """Grouped p50 stage components at a fixed rate.

    This intentionally avoids the old stacked-bar presentation. Percentiles are
    not additive: p50(e2e) - p50(ingest) - p50(compute) is only an approximate
    residual, not a true p50 egress stage. Grouped log-scale bars make the
    microsecond compute component visible without letting saturated T1 queueing
    flatten every other tier.
    """
    rates_avail = sorted({r for (_, r) in agg.keys()})
    if target_rate not in rates_avail:
        target_rate = min(rates_avail, key=lambda r: abs(r - target_rate))
    if filename is None:
        filename = f"05_stage_components_{target_rate//1000}k.png"

    tiers = sorted({t for (t, _) in agg.keys()})
    ingest  = [agg[(t, target_rate)]["ingest_p50"]  for t in tiers]
    compute = [agg[(t, target_rate)]["compute_p50"] for t in tiers]
    e2e_v   = [agg[(t, target_rate)]["e2e_p50"]     for t in tiers]
    # Approximate residual only; medians are not additive.
    egress  = [max(0.0, e2e_v[i] - ingest[i] - compute[i])
               for i in range(len(tiers))]

    fig, ax = plt.subplots(figsize=(10, 5.5))
    labels = [TIER_LABEL[t] for t in tiers]
    x = np.arange(len(tiers))
    width = 0.18

    def positive(vals):
        return [max(v, 1e-3) for v in vals]

    ax.bar(x - 1.5 * width, positive(ingest),  width,
           label="Ingress p50 (T2−T1)", color="#b8b8b8")
    ax.bar(x - 0.5 * width, positive(compute), width,
           label="Compute p50 (T3−T2)", color="#2a9d8f")
    ax.bar(x + 0.5 * width, positive(egress),  width,
           label="Residual approx. (e2e−ingest−compute)", color="#264653")
    ax.scatter(x + 1.5 * width, positive(e2e_v), marker="D", s=42,
               color="#111111", label="End-to-end p50 (T4−T1)", zorder=4)

    ax.set_xticks(x)
    ax.set_xticklabels([l.split(" ")[0] for l in labels], fontsize=9)
    ax.set_yscale("log")
    ax.set_title(f"p50 stage components @ {target_rate:,} Hz",
                 fontsize=11, pad=10)
    ax.set_ylabel("Latency (µs)", fontsize=10)
    ax.grid(True, axis="y", which="both", alpha=0.25)
    ax.legend(fontsize=8, loc="upper left", framealpha=0.95)
    ax.text(
        0.01, 0.01,
        "Residual is approximate because medians are not additive.",
        transform=ax.transAxes, fontsize=8, color="#555555",
        ha="left", va="bottom")
    save(fig, outdir, filename)


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
    """Receiver-ingress-to-output latency, with cross-host noise floor band
    and a min/max band across reps for the p50 line."""
    fig, ax = plt.subplots(figsize=(8, 5))
    for tier in sorted({t for (t, _) in agg.keys()}):
        rates, p50 = tier_series(agg, tier, "e2e_p50")
        _,     p99 = tier_series(agg, tier, "e2e_p99")
        c, m = TIER_COLOR[tier], TIER_MARKER[tier]
        _shade_band(ax, tier, agg, "e2e_p50", c)
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
    plot_stage_breakdown(agg, outdir, target_rate=50000,
                         filename="05_stage_components_50k.png")
    plot_stage_breakdown(agg, outdir, target_rate=100000,
                         filename="05b_stage_components_100k.png")
    plot_e2e_latency(agg, outdir, noise_floor_us=floor_us)
    print(f"\nDone. {len(rows)} runs across "
          f"{len({t for t,_ in agg})} tier(s) × {len({r for _,r in agg})} rate(s).")


if __name__ == "__main__":
    main()
