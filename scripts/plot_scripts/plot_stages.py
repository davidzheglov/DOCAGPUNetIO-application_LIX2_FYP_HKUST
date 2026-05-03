#!/usr/bin/env python3
"""
plot_stages.py — tier-wise stage latency comparison plots.

Produces figures for ingest/compute/egress latencies (p50 and p99).

For compute latency:
  - Combined line plot showing all tiers together
  - Individual scatter/line plots for each tier separately

Usage:
  python3 scripts/plot_stages.py results/benchmark_20260428_193500.csv
  python3 scripts/plot_stages.py --latest          # newest CSV in results/
  python3 scripts/plot_stages.py --out results/my_plots   # custom output dir
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

REPO_ROOT   = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO_ROOT / "results"

# ── Visual identity ───────────────────────────────────────────────────────────
TIER_LABEL = {
    1: "T1  CPU recvfrom\n(3 copies)",
    2: "T2  DPDK PMD\n(2 copies)",
    3: "T3  GPU RDMA\n(0 copies)",
    4: "T4  DOCA GPUNetIO\n(0 copies)",
}
TIER_COLOR = {
    1: "#e76f51",
    2: "#f4a261",
    3: "#2a9d8f",
    4: "#264653",
}
TIER_MARKER = {1: "o", 2: "s", 3: "^", 4: "D"}

# ── Data loading ──────────────────────────────────────────────────────────────

def load(csv_path: Path):
    rows = []
    with open(csv_path) as f:
        for r in csv.DictReader(f):
            e50 = float(r["e2e_p50_us"])
            e99 = float(r["e2e_p99_us"])
            i50 = float(r["ingest_p50_us"])
            i99 = float(r["ingest_p99_us"])
            c50 = float(r["compute_p50_us"])
            c99 = float(r["compute_p99_us"])
            rows.append({
                "tier":        int(r["tier"]),
                "rate":        int(r["rate_hz"]),
                "rep":         int(r["repetition"]),
                "ingest_p50":  i50,
                "ingest_p99":  i99,
                "compute_p50": c50,
                "compute_p99": c99,
                "egress_p50":  max(0.0, e50 - i50 - c50),
                "egress_p99":  max(0.0, e99 - i99 - c99),
                "clock_rtt_us": float(r.get("clock_rtt_us", 0.0) or 0.0),
            })
    return rows


def aggregate(rows):
    """Group by (tier, rate); return median across reps for each metric."""
    KEYS = ("ingest_p50", "ingest_p99", "compute_p50", "compute_p99",
            "egress_p50", "egress_p99")
    grouped = defaultdict(list)
    for r in rows:
        grouped[(r["tier"], r["rate"])].append(r)
    out = {}
    for key, runs in grouped.items():
        entry = {}
        for k in KEYS:
            vals = [r[k] for r in runs]
            entry[k]          = float(np.median(vals))
            entry[k + "_min"] = float(np.min(vals))
            entry[k + "_max"] = float(np.max(vals))
        out[key] = entry
    return out


def get_raw_by_tier(rows, tier: int, metric: str):
    """Get all raw data points for a specific tier and metric."""
    points = [(r["rate"], r[metric]) for r in rows if r["tier"] == tier]
    rates = sorted(set(p[0] for p in points))
    vals_by_rate = {rate: [p[1] for p in points if p[0] == rate] for rate in rates}
    return rates, vals_by_rate


# ── Plotting helpers ──────────────────────────────────────────────────────────

def _fmt_rate(v):
    return f"{int(v/1000)}k" if v < 1_000_000 else f"{v/1e6:g}M"


def _plot_combined_compute(agg, tiers, rates, outdir: Path, filename: str):
    """Combined line plot for compute latency showing all tiers."""
    fig, ax = plt.subplots(figsize=(10, 6))

    for tier in tiers:
        xs, ys, lo_err, hi_err = [], [], [], []
        for rate in rates:
            key = (tier, rate)
            if key not in agg:
                continue
            med = agg[key]["compute_p50"]
            lo  = agg[key]["compute_p50_min"]
            hi  = agg[key]["compute_p50_max"]
            xs.append(rate)
            ys.append(med)
            lo_err.append(med - lo)
            hi_err.append(hi - med)

        if not xs:
            continue
        color  = TIER_COLOR[tier]
        label  = TIER_LABEL[tier].replace("\n", " ")
        marker = TIER_MARKER.get(tier, "o")
        
        ax.plot(xs, ys, marker=marker, color=color, label=label,
                linewidth=1.8, markersize=6, zorder=4)
        ax.fill_between(xs,
                        [y - e for y, e in zip(ys, lo_err)],
                        [y + e for y, e in zip(ys, hi_err)],
                        color=color, alpha=0.12, linewidth=0, zorder=3)

    ax.set_xscale("log")
    ax.xaxis.set_major_formatter(mticker.FuncFormatter(
        lambda v, _: _fmt_rate(v)))
    ax.set_title("Compute Latency — p50\n(GPU kernel execution)", fontsize=13, pad=10)
    ax.set_xlabel("Offered rate (ticks/s)", fontsize=10)
    ax.set_ylabel("Latency (µs)", fontsize=10)
    ax.grid(True, which="both", alpha=0.25)
    ax.tick_params(labelsize=9)
    ax.legend(fontsize=8, ncol=2, loc="best")

    fig.tight_layout()
    path = outdir / filename
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  → {path.relative_to(REPO_ROOT)}")


def _plot_individual_compute(rows, tier: int, outdir: Path, filename: str):
    """Individual scatter/line plot for compute latency of a single tier."""
    rates, vals_by_rate = get_raw_by_tier(rows, tier, "compute_p50")
    
    if not rates:
        print(f"  [WARN] No compute data for tier {tier}")
        return
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Calculate medians and IQR for each rate
    medians = []
    lower_err = []
    upper_err = []
    all_y = []
    
    for rate in rates:
        vals = vals_by_rate[rate]
        med = np.median(vals)
        q1, q3 = np.percentile(vals, [25, 75])
        all_y.extend(vals)
        
        medians.append(med)
        lower_err.append(med - q1)
        upper_err.append(q3 - med)
        
        # Plot individual points as scatter
        ax.scatter([rate] * len(vals), vals, alpha=0.3, s=30, 
                  color=TIER_COLOR[tier], edgecolors='black', linewidth=0.5, zorder=2)
    
    # Plot median line with error bars
    ax.errorbar(rates, medians, 
                yerr=[lower_err, upper_err],
                fmt='o-', color=TIER_COLOR[tier], linewidth=2, markersize=8,
                capsize=5, capthick=1.5, elinewidth=1.5, zorder=3,
                label=f"Median ± IQR")
    
    ax.set_xscale("log")
    ax.xaxis.set_major_formatter(mticker.FuncFormatter(
        lambda v, _: _fmt_rate(v)))
    
    tier_name = TIER_LABEL[tier].replace("\n", " ")
    ax.set_title(f"Compute Latency — p50\n{tier_name}", fontsize=13, pad=10)
    ax.set_xlabel("Offered rate (ticks/s)", fontsize=10)
    ax.set_ylabel("Latency (µs)", fontsize=10)
    ax.grid(True, which="both", alpha=0.25)
    ax.tick_params(labelsize=9)
    ax.legend(fontsize=9, loc="best")
    
    fig.tight_layout()
    path = outdir / filename
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  → {path.relative_to(REPO_ROOT)}")


def _plot_metric(agg, metric_key: str, title: str, ylabel: str,
                 tiers, rates, outdir: Path, filename: str,
                 noise_floor_us: float = 0.0):
    """Grouped-bar chart for non-compute metrics."""
    n_tiers = len(tiers)
    n_rates = len(rates)
    x = np.arange(n_rates)
    width = 0.7 / n_tiers
    offsets = np.linspace(-(n_tiers - 1) / 2, (n_tiers - 1) / 2, n_tiers) * width

    fig, ax = plt.subplots(figsize=(max(8, n_rates * 1.6), 5))

    for i, tier in enumerate(tiers):
        vals, lo_err, hi_err = [], [], []
        for rate in rates:
            key = (tier, rate)
            if key in agg:
                med = agg[key][metric_key]
                lo  = agg[key][metric_key + "_min"]
                hi  = agg[key][metric_key + "_max"]
            else:
                med = lo = hi = 0.0
            vals.append(med)
            lo_err.append(med - lo)
            hi_err.append(hi - med)

        bars = ax.bar(
            x + offsets[i], vals, width,
            label=TIER_LABEL[tier].replace("\n", " "),
            color=TIER_COLOR[tier], edgecolor="white", linewidth=0.6, zorder=3,
        )
        ax.errorbar(x + offsets[i], vals,
                    yerr=[lo_err, hi_err],
                    fmt="none", color="black", capsize=3, linewidth=1.0, zorder=4)

    if noise_floor_us > 0:
        ax.axhline(noise_floor_us, color="crimson", linewidth=1.2,
                   linestyle="--", zorder=5,
                   label=f"clock noise floor ({noise_floor_us:.0f} µs)")
        ax.axhspan(0, noise_floor_us, color="crimson", alpha=0.05, zorder=1)

    ax.set_title(title, fontsize=13, pad=10)
    ax.set_xlabel("Offered rate (ticks/s)", fontsize=10)
    ax.set_ylabel(ylabel, fontsize=10)
    ax.set_xticks(x)
    ax.set_xticklabels([_fmt_rate(r) for r in rates], fontsize=9)
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(
        lambda v, _: f"{v:,.0f}"))
    ax.grid(axis="y", alpha=0.3, zorder=0)
    ax.tick_params(labelsize=9)
    ax.legend(fontsize=8, ncol=2, loc="upper left")

    fig.tight_layout()
    path = outdir / filename
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  → {path.relative_to(REPO_ROOT)}")


# ── Main ──────────────────────────────────────────────────────────────────────

def find_latest_csv() -> Path:
    csvs = sorted(RESULTS_DIR.glob("benchmark_*.csv"))
    if not csvs:
        sys.exit("No benchmark_*.csv found in results/")
    return csvs[-1]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", nargs="?", help="Path to benchmark CSV")
    ap.add_argument("--latest", action="store_true",
                    help="Use the most recent benchmark CSV in results/")
    ap.add_argument("--out", help="Output directory (default: results/stages_<timestamp>)")
    ap.add_argument("--tiers", default="1,2,3,4",
                    help="Comma-separated tier list to include (default: 1,2,3,4)")
    args = ap.parse_args()

    if args.latest:
        csv_path = find_latest_csv()
    elif args.csv:
        csv_path = Path(args.csv)
    else:
        ap.print_help()
        sys.exit(1)

    if not csv_path.exists():
        sys.exit(f"CSV not found: {csv_path}")

    tiers = [int(t) for t in args.tiers.split(",")]

    outdir = Path(args.out) if args.out else \
        RESULTS_DIR / f"stages_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    outdir.mkdir(parents=True, exist_ok=True)

    print(f"Reading {csv_path.name} …")
    rows = load(csv_path)
    if not rows:
        sys.exit("CSV has no data rows.")

    rows = [r for r in rows if r["tier"] in tiers]
    if not rows:
        sys.exit(f"No rows found for tiers {tiers}")

    agg   = aggregate(rows)
    rates = sorted({r for (_, r) in agg})
    avail_tiers = sorted({t for (t, _) in agg} & set(tiers))

    noise_floor = max((r["clock_rtt_us"] for r in rows if r["clock_rtt_us"] > 0),
                      default=0.0) / 2.0

    print(f"Tiers: {avail_tiers}  |  Rates: {[_fmt_rate(r) for r in rates]}")
    print(f"Cross-host noise floor: {noise_floor:.1f} µs")
    print(f"Generating plots in {outdir.relative_to(REPO_ROOT)} …")

    # Ingest and egress (bar charts)
    INGEST_EGRESS_SPECS = [
        ("ingest_p50",  "Ingest Latency — p50\n(NIC → receiver handoff)",
         "Latency (µs)", "01_ingest_p50"),
        ("ingest_p99",  "Ingest Latency — p99\n(NIC → receiver handoff)",
         "Latency (µs)", "02_ingest_p99"),
        ("egress_p50",  "Egress Latency — p50\n(e2e − ingest − compute)",
         "Latency (µs)", "05_egress_p50"),
        ("egress_p99",  "Egress Latency — p99\n(e2e − ingest − compute)",
         "Latency (µs)", "06_egress_p99"),
    ]

    for metric_key, title, ylabel, name_base in INGEST_EGRESS_SPECS:
        nf = noise_floor if ("ingest" in metric_key or "egress" in metric_key) else 0.0
        _plot_metric(agg, metric_key, title, ylabel,
                     avail_tiers, rates, outdir,
                     name_base + ".png", noise_floor_us=nf)

    # Compute latency: combined line plot + individual plots
    print("\nCompute latency plots:")
    _plot_combined_compute(agg, avail_tiers, rates, outdir, "03_compute_p50_combined.png")
    
    # Also generate p99 combined if desired (optional)
    # _plot_combined_compute_p99(agg, avail_tiers, rates, outdir, "04_compute_p99_combined.png")
    
    print("\nIndividual tier plots:")
    for tier in avail_tiers:
        _plot_individual_compute(rows, tier, outdir, f"03_compute_p50_tier{tier}.png")

    print("\nDone.")


if __name__ == "__main__":
    main()