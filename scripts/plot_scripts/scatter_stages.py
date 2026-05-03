#!/usr/bin/env python3
"""
scatter_stages.py — Individual scatter plots for each tier and metric.

Produces scatter plots showing raw data points for each tier separately:
  - ingest_p50/p99
  - compute_p50/p99  
  - egress_p50/p99

Output: results/scatter_plots/
  tier1_ingest_p50.png, tier1_ingest_p99.png, etc.
  tier2_ingest_p50.png, ...
  combined_all_tiers_ingest_p50.png (T1-T4)
  combined_t2_t4_ingest_p50.png (T2-T4)

Usage:
  python3 scripts/scatter_stages.py results/benchmark_20260428_193500.csv
  python3 scripts/scatter_stages.py --latest
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO_ROOT / "results"

TIER_LABEL = {
    1: "T1: CPU recvfrom (3 copies)",
    2: "T2: DPDK PMD (2 copies)",
    3: "T3: GPU RDMA (0 copies)",
    4: "T4: DOCA GPUNetIO (0 copies)",
}
TIER_COLOR = {
    1: "#e76f51",
    2: "#f4a261",
    3: "#2a9d8f",
    4: "#264653",
}
TIER_MARKER = {1: "o", 2: "s", 3: "^", 4: "D"}

METRICS = [
    ("ingest_p50", "Ingest Latency (p50)", "Latency (µs)"),
    ("ingest_p99", "Ingest Latency (p99)", "Latency (µs)"),
    ("compute_p50", "Compute Latency (p50)", "Latency (µs)"),
    ("compute_p99", "Compute Latency (p99)", "Latency (µs)"),
    ("egress_p50", "Egress Latency (p50)", "Latency (µs)"),
    ("egress_p99", "Egress Latency (p99)", "Latency (µs)"),
]


def load_csv(csv_path: Path):
    """Load CSV and return rows with computed egress."""
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
                "tier": int(r["tier"]),
                "rate": int(r["rate_hz"]),
                "rep": int(r["repetition"]),
                "ingest_p50": i50,
                "ingest_p99": i99,
                "compute_p50": c50,
                "compute_p99": c99,
                "egress_p50": max(0.0, e50 - i50 - c50),
                "egress_p99": max(0.0, e99 - i99 - c99),
                "clock_rtt_us": float(r.get("clock_rtt_us", 0.0) or 0.0),
            })
    return rows


def fmt_rate(v):
    return f"{int(v/1000)}k" if v < 1_000_000 else f"{v/1e6:.1f}M"


def plot_scatter_tier(data, tier: int, metric: str, title: str, ylabel: str, outdir: Path):
    """Create scatter plot for a single tier and metric."""
    points = [(r["rate"], r[metric]) for r in data if r["tier"] == tier]
    if not points:
        print(f"  [SKIP] No data for tier {tier}, metric {metric}")
        return
    
    # Group by rate
    rates = sorted(set(p[0] for p in points))
    vals_by_rate = {r: [p[1] for p in points if p[0] == r] for r in rates}
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Plot individual points
    all_vals = []
    for rate in rates:
        vals = vals_by_rate[rate]
        all_vals.extend(vals)
        x = [rate] * len(vals)
        ax.scatter(x, vals, alpha=0.5, s=40, 
                  color=TIER_COLOR[tier], marker=TIER_MARKER[tier],
                  edgecolors='black', linewidth=0.5, zorder=2)
    
    # Add median line
    medians = [np.median(vals_by_rate[r]) for r in rates]
    ax.plot(rates, medians, 'o-', color=TIER_COLOR[tier], linewidth=2, 
            markersize=8, zorder=3, label='Median')
    
    # Add quartile lines
    q1s = [np.percentile(vals_by_rate[r], 25) for r in rates]
    q3s = [np.percentile(vals_by_rate[r], 75) for r in rates]
    ax.fill_between(rates, q1s, q3s, alpha=0.2, color=TIER_COLOR[tier], 
                    label='IQR (25th-75th)')
    
    ax.set_xscale('log')
    ax.xaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: fmt_rate(v)))
    
    tier_name = TIER_LABEL[tier]
    ax.set_title(f"{title}\n{tier_name}", fontsize=13, pad=10)
    ax.set_xlabel("Offered rate (ticks/s)", fontsize=10)
    ax.set_ylabel(ylabel, fontsize=10)
    ax.grid(True, which='both', alpha=0.25, linestyle='--')
    ax.tick_params(labelsize=9)
    ax.legend(fontsize=9, loc='best')
    
    # Auto-scale y-axis with some padding
    if all_vals:
        y_min = min(all_vals)
        y_max = max(all_vals)
        padding = (y_max - y_min) * 0.05
        ax.set_ylim(max(0, y_min - padding), y_max + padding)
    
    fig.tight_layout()
    safe_metric = metric.replace('_', '')
    outfile = outdir / f"tier{tier}_{safe_metric}.png"
    fig.savefig(outfile, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f"  → {outfile.relative_to(REPO_ROOT)}")


def plot_combined(data, tiers, metric: str, title: str, ylabel: str, outdir: Path, suffix: str = "combined"):
    """Create combined scatter/line plot for specified tiers."""
    fig, ax = plt.subplots(figsize=(12, 7))
    
    for tier in tiers:
        points = [(r["rate"], r[metric]) for r in data if r["tier"] == tier]
        if not points:
            continue
        
        rates = sorted(set(p[0] for p in points))
        vals_by_rate = {r: [p[1] for p in points if p[0] == r] for r in rates}
        
        # Plot individual points with low alpha
        for rate in rates:
            vals = vals_by_rate[rate]
            x = [rate] * len(vals)
            ax.scatter(x, vals, alpha=0.2, s=25, 
                      color=TIER_COLOR[tier], marker=TIER_MARKER[tier],
                      edgecolors='none', zorder=1)
        
        # Plot median line
        medians = [np.median(vals_by_rate[r]) for r in rates]
        ax.plot(rates, medians, 'o-', color=TIER_COLOR[tier], 
                linewidth=2, markersize=6, zorder=3,
                label=TIER_LABEL[tier])
        
        # Add IQR band
        q1s = [np.percentile(vals_by_rate[r], 25) for r in rates]
        q3s = [np.percentile(vals_by_rate[r], 75) for r in rates]
        ax.fill_between(rates, q1s, q3s, alpha=0.15, color=TIER_COLOR[tier])
    
    ax.set_xscale('log')
    ax.xaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: fmt_rate(v)))
    
    # Add title suffix to indicate which tiers are included
    if suffix == "combined_all_tiers":
        title_suffix = "All Tiers (T1-T4)"
    elif suffix == "combined_t2_t4":
        title_suffix = "High-Performance Tiers (T2-T4)"
    else:
        title_suffix = "Combined"
    
    ax.set_title(f"{title}\n{title_suffix}", fontsize=13, pad=10)
    ax.set_xlabel("Offered rate (ticks/s)", fontsize=10)
    ax.set_ylabel(ylabel, fontsize=10)
    ax.grid(True, which='both', alpha=0.25, linestyle='--')
    ax.tick_params(labelsize=9)
    ax.legend(fontsize=8, ncol=2, loc='best')
    
    fig.tight_layout()
    safe_metric = metric.replace('_', '')
    outfile = outdir / f"{suffix}_{safe_metric}.png"
    fig.savefig(outfile, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f"  → {outfile.relative_to(REPO_ROOT)}")


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
    ap.add_argument("--out", help="Output directory (default: results/scatter_plots_<timestamp>)")
    ap.add_argument("--tiers", default="1,2,3,4",
                    help="Comma-separated tier list (default: 1,2,3,4)")
    ap.add_argument("--combined", action="store_true", default=True,
                    help="Generate combined plots (default: True)")
    ap.add_argument("--no-combined", action="store_true",
                    help="Skip combined plots")
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
        RESULTS_DIR / f"scatter_plots_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    outdir.mkdir(parents=True, exist_ok=True)

    print(f"Reading {csv_path.name} …")
    data = load_csv(csv_path)
    if not data:
        sys.exit("CSV has no data rows.")

    data = [r for r in data if r["tier"] in tiers]
    avail_tiers = sorted(set(r["tier"] for r in data))

    print(f"Tiers: {avail_tiers}")
    print(f"Output dir: {outdir.relative_to(REPO_ROOT)}")
    print()

    for metric, title, ylabel in METRICS:
        print(f"\n{metric}:")
        
        # Individual tier plots
        for tier in avail_tiers:
            plot_scatter_tier(data, tier, metric, title, ylabel, outdir)
        
        # Combined plots (if not disabled)
        if not args.no_combined:
            # Combined plot for all available tiers (T1-T4)
            plot_combined(data, avail_tiers, metric, title, ylabel, outdir, 
                         suffix="combined_all_tiers")
            
            # Combined plot for T2, T3, T4 only (exclude T1 if present)
            t2_t4_tiers = [t for t in avail_tiers if t in [2, 3, 4]]
            if t2_t4_tiers and len(t2_t4_tiers) >= 2:
                plot_combined(data, t2_t4_tiers, metric, title, ylabel, outdir,
                             suffix="combined_t2_t4")

    print("\nDone.")


if __name__ == "__main__":
    main()