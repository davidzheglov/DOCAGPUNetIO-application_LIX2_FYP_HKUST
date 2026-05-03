#!/usr/bin/env python3
"""
plot_stages.py — tier-wise stage latency comparison plots.

Produces 6 figures (p50 and p99 for ingest / compute / egress) where each
figure shows ALL tiers side-by-side at every offered rate, making it easy to
compare the pipeline cost breakdown across T1→T4.

  01_ingest_p50.png   — NIC→receiver handoff latency (p50), per tier × rate
  02_ingest_p99.png   — same, p99
  03_compute_p50.png  — GPU kernel latency (p50)
  04_compute_p99.png  — same, p99
  05_egress_p50.png   — e2e − ingest − compute (p50), remainder for output path
  06_egress_p99.png   — same, p99

Egress is defined as:  egress = e2e − ingest − compute
(captures cudaMemcpy + result UDP send + any downstream latency)

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

# ── Visual identity (same palette as plot_benchmark.py) ───────────────────────
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
TIER_HATCH = {1: "", 2: "//", 3: "..", 4: "xx"}

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
                # egress = e2e − ingest − compute (floor at 0 to avoid neg noise)
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


# ── Plotting ──────────────────────────────────────────────────────────────────

def _fmt_rate(v):
    return f"{int(v/1000)}k" if v < 1_000_000 else f"{v/1e6:g}M"


def _plot_metric(agg, metric_key: str, title: str, ylabel: str,
                 tiers, rates, outdir: Path, filename: str,
                 noise_floor_us: float = 0.0):
    """
    Grouped-bar chart: x-axis = offered rate, groups = tiers.
    Each bar is the median across reps; error bars show min→max spread.
    """
    n_tiers = len(tiers)
    n_rates = len(rates)
    x = np.arange(n_rates)
    width = 0.7 / n_tiers          # total bar cluster width = 0.7
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

        color = TIER_COLOR[tier]
        hatch = TIER_HATCH[tier]
        label = TIER_LABEL[tier].replace("\n", " ")

        bars = ax.bar(
            x + offsets[i], vals, width,
            label=label, color=color, hatch=hatch,
            edgecolor="white", linewidth=0.6, zorder=3,
        )
        # Error bars for run-to-run spread
        ax.errorbar(
            x + offsets[i], vals,
            yerr=[lo_err, hi_err],
            fmt="none", color="black", capsize=3, linewidth=1.0, zorder=4,
        )

    # Noise floor shading (cross-host clock limit for ingest/egress)
    if noise_floor_us > 0 and ("ingest" in metric_key or "egress" in metric_key):
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


def _plot_line_metric(agg, metric_key: str, title: str, ylabel: str,
                      tiers, rates, outdir: Path, filename: str,
                      noise_floor_us: float = 0.0):
    """
    Line plot variant: x-axis = offered rate (log), one line per tier.
    Useful as a companion to the bar chart for presentations.
    """
    fig, ax = plt.subplots(figsize=(8, 5))

    markers = {1: "o", 2: "s", 3: "^", 4: "D"}
    for tier in tiers:
        xs, ys, lo_err, hi_err = [], [], [], []
        for rate in rates:
            key = (tier, rate)
            if key not in agg:
                continue
            med = agg[key][metric_key]
            lo  = agg[key][metric_key + "_min"]
            hi  = agg[key][metric_key + "_max"]
            xs.append(rate)
            ys.append(med)
            lo_err.append(med - lo)
            hi_err.append(hi - med)

        if not xs:
            continue
        color  = TIER_COLOR[tier]
        label  = TIER_LABEL[tier].replace("\n", " ")
        marker = markers.get(tier, "o")
        ax.plot(xs, ys, marker=marker, color=color, label=label,
                linewidth=1.8, markersize=6, zorder=4)
        ax.fill_between(xs,
                        [y - e for y, e in zip(ys, lo_err)],
                        [y + e for y, e in zip(ys, hi_err)],
                        color=color, alpha=0.12, linewidth=0, zorder=3)

    if noise_floor_us > 0 and ("ingest" in metric_key or "egress" in metric_key):
        ax.axhline(noise_floor_us, color="crimson", linewidth=1.2,
                   linestyle="--", zorder=5,
                   label=f"clock noise floor ({noise_floor_us:.0f} µs)")

    ax.set_xscale("log")
    ax.xaxis.set_major_formatter(mticker.FuncFormatter(
        lambda v, _: _fmt_rate(v)))
    ax.set_title(title, fontsize=13, pad=10)
    ax.set_xlabel("Offered rate (ticks/s)", fontsize=10)
    ax.set_ylabel(ylabel, fontsize=10)
    ax.grid(True, which="both", alpha=0.25)
    ax.tick_params(labelsize=9)
    ax.legend(fontsize=8, ncol=2, loc="best")

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
    ap.add_argument("--bar", action="store_true", default=True,
                    help="Generate grouped-bar charts (default: on)")
    ap.add_argument("--line", action="store_true", default=False,
                    help="Also generate line chart versions")
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

    # Filter to requested tiers
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

    SPECS = [
        # (metric_key, title, ylabel, filename_base)
        ("ingest_p50",  "Ingest Latency — p50\n(NIC → receiver handoff)",
         "Latency (µs)", "01_ingest_p50"),
        ("ingest_p99",  "Ingest Latency — p99\n(NIC → receiver handoff)",
         "Latency (µs)", "02_ingest_p99"),
        ("compute_p50", "Compute Latency — p50\n(GPU kernel execution)",
         "Latency (µs)", "03_compute_p50"),
        ("compute_p99", "Compute Latency — p99\n(GPU kernel execution)",
         "Latency (µs)", "04_compute_p99"),
        ("egress_p50",  "Egress Latency — p50\n(e2e − ingest − compute)",
         "Latency (µs)", "05_egress_p50"),
        ("egress_p99",  "Egress Latency — p99\n(e2e − ingest − compute)",
         "Latency (µs)", "06_egress_p99"),
    ]

    for metric_key, title, ylabel, name_base in SPECS:
        nf = noise_floor if ("ingest" in metric_key or "egress" in metric_key) else 0.0
        _plot_metric(agg, metric_key, title, ylabel,
                     avail_tiers, rates, outdir,
                     name_base + "_bar.png", noise_floor_us=nf)
        if args.line:
            _plot_line_metric(agg, metric_key, title, ylabel,
                              avail_tiers, rates, outdir,
                              name_base + "_line.png", noise_floor_us=nf)

    print("Done.")


if __name__ == "__main__":
    main()
