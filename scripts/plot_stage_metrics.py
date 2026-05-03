#!/usr/bin/env python3
"""
plot_stage_metrics.py - tier-wise stage metric comparison plots.

Reads a benchmark CSV emitted by bin/benchmark_harness and writes two figures:

  stage_metrics_p50.png - ingest / compute / approximate egress p50 vs rate
  stage_metrics_p99.png - ingest / compute / approximate egress p99 vs rate

Egress is an approximate residual:

  egress ~= e2e - ingest - compute

Percentiles are not additive, so this residual is useful as a visual
decomposition aid, not as an exact per-tick percentile.

Usage:
  python3 scripts/plot_stage_metrics.py results/benchmark_YYYYMMDD_HHMMSS.csv
  python3 scripts/plot_stage_metrics.py --latest
  python3 scripts/plot_stage_metrics.py --latest --out results/stage_metric_plots
"""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker


REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO_ROOT / "results"

TIER_LABEL = {
    1: "T1 CPU",
    2: "T2 DPDK",
    3: "T3 RDMA",
    4: "T4 DOCA",
}
TIER_COLOR = {
    1: "#e76f51",
    2: "#f4a261",
    3: "#2a9d8f",
    4: "#264653",
}
TIER_MARKER = {1: "o", 2: "s", 3: "^", 4: "D"}


def load_rows(csv_path: Path):
    rows = []
    with open(csv_path, newline="") as f:
        for r in csv.DictReader(f):
            e2e_p50 = float(r["e2e_p50_us"])
            e2e_p99 = float(r["e2e_p99_us"])
            ingest_p50 = float(r["ingest_p50_us"])
            ingest_p99 = float(r["ingest_p99_us"])
            compute_p50 = float(r["compute_p50_us"])
            compute_p99 = float(r["compute_p99_us"])

            rows.append({
                "tier": int(r["tier"]),
                "rate": int(r["rate_hz"]),
                "ingest_p50": ingest_p50,
                "ingest_p99": ingest_p99,
                "compute_p50": compute_p50,
                "compute_p99": compute_p99,
                "egress_p50": max(0.0, e2e_p50 - ingest_p50 - compute_p50),
                "egress_p99": max(0.0, e2e_p99 - ingest_p99 - compute_p99),
            })
    return rows


def aggregate(rows):
    grouped = defaultdict(list)
    for r in rows:
        grouped[(r["tier"], r["rate"])].append(r)

    metrics = (
        "ingest_p50", "compute_p50", "egress_p50",
        "ingest_p99", "compute_p99", "egress_p99",
    )
    out = {}
    for key, reps in grouped.items():
        entry = {}
        for metric in metrics:
            vals = [r[metric] for r in reps]
            entry[metric] = statistics.median(vals)
            entry[metric + "_min"] = min(vals)
            entry[metric + "_max"] = max(vals)
        out[key] = entry
    return out


def find_latest() -> Path:
    csvs = sorted(RESULTS_DIR.glob("benchmark_*.csv"))
    if not csvs:
        print("No benchmark CSVs found in results/", file=sys.stderr)
        sys.exit(1)
    return csvs[-1]


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def setup_axis(ax, title):
    ax.set_title(title, fontsize=11, pad=8)
    ax.set_xlabel("Offered tick rate (Hz)", fontsize=10)
    ax.set_ylabel("Latency (us)", fontsize=10)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.grid(True, which="both", alpha=0.25)
    ax.tick_params(labelsize=9)
    ax.xaxis.set_major_formatter(mticker.FuncFormatter(
        lambda v, _: f"{int(v / 1000)}k" if v < 1e6 else f"{v / 1e6:g}M"))


def tier_series(agg, tier, metric):
    rates = sorted(r for (t, r) in agg.keys() if t == tier)
    y = [max(agg[(tier, r)][metric], 1e-3) for r in rates]
    lo = [max(agg[(tier, r)][metric + "_min"], 1e-3) for r in rates]
    hi = [max(agg[(tier, r)][metric + "_max"], 1e-3) for r in rates]
    return rates, y, lo, hi


def plot_percentile(agg, outdir: Path, percentile: str):
    metric_defs = [
        ("ingest", f"ingest_{percentile}", "Ingest"),
        ("compute", f"compute_{percentile}", "Compute"),
        ("egress", f"egress_{percentile}", "Approx. egress residual"),
    ]

    fig, axes = plt.subplots(1, 3, figsize=(16, 5), sharex=True)
    tiers = sorted({t for (t, _) in agg.keys()})

    for ax, (_, metric, title) in zip(axes, metric_defs):
        for tier in tiers:
            rates, y, lo, hi = tier_series(agg, tier, metric)
            color = TIER_COLOR.get(tier, "#333333")
            marker = TIER_MARKER.get(tier, "o")
            if any(abs(h - l) > 1e-9 for l, h in zip(lo, hi)):
                ax.fill_between(rates, lo, hi, color=color, alpha=0.15, linewidth=0)
            ax.plot(rates, y, color=color, marker=marker, linewidth=2,
                    label=TIER_LABEL.get(tier, f"T{tier}"))
        setup_axis(ax, f"{title} {percentile.upper()}")

    axes[0].legend(fontsize=9, loc="best", framealpha=0.95)
    fig.suptitle(
        f"Tier-wise stage latency comparison ({percentile.upper()})",
        fontsize=13,
        y=1.03,
    )
    fig.text(
        0.5, -0.02,
        "Egress is an approximate residual: e2e - ingest - compute. "
        "Percentiles are not additive.",
        ha="center",
        fontsize=9,
        color="#555555",
    )
    fig.tight_layout()
    out = outdir / f"stage_metrics_{percentile}.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {display_path(out)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="?", help="benchmark CSV from run_benchmark.sh")
    ap.add_argument("--latest", action="store_true", help="use newest results/benchmark_*.csv")
    ap.add_argument("--out", help="output directory")
    args = ap.parse_args()

    csv_path = find_latest() if args.latest or not args.csv else Path(args.csv)
    if not csv_path.exists():
        print(f"Not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    if args.out:
        outdir = Path(args.out)
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        outdir = RESULTS_DIR / f"stage_metrics_{ts}"
    outdir.mkdir(parents=True, exist_ok=True)

    print(f"Reading {csv_path}")
    rows = load_rows(csv_path)
    if not rows:
        print("CSV has no data rows", file=sys.stderr)
        sys.exit(1)

    agg = aggregate(rows)
    print(f"Writing plots to {display_path(outdir)}/")
    plot_percentile(agg, outdir, "p50")
    plot_percentile(agg, outdir, "p99")


if __name__ == "__main__":
    main()
