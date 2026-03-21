#!/usr/bin/env python3
"""
dashboard.py — GPU tick pipeline benchmark visualiser.

Reads results/benchmark.csv (produced by benchmark_harness) and generates
a set of Plotly charts saved as HTML files in results/plots/.

Charts produced:
  1. latency_percentiles.html  — p50/p95/p99 E2E latency per tier (box + line)
  2. throughput_latency.html   — throughput-vs-latency scatter per tier
  3. stage_breakdown.html      — ingestion / compute / total latency bars
  4. saturation_sweep.html     — latency vs rate for all tiers (line chart)
  5. speedup.html              — speedup factor vs T1 baseline (bar chart)
  6. cpu_comparison.html       — tier comparison summary table

Usage:
    pip install -r requirements.txt
    python dashboard.py [--results results/benchmark.csv] [--out results/plots/]
"""

import argparse
import os
import sys
from pathlib import Path

import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

# ── Tier labels ───────────────────────────────────────────────────────────────
TIER_LABELS = {
    1: "T1 CPU naive",
    2: "T2 DPDK",
    3: "T3 GPU RDMA",
    4: "T4 GPUNetIO",
    5: "T5 GPUNetIO+DPU",
}
TIER_COLORS = {
    1: "#e15759",   # red
    2: "#f28e2b",   # orange
    3: "#edc948",   # yellow
    4: "#59a14f",   # green
    5: "#4e79a7",   # blue
}


def load_data(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    df["tier_label"] = df["tier"].map(TIER_LABELS)
    # Latencies are in µs (written by harness)
    return df


def save(fig: go.Figure, path: Path, title: str) -> None:
    fig.update_layout(
        title=dict(text=title, font=dict(size=18)),
        template="plotly_white",
        font=dict(family="Inter, Arial, sans-serif", size=13),
        legend=dict(title="Tier"),
    )
    fig.write_html(str(path))
    print(f"  Saved: {path}")


# ── Chart 1: E2E latency percentiles (box plot per tier) ──────────────────────
def chart_latency_percentiles(df: pd.DataFrame, out: Path) -> None:
    fig = go.Figure()
    for tier in sorted(df["tier"].unique()):
        sub = df[df["tier"] == tier]
        label = TIER_LABELS.get(tier, f"T{tier}")
        color = TIER_COLORS.get(tier, "#aaa")
        # Use p50/p95/p99 columns to draw synthetic box
        fig.add_trace(go.Bar(
            name=label,
            x=["p50", "p95", "p99"],
            y=[sub["e2e_p50_us"].mean(),
               sub["e2e_p95_us"].mean(),
               sub["e2e_p99_us"].mean()],
            marker_color=color,
        ))
    fig.update_layout(
        barmode="group",
        xaxis_title="Percentile",
        yaxis_title="E2E Latency (µs)",
        yaxis_type="log",
    )
    save(fig, out / "latency_percentiles.html",
         "E2E Latency Percentiles by Tier")


# ── Chart 2: Throughput vs Latency scatter ─────────────────────────────────────
def chart_throughput_latency(df: pd.DataFrame, out: Path) -> None:
    fig = go.Figure()
    for tier in sorted(df["tier"].unique()):
        sub = df[df["tier"] == tier]
        label = TIER_LABELS.get(tier, f"T{tier}")
        color = TIER_COLORS.get(tier, "#aaa")
        fig.add_trace(go.Scatter(
            x=sub["throughput_per_sec"],
            y=sub["e2e_p99_us"],
            mode="markers+lines",
            name=label,
            marker=dict(size=10, color=color),
            line=dict(color=color),
            text=[f"rate={r}" for r in sub["rate_hz"]],
        ))
    fig.update_layout(
        xaxis_title="Throughput (ticks/sec)",
        yaxis_title="p99 E2E Latency (µs)",
        yaxis_type="log",
        xaxis_type="log",
    )
    save(fig, out / "throughput_latency.html",
         "Throughput vs p99 Latency (log-log)")


# ── Chart 3: Stage breakdown (ingest / compute / total) ───────────────────────
def chart_stage_breakdown(df: pd.DataFrame, out: Path) -> None:
    # Average over all runs per tier
    summary = df.groupby("tier")[
        ["ingest_p50_us", "compute_p50_us", "e2e_p50_us"]
    ].mean().reset_index()
    summary["tier_label"] = summary["tier"].map(TIER_LABELS)

    fig = go.Figure()
    fig.add_trace(go.Bar(
        name="Ingestion (T2−T1)",
        x=summary["tier_label"],
        y=summary["ingest_p50_us"],
        marker_color="#4e79a7",
    ))
    fig.add_trace(go.Bar(
        name="Compute (T3−T2)",
        x=summary["tier_label"],
        y=summary["compute_p50_us"],
        marker_color="#f28e2b",
    ))
    fig.update_layout(
        barmode="stack",
        xaxis_title="Tier",
        yaxis_title="Median Latency (µs)",
        yaxis_type="log",
    )
    save(fig, out / "stage_breakdown.html",
         "Pipeline Stage Breakdown — Median Latency")


# ── Chart 4: Saturation sweep (latency vs rate per tier) ─────────────────────
def chart_saturation_sweep(df: pd.DataFrame, out: Path) -> None:
    agg = df.groupby(["tier", "rate_hz"])[
        ["e2e_p50_us", "e2e_p99_us"]
    ].mean().reset_index()

    fig = make_subplots(rows=1, cols=2,
                         subplot_titles=["p50 E2E Latency", "p99 E2E Latency"])
    for tier in sorted(agg["tier"].unique()):
        sub = agg[agg["tier"] == tier].sort_values("rate_hz")
        label = TIER_LABELS.get(tier, f"T{tier}")
        color = TIER_COLORS.get(tier, "#aaa")
        fig.add_trace(go.Scatter(
            x=sub["rate_hz"], y=sub["e2e_p50_us"],
            name=label, mode="lines+markers",
            marker=dict(color=color), line=dict(color=color),
            showlegend=True,
        ), row=1, col=1)
        fig.add_trace(go.Scatter(
            x=sub["rate_hz"], y=sub["e2e_p99_us"],
            name=label, mode="lines+markers",
            marker=dict(color=color), line=dict(color=color),
            showlegend=False,
        ), row=1, col=2)
    fig.update_xaxes(title_text="Message Rate (msg/sec)", type="log")
    fig.update_yaxes(title_text="Latency (µs)", type="log")
    save(fig, out / "saturation_sweep.html",
         "Latency vs Rate — Saturation Sweep")


# ── Chart 5: Speedup vs T1 baseline ───────────────────────────────────────────
def chart_speedup(df: pd.DataFrame, out: Path) -> None:
    agg = df.groupby("tier")["e2e_p50_us"].mean()
    baseline = agg.get(1, None)
    if baseline is None or baseline == 0:
        print("  Warning: T1 baseline not found, skipping speedup chart")
        return

    tiers  = sorted(agg.index)
    labels = [TIER_LABELS.get(t, f"T{t}") for t in tiers]
    speedups = [baseline / agg[t] for t in tiers]
    colors   = [TIER_COLORS.get(t, "#aaa") for t in tiers]

    fig = go.Figure(go.Bar(
        x=labels, y=speedups,
        marker_color=colors,
        text=[f"{s:.1f}×" for s in speedups],
        textposition="outside",
    ))
    fig.update_layout(
        xaxis_title="Tier",
        yaxis_title="Speedup vs T1 (p50 E2E latency)",
    )
    save(fig, out / "speedup.html",
         "Speedup Factor vs T1 CPU Naive Baseline")


# ── Chart 6: Summary table ─────────────────────────────────────────────────────
def chart_summary_table(df: pd.DataFrame, out: Path) -> None:
    agg = df.groupby("tier").agg(
        n_ticks=("n_ticks", "sum"),
        drop_rate=("drop_rate", "mean"),
        e2e_p50=("e2e_p50_us", "mean"),
        e2e_p95=("e2e_p95_us", "mean"),
        e2e_p99=("e2e_p99_us", "mean"),
        throughput=("throughput_per_sec", "mean"),
    ).reset_index()
    agg["tier_label"] = agg["tier"].map(TIER_LABELS)

    fig = go.Figure(go.Table(
        header=dict(
            values=["Tier", "p50 (µs)", "p95 (µs)", "p99 (µs)",
                    "Throughput (k/s)", "Drop Rate"],
            fill_color="#2c3e50",
            font=dict(color="white", size=13),
            align="center",
        ),
        cells=dict(
            values=[
                agg["tier_label"],
                agg["e2e_p50"].round(2),
                agg["e2e_p95"].round(2),
                agg["e2e_p99"].round(2),
                (agg["throughput"] / 1000).round(1),
                (agg["drop_rate"] * 100).round(2).astype(str) + "%",
            ],
            fill_color=[["#f5f5f5", "#ffffff"] * (len(agg) // 2 + 1)],
            align="center",
        ),
    ))
    save(fig, out / "summary_table.html",
         "Benchmark Summary — All Tiers")


# ── main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description="GPU tick pipeline benchmark dashboard")
    parser.add_argument("--results", default="results/benchmark.csv",
                        help="Path to benchmark CSV (default: results/benchmark.csv)")
    parser.add_argument("--out", default="results/plots/",
                        help="Output directory for HTML charts")
    args = parser.parse_args()

    csv_path = Path(args.results)
    out_dir  = Path(args.out)

    if not csv_path.exists():
        print(f"Error: {csv_path} not found.", file=sys.stderr)
        print("Run benchmark_harness first to generate results.", file=sys.stderr)
        sys.exit(1)

    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading {csv_path}...")
    df = load_data(str(csv_path))
    print(f"  {len(df)} runs loaded, tiers: {sorted(df['tier'].unique())}")

    print("\nGenerating charts...")
    chart_latency_percentiles(df, out_dir)
    chart_throughput_latency(df, out_dir)
    chart_stage_breakdown(df, out_dir)
    chart_saturation_sweep(df, out_dir)
    chart_speedup(df, out_dir)
    chart_summary_table(df, out_dir)

    print(f"\nAll charts written to {out_dir}")
    print("Open any .html file in a browser to view interactively.")


if __name__ == "__main__":
    main()
