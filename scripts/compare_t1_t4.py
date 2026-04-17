#!/usr/bin/env python3
"""
compare_t1_t4.py — Rate-sweep comparison between T1 (cpu_receiver) and
                   T4 (gpu_receiver / DOCA GPUNetIO).

Reads every results/single/T1_* and T4_* run, groups by (tier, rate_hz),
aggregates over repetitions, and writes:

    results/comparison/
        01_throughput.png        — achieved Hz vs offered rate
        02_drop_rate.png         — drop % vs rate (log-x)
        03_compute_latency.png   — compute (T3-T2) p50 / p99 vs rate
        04_egress_latency.png    — egress  (T4-T3) p50 / p99 vs rate
        05_ingest_latency.png    — ingest  (T2-T1) p50 / p99 vs rate
                                   ★ T1 = reliable (same-clock host loop)
                                   ★ T4 = cross-machine upper bound
        06_e2e_latency.png       — e2e     (T4-T1) p50 / p99 vs rate
        07_stage_breakdown.png   — stacked bar at each rate: ingest/compute/egress p50
        summary_table.txt        — machine-readable numbers

Usage:
    python3 scripts/compare_t1_t4.py               # auto-discover all runs
    python3 scripts/compare_t1_t4.py --rates 10000 50000 100000
    python3 scripts/compare_t1_t4.py --out results/my_comparison
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from textwrap import dedent

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

REPO_ROOT   = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO_ROOT / "results" / "single"
DEFAULT_OUT = REPO_ROOT / "results" / "comparison"

# ── Colours ───────────────────────────────────────────────────────────────────
T1_COLOR  = "#e76f51"   # orange-red
T4_COLOR  = "#3a7ca5"   # blue
T1_LIGHT  = "#f4a27a"
T4_LIGHT  = "#7ab3d4"

TIER_META = {
    1: dict(label="T1 cpu_receiver\n(kernel UDP + cudaMemcpy)", color=T1_COLOR, light=T1_LIGHT),
    4: dict(label="T4 GPUNetIO\n(DOCA persistent kernel)",       color=T4_COLOR, light=T4_LIGHT),
}

# ─────────────────────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────────────────────

def discover_runs(results_dir: Path, tiers=(1, 4)) -> list[Path]:
    """Return sorted list of run dirs for the requested tiers."""
    prefixes = tuple(f"T{t}_" for t in tiers)
    runs = [p for p in results_dir.iterdir()
            if p.is_dir() and p.name.startswith(prefixes)]
    return sorted(runs, key=lambda p: p.name)


def load_summary(run_dir: Path) -> dict:
    sp = run_dir / "summary.json"
    if not sp.exists():
        return {}
    with open(sp) as f:
        return json.load(f)


def load_bench_csv(run_dir: Path) -> np.ndarray | None:
    cp = run_dir / "bench.csv"
    if not cp.exists():
        return None
    rows = []
    with open(cp, newline="") as f:
        for r in csv.DictReader(f):
            try:
                rows.append((
                    int(r["recv_ns"]), int(r["tick_id"]),
                    int(r["t1_ns"]),   int(r["t2_ns"]),
                    int(r["t3_ns"]),   int(r["t4_ns"]),
                    int(r["tier"]),    int(r["dropped"]),
                ))
            except (KeyError, ValueError):
                continue
    if not rows:
        return None
    dtype = np.dtype([
        ("recv_ns","u8"), ("tick_id","u8"),
        ("t1_ns","u8"), ("t2_ns","u8"),
        ("t3_ns","u8"), ("t4_ns","u8"),
        ("tier","u1"),  ("dropped","u1"),
    ])
    return np.array(rows, dtype=dtype)


def window_data(data: np.ndarray, summary: dict) -> np.ndarray:
    """Keep only the measurement window (skip warmup)."""
    run = summary.get("run", {})
    warmup   = run.get("warmup_sec",   5)
    duration = run.get("duration_sec", 30)

    # Use t2_ns as window reference (always host clock for both T1 and T4).
    t2 = data["t2_ns"].astype(np.int64)
    t2_valid = t2[t2 > 0]
    if len(t2_valid) == 0:
        return data
    t2_min = int(t2_valid.min())
    start  = t2_min + warmup   * 1_000_000_000
    end    = t2_min + (warmup + duration) * 1_000_000_000
    mask   = (t2 >= start) & (t2 < end) & (t2 > 0)
    return data[mask]


def lat_us(data: np.ndarray, a_field: str, b_field: str,
           max_us: float = 5e6) -> np.ndarray:
    """Compute (b - a) in microseconds, filtered to (0, max_us)."""
    a = data[a_field].astype(np.int64)
    b = data[b_field].astype(np.int64)
    diff = (b - a) / 1000.0
    return diff[(diff > 0) & (diff < max_us) & np.isfinite(diff)]


def compute_stats(arr: np.ndarray) -> dict:
    if len(arr) == 0:
        nan = float("nan")
        return dict(n=0, p50=nan, p95=nan, p99=nan, p999=nan, mean=nan, max=nan)
    p50, p95, p99, p999 = np.percentile(arr, [50, 95, 99, 99.9])
    return dict(n=len(arr), p50=float(p50), p95=float(p95),
                p99=float(p99), p999=float(p999),
                mean=float(arr.mean()), max=float(arr.max()))


def process_run(run_dir: Path) -> dict | None:
    """Return a normalised run record, or None if the run is unusable."""
    summary = load_summary(run_dir)
    data    = load_bench_csv(run_dir)
    if data is None or len(data) == 0:
        return None

    run_meta  = summary.get("run", {})
    tier      = int(run_meta.get("tier",       run_dir.name[1]))   # T1_ or T4_
    rate_hz   = int(run_meta.get("rate_hz",    0))
    rep       = int(run_meta.get("repetition", 1))

    if rate_hz == 0:
        # Try to parse from folder name: T1_50000hz_rep1_...
        parts = run_dir.name.split("_")
        for p in parts:
            if p.endswith("hz"):
                try:
                    rate_hz = int(p[:-2])
                    break
                except ValueError:
                    pass

    if rate_hz == 0:
        print(f"  [skip] {run_dir.name}: could not determine rate_hz")
        return None

    data = window_data(data, summary)
    if len(data) == 0:
        print(f"  [skip] {run_dir.name}: empty after windowing")
        return None

    # Throughput
    tids = np.sort(data["tick_id"].astype(np.int64))
    expected = int(tids[-1] - tids[0] + 1)
    received = len(tids)
    drop_rate  = 1.0 - received / expected if expected > 0 else 0.0

    # T2 time span for achieved rate
    t2 = data["t2_ns"].astype(np.int64)
    t2 = t2[t2 > 0]
    span_s = (t2.max() - t2.min()) / 1e9 if len(t2) > 1 else 1.0
    achieved_hz = received / span_s

    return dict(
        run_name   = run_dir.name,
        tier       = tier,
        rate_hz    = rate_hz,
        rep        = rep,
        expected   = expected,
        received   = received,
        drop_rate  = drop_rate,
        achieved_hz= achieved_hz,
        ingest  = compute_stats(lat_us(data, "t1_ns", "t2_ns")),
        compute = compute_stats(lat_us(data, "t2_ns", "t3_ns")),
        egress  = compute_stats(lat_us(data, "t3_ns", "t4_ns")),
        e2e     = compute_stats(lat_us(data, "t1_ns", "t4_ns")),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Aggregation (mean over reps at each rate)
# ─────────────────────────────────────────────────────────────────────────────

def aggregate(runs: list[dict]) -> dict:
    """
    Returns  {tier: {rate_hz: {metric: {stat: value}}}}
    where metric ∈ {throughput, drop_rate, ingest, compute, egress, e2e}
    and   stat   ∈ {p50, p95, p99, mean, ...}
    """
    # Group: tier -> rate -> list[run]
    grouped: dict = defaultdict(lambda: defaultdict(list))
    for r in runs:
        grouped[r["tier"]][r["rate_hz"]].append(r)

    out = {}
    for tier, rates in grouped.items():
        out[tier] = {}
        for rate, reps in sorted(rates.items()):
            def avg_field(key, subkey):
                vals = [r[key][subkey] for r in reps
                        if r[key][subkey] == r[key][subkey]]  # nan check
                return float(np.mean(vals)) if vals else float("nan")

            def avg(key):
                vals = [r[key] for r in reps if r[key] == r[key]]
                return float(np.mean(vals)) if vals else float("nan")

            out[tier][rate] = {
                "n_reps":      len(reps),
                "achieved_hz": avg("achieved_hz"),
                "drop_rate":   avg("drop_rate"),
                "ingest":  {s: avg_field("ingest",  s) for s in ("p50","p95","p99","p999","mean")},
                "compute": {s: avg_field("compute", s) for s in ("p50","p95","p99","p999","mean")},
                "egress":  {s: avg_field("egress",  s) for s in ("p50","p95","p99","p999","mean")},
                "e2e":     {s: avg_field("e2e",     s) for s in ("p50","p95","p99","p999","mean")},
            }
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Plotting helpers
# ─────────────────────────────────────────────────────────────────────────────

def _rates_vals(agg: dict, tier: int, getter):
    """Return (rates, values) for one tier, sorted by rate."""
    d = agg.get(tier, {})
    pairs = [(r, getter(v)) for r, v in sorted(d.items())]
    if not pairs:
        return np.array([]), np.array([])
    rates, vals = zip(*pairs)
    return np.array(rates, dtype=float), np.array(vals, dtype=float)


def _log_x_axis(ax, rates_all):
    ax.set_xscale("log")
    ticks = sorted(set(int(r) for r in rates_all if r > 0))
    ax.set_xticks(ticks)
    ax.xaxis.set_major_formatter(mticker.FuncFormatter(
        lambda x, _: f"{int(x):,}"))
    ax.set_xlabel("Offered rate (ticks/s)")


def _save(fig, path: Path):
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)
    print(f"  wrote {path}")


# ─────────────────────────────────────────────────────────────────────────────
# Individual plots
# ─────────────────────────────────────────────────────────────────────────────

def plot_throughput(agg: dict, out: Path):
    fig, ax = plt.subplots(figsize=(9, 5))
    rates_all = []
    for tier in (1, 4):
        meta = TIER_META[tier]
        rates, vals = _rates_vals(agg, tier, lambda v: v["achieved_hz"])
        if not len(rates):
            continue
        rates_all.extend(rates)
        ax.plot(rates, vals, "o-", color=meta["color"],
                label=meta["label"], linewidth=1.8, markersize=6)
    # Ideal line
    all_r = sorted(set(rates_all))
    if all_r:
        ax.plot(all_r, all_r, "k--", linewidth=0.9, alpha=0.4, label="ideal (achieved = offered)")
    _log_x_axis(ax, rates_all)
    ax.set_ylabel("Achieved throughput (ticks/s)")
    ax.set_title("Throughput: T1 cpu_receiver vs T4 GPUNetIO")
    ax.legend(loc="upper left", fontsize=9)
    ax.grid(alpha=0.25, which="both")
    _save(fig, out)


def plot_drop_rate(agg: dict, out: Path):
    fig, ax = plt.subplots(figsize=(9, 5))
    rates_all = []
    for tier in (1, 4):
        meta = TIER_META[tier]
        rates, vals = _rates_vals(agg, tier, lambda v: v["drop_rate"] * 100)
        if not len(rates):
            continue
        rates_all.extend(rates)
        ax.plot(rates, vals, "o-", color=meta["color"],
                label=meta["label"], linewidth=1.8, markersize=6)
    _log_x_axis(ax, rates_all)
    ax.set_ylabel("Drop rate (%)")
    ax.set_title("Drop rate vs offered rate: T1 vs T4")
    ax.legend(loc="upper left", fontsize=9)
    ax.grid(alpha=0.25, which="both")
    ax.axhline(0, color="black", linewidth=0.5, alpha=0.4)
    _save(fig, out)


def _plot_latency_metric(agg: dict, metric: str, ylabel: str,
                          title: str, note: str, out: Path):
    fig, ax = plt.subplots(figsize=(9, 5))
    rates_all = []
    for tier in (1, 4):
        meta = TIER_META[tier]
        rates_p50, p50 = _rates_vals(agg, tier, lambda v: v[metric]["p50"])
        rates_p99, p99 = _rates_vals(agg, tier, lambda v: v[metric]["p99"])
        if not len(rates_p50):
            continue
        rates_all.extend(rates_p50)
        ax.plot(rates_p50, p50, "o-", color=meta["color"],
                label=f"{meta['label'].split(chr(10))[0]} p50",
                linewidth=1.8, markersize=6)
        ax.plot(rates_p99, p99, "s--", color=meta["light"],
                label=f"{meta['label'].split(chr(10))[0]} p99",
                linewidth=1.3, markersize=5)
    _log_x_axis(ax, rates_all)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    if note:
        ax.text(0.01, 0.99, note, transform=ax.transAxes, fontsize=8,
                verticalalignment="top", color="grey",
                bbox=dict(boxstyle="round,pad=0.3", facecolor="white", alpha=0.7))
    ax.legend(loc="best", fontsize=8)
    ax.grid(alpha=0.25, which="both")
    _save(fig, out)


def plot_stage_breakdown(agg: dict, out: Path):
    """Stacked bar chart: ingest + compute + egress p50 per tier per rate."""
    # Collect all rates present in either tier
    all_rates = sorted(set(
        r for tier in (1, 4) for r in agg.get(tier, {})
    ))
    if not all_rates:
        return

    n_rates = len(all_rates)
    n_tiers = 2
    bar_w   = 0.35
    offsets = [-0.5 * bar_w, 0.5 * bar_w]

    fig, ax = plt.subplots(figsize=(max(10, n_rates * 1.5), 6))

    stages = [
        ("ingest",  "T2-T1", "#3a7ca5"),
        ("compute", "T3-T2", "#f4a261"),
        ("egress",  "T4-T3", "#e76f51"),
    ]
    labels_plotted = set()

    for ti, tier in enumerate((1, 4)):
        tier_data = agg.get(tier, {})
        bottom = np.zeros(n_rates)
        for stage, stage_label, color in stages:
            vals = np.array([
                tier_data.get(r, {}).get(stage, {}).get("p50", 0.0) or 0.0
                for r in all_rates
            ], dtype=float)
            x = np.arange(n_rates) + offsets[ti]
            lbl_key = (stage, tier)
            tier_short = f"T{tier}"
            label = f"{tier_short} {stage_label}" if lbl_key not in labels_plotted else None
            bars = ax.bar(x, vals, width=bar_w, bottom=bottom,
                          color=color, alpha=0.85 if tier == 4 else 0.6,
                          edgecolor="white", linewidth=0.5, label=label,
                          hatch="//" if tier == 1 else "")
            # Value labels on taller bars
            for xi, (h, b) in enumerate(zip(vals, bottom)):
                if h > 0.5:
                    ax.text(x[xi], b + h / 2, f"{h:.0f}",
                            ha="center", va="center", fontsize=7, color="white",
                            fontweight="bold")
            bottom += vals
            if label:
                labels_plotted.add(lbl_key)

    # Tier label above each pair of bars
    for i, rate in enumerate(all_rates):
        ax.text(i - 0.5 * bar_w, ax.get_ylim()[1] * 0.01, "T1",
                ha="center", va="bottom", fontsize=8, color=T1_COLOR, fontweight="bold")
        ax.text(i + 0.5 * bar_w, ax.get_ylim()[1] * 0.01, "T4",
                ha="center", va="bottom", fontsize=8, color=T4_COLOR, fontweight="bold")

    ax.set_xticks(np.arange(n_rates))
    ax.set_xticklabels([f"{r:,}" for r in all_rates], rotation=30, ha="right")
    ax.set_xlabel("Offered rate (ticks/s)")
    ax.set_ylabel("p50 latency (μs)")
    ax.set_title("Pipeline stage breakdown (p50): T1 cpu_receiver vs T4 GPUNetIO")
    ax.legend(loc="upper left", fontsize=8, ncol=3)
    ax.grid(alpha=0.25, axis="y")
    _save(fig, out)


# ─────────────────────────────────────────────────────────────────────────────
# Text summary table
# ─────────────────────────────────────────────────────────────────────────────

def write_summary_table(agg: dict, out: Path):
    lines = []
    hdr = (f"{'tier':>4}  {'rate_hz':>10}  {'reps':>4}  "
           f"{'achieved_hz':>12}  {'drop%':>6}  "
           f"{'ingest_p50':>10}  {'ingest_p99':>10}  "
           f"{'compute_p50':>11}  {'compute_p99':>11}  "
           f"{'egress_p50':>10}  {'egress_p99':>10}  "
           f"{'e2e_p50':>8}  {'e2e_p99':>8}")
    lines.append(hdr)
    lines.append("-" * len(hdr))

    for tier in (1, 4):
        for rate in sorted(agg.get(tier, {})):
            v = agg[tier][rate]

            def f(metric, stat):
                val = v[metric][stat]
                return f"{val:10.2f}" if val == val else "       NaN"

            lines.append(
                f"{tier:>4}  {rate:>10,}  {v['n_reps']:>4}  "
                f"{v['achieved_hz']:>12,.0f}  {v['drop_rate']*100:>6.3f}  "
                f"{f('ingest','p50')}  {f('ingest','p99')}  "
                f"{f('compute','p50')}  {f('compute','p99')}  "
                f"{f('egress','p50')}  {f('egress','p99')}  "
                f"{f('e2e','p50')}  {f('e2e','p99')}"
            )
        lines.append("")

    note = dedent("""
    Notes:
      ingest  (T2-T1) — T1: same-host clock, measures kernel UDP loopback + cudaMemcpy H2D.
                        T4: crosses DPU↔host clock boundary; tens-of-ms noise floor; upper bound only.
      compute (T3-T2) — both same machine. T1: per-batch kernel ÷ batch_size. T4: persistent GPU kernel.
      egress  (T4-T3) — T1: cudaMemcpy D2H + sendto. T4: result_ring write → host poll + sendto.
      e2e     (T4-T1) — T1: same-host clock, fully trustworthy. T4: upper bound (cross-machine).
    """).strip()
    lines.append(note)

    out.write_text("\n".join(lines))
    print(f"  wrote {out}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="Compare T1 cpu_receiver vs T4 GPUNetIO across a rate sweep.")
    p.add_argument("--results-dir", default=str(RESULTS_DIR),
                   help="Directory containing T1_* and T4_* run subdirs")
    p.add_argument("--out", default=str(DEFAULT_OUT),
                   help="Output directory for plots and table")
    p.add_argument("--rates", type=int, nargs="+", default=None,
                   help="Restrict to specific rates (e.g. --rates 10000 50000)")
    p.add_argument("--tiers", type=int, nargs="+", default=[1, 4],
                   help="Which tiers to include (default: 1 4)")
    args = p.parse_args()

    results_dir = Path(args.results_dir)
    out_dir     = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Discover & load ────────────────────────────────────────────────────
    runs_dirs = discover_runs(results_dir, tiers=args.tiers)
    if not runs_dirs:
        sys.exit(f"[compare] no T1/T4 runs found in {results_dir}")

    print(f"[compare] found {len(runs_dirs)} run dirs in {results_dir}")
    runs = []
    for rd in runs_dirs:
        rec = process_run(rd)
        if rec is None:
            print(f"  [skip] {rd.name}")
            continue
        if args.rates and rec["rate_hz"] not in args.rates:
            continue
        runs.append(rec)
        print(f"  [ok]   {rd.name}  tier={rec['tier']}  rate={rec['rate_hz']:,}  "
              f"recv={rec['received']:,}  drop={rec['drop_rate']*100:.2f}%")

    if not runs:
        sys.exit("[compare] no usable runs after filtering")

    agg = aggregate(runs)
    print(f"\n[compare] aggregated: "
          + ", ".join(f"T{t} × {len(agg.get(t,{}))} rates" for t in args.tiers))

    # ── Plots ──────────────────────────────────────────────────────────────
    print(f"\n[compare] writing plots to {out_dir}/")

    plot_throughput(agg, out_dir / "01_throughput.png")
    plot_drop_rate(agg,  out_dir / "02_drop_rate.png")

    _plot_latency_metric(
        agg, "compute", "Compute latency (μs)",
        "Compute latency (T3−T2): T1 vs T4",
        "T1: per-tick (batch kernel / batch_size)\nT4: inline persistent GPU kernel",
        out_dir / "03_compute_latency.png",
    )
    _plot_latency_metric(
        agg, "egress", "Egress latency (μs)",
        "Egress latency (T4−T3): T1 vs T4",
        "T1: cudaMemcpy D→H + sendto\nT4: result_ring write → host poll + sendto",
        out_dir / "04_egress_latency.png",
    )
    _plot_latency_metric(
        agg, "ingest", "Ingest latency (μs)",
        "Ingest latency (T2−T1): T1 vs T4",
        "T1 ★ same-host clock: kernel UDP loop + recvfrom + cudaMemcpy H→D\n"
        "T4 ⚠ cross-machine: DPU↔host drift → tens-of-ms noise floor (upper bound)",
        out_dir / "05_ingest_latency.png",
    )
    _plot_latency_metric(
        agg, "e2e", "End-to-end latency (μs)",
        "End-to-end latency (T4−T1): T1 vs T4",
        "T1 ★ same-host clock: reliable\n"
        "T4 ⚠ cross-machine: upper bound only",
        out_dir / "06_e2e_latency.png",
    )

    plot_stage_breakdown(agg, out_dir / "07_stage_breakdown.png")
    write_summary_table(agg, out_dir / "summary_table.txt")

    print(f"\n[compare] done  →  {out_dir}/")


if __name__ == "__main__":
    main()
