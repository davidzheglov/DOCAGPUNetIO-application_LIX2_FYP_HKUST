#!/usr/bin/env python3
"""
pipeline_test.py — full pipeline integration test for laptop.
No GPU, DPDK, or DOCA required.

Runs all 5 tier data paths simultaneously:
  data_source → T1..T5 receivers → fill_simulator → results CSV → dashboard

Each tier receives the same TickMessage multicast stream and processes it
independently.  Tier-specific latency profiles are applied to T2/T3/T4
timestamps to produce realistic benchmark CSV output even without hardware.

Simulated latency profiles (representative of real hardware):
  T1 CPU naive    : ingest ~200 µs  compute ~50 µs
  T2 DPDK         : ingest  ~80 µs  compute ~50 µs
  T3 GPU RDMA     : ingest  ~40 µs  compute ~20 µs
  T4 GPUNetIO     : ingest  ~10 µs  compute  ~5 µs
  T5 GPUNetIO+DPU : ingest   ~5 µs  compute  ~3 µs

Usage:
  python scripts/pipeline_test.py --mode replay --duration 30
  python scripts/pipeline_test.py --mode live   --duration 60
  python scripts/pipeline_test.py --mode replay --rate 5000 --duration 60

After the run:
  python src/dashboard/dashboard.py --results results/laptop_test.csv
"""

import argparse
import csv
import json
import math
import queue
import random
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Wire formats — must match C++ headers exactly
# ─────────────────────────────────────────────────────────────────────────────

TICK_FMT   = "=QIHBBdddd"   # 48 bytes — tick_message.h
TICK_SIZE  = struct.calcsize(TICK_FMT)
assert TICK_SIZE == 48

MCAST_ADDR = "239.0.0.1"
MCAST_PORT = 5005

SOURCE_REPLAY, SOURCE_LIVE = 0, 1


def symbol_to_id(sym: str) -> int:
    h = 5381
    for c in sym.encode():
        h = ((h << 5) + h) ^ c
        h &= 0xFFFFFFFF
    return h % 256


@dataclass
class Tick:
    timestamp_ns:  int
    tick_id:       int
    instrument_id: int
    source:        int
    bid:           float
    ask:           float
    last_price:    float
    volume:        float

    @property
    def mid(self) -> float:
        return (self.bid + self.ask) / 2

    @property
    def spread(self) -> float:
        return self.ask - self.bid


def unpack_tick(data: bytes) -> Tick:
    ts, tid, iid, src, _, bid, ask, last, vol = struct.unpack(TICK_FMT, data)
    return Tick(ts, tid, iid, src, bid, ask, last, vol)


def pack_tick(t: Tick) -> bytes:
    return struct.pack(TICK_FMT,
                       t.timestamp_ns, t.tick_id, t.instrument_id,
                       t.source, 0,
                       t.bid, t.ask, t.last_price, t.volume)


# ─────────────────────────────────────────────────────────────────────────────
# Tier profiles
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TierProfile:
    name:           str
    ingest_us_mean: float   # simulated T2-T1 latency (µs)
    ingest_us_std:  float
    compute_us_mean: float  # simulated T3-T2 latency (µs)
    compute_us_std:  float


TIER_PROFILES = {
    1: TierProfile("T1 CPU naive",    200.0, 80.0,  50.0, 20.0),
    2: TierProfile("T2 DPDK",          80.0, 25.0,  50.0, 18.0),
    3: TierProfile("T3 GPU RDMA",      40.0, 12.0,  20.0,  6.0),
    4: TierProfile("T4 GPUNetIO",      10.0,  3.0,   5.0,  1.5),
    5: TierProfile("T5 GPUNetIO+DPU",   5.0,  1.5,   3.0,  0.8),
}


def sample_latency(mean: float, std: float) -> float:
    """Sample latency in µs; clamp to [mean*0.2, mean*5]."""
    v = random.gauss(mean, std)
    return max(mean * 0.2, min(mean * 5, v))


# ─────────────────────────────────────────────────────────────────────────────
# EMA + signal logic  (mirrors process_kernel.cuh)
# ─────────────────────────────────────────────────────────────────────────────

class EMAProcessor:
    def __init__(self, alpha: float = 0.05, threshold: float = 0.0002):
        self.alpha     = alpha
        self.threshold = threshold
        self._ema      = [0.0] * 256

    def process(self, tick: Tick) -> tuple[int, float, float, float]:
        """Returns (signal, mid, spread, ema)."""
        mid    = tick.mid
        spread = tick.spread
        inst   = tick.instrument_id % 256

        if self._ema[inst] == 0.0:
            self._ema[inst] = mid   # seed on first tick

        old_ema = self._ema[inst]
        new_ema = self.alpha * mid + (1 - self.alpha) * old_ema
        self._ema[inst] = new_ema

        signal = 0
        if mid < new_ema - self.threshold * new_ema:
            signal = +1   # price below mean → buy
        elif mid > new_ema + self.threshold * new_ema:
            signal = -1   # price above mean → sell

        return signal, mid, spread, new_ema


# ─────────────────────────────────────────────────────────────────────────────
# BenchmarkResult (for harness collection)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BenchmarkResult:
    tick_id: int
    tier:    int
    t1_ns:   int
    t2_ns:   int
    t3_ns:   int
    t4_ns:   int
    dropped: bool = False

    @property
    def e2e_us(self)     -> float: return (self.t4_ns - self.t1_ns) / 1000
    @property
    def ingest_us(self)  -> float: return (self.t2_ns - self.t1_ns) / 1000
    @property
    def compute_us(self) -> float: return (self.t3_ns - self.t2_ns) / 1000


# ─────────────────────────────────────────────────────────────────────────────
# Signal result (for fill simulator)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SignalResult:
    tick_id:       int
    instrument_id: int
    signal:        int   # +1 / -1 / 0
    mid_price:     float
    spread:        float
    ema:           float
    t4_ns:         int


# ─────────────────────────────────────────────────────────────────────────────
# Multicast receive socket
# ─────────────────────────────────────────────────────────────────────────────

def make_recv_socket() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
        pass
    sock.bind(("", MCAST_PORT))
    mreq = struct.pack("4s4s",
                        socket.inet_aton(MCAST_ADDR),
                        socket.inet_aton("0.0.0.0"))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.settimeout(0.5)
    return sock


# ─────────────────────────────────────────────────────────────────────────────
# Tier receiver thread
# ─────────────────────────────────────────────────────────────────────────────

class TierReceiver(threading.Thread):
    def __init__(self, tier: int,
                 result_queue: queue.Queue,
                 signal_queue: Optional[queue.Queue],
                 stop_event: threading.Event,
                 alpha: float = 0.05, threshold: float = 0.0002):
        super().__init__(daemon=True, name=f"T{tier}-receiver")
        self.tier         = tier
        self.profile      = TIER_PROFILES[tier]
        self.result_q     = result_queue
        self.signal_q     = signal_queue   # only T1 sends to fill sim
        self.stop         = stop_event
        self.processor    = EMAProcessor(alpha=alpha, threshold=threshold)
        self.n_rx         = 0
        self.n_signals    = 0

    def run(self):
        sock = make_recv_socket()
        while not self.stop.is_set():
            try:
                data, _ = sock.recvfrom(TICK_SIZE + 64)
            except socket.timeout:
                continue
            if len(data) < TICK_SIZE:
                continue

            tick = unpack_tick(data[:TICK_SIZE])
            self.n_rx += 1

            # T1 = tick.timestamp_ns (stamped by data_source at sendto)
            t1 = tick.timestamp_ns

            # Simulate tier-specific ingestion latency (T2: tick in GPU memory)
            ingest_ns = int(sample_latency(
                self.profile.ingest_us_mean,
                self.profile.ingest_us_std) * 1000)
            t2 = t1 + ingest_ns

            # Process: EMA + signal
            signal, mid, spread, ema = self.processor.process(tick)

            # Simulate compute latency (T3: kernel done)
            compute_ns = int(sample_latency(
                self.profile.compute_us_mean,
                self.profile.compute_us_std) * 1000)
            t3 = t2 + compute_ns

            # T4: signal written to output buffer (~1µs after T3)
            t4 = t3 + int(sample_latency(1.0, 0.3) * 1000)

            br = BenchmarkResult(tick.tick_id, self.tier,
                                  t1, t2, t3, t4)
            self.result_q.put(br)

            if signal != 0:
                self.n_signals += 1
                if self.signal_q is not None:
                    self.signal_q.put(SignalResult(
                        tick.tick_id, tick.instrument_id, signal,
                        mid, spread, ema, t4))

        sock.close()


# ─────────────────────────────────────────────────────────────────────────────
# Fill simulator thread  (receives from T1 only)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class InstrumentBook:
    position:  int   = 0     # -1 short / 0 flat / +1 long
    entry_px:  float = 0.0
    realized:  float = 0.0
    n_trades:  int   = 0
    n_wins:    int   = 0


class FillSimulator(threading.Thread):
    COMMISSION = 0.0005   # 5 bps per side

    def __init__(self, signal_queue: queue.Queue, stop_event: threading.Event):
        super().__init__(daemon=True, name="fill-simulator")
        self.q     = signal_queue
        self.stop  = stop_event
        self.books: dict[int, InstrumentBook] = {}
        self.trades: list[dict] = []

    def _book(self, inst: int) -> InstrumentBook:
        if inst not in self.books:
            self.books[inst] = InstrumentBook()
        return self.books[inst]

    def _fill(self, sig: SignalResult):
        book = self._book(sig.instrument_id)
        exec_px = sig.mid_price + sig.signal * sig.spread * 0.5

        if book.position == 0:
            book.position = sig.signal
            book.entry_px = exec_px * (1 + sig.signal * self.COMMISSION)
            return

        if book.position != sig.signal:
            close_px = exec_px * (1 - book.position * self.COMMISSION)
            pnl = (close_px - book.entry_px) * book.position
            book.realized += pnl
            book.n_trades += 1
            if pnl > 0:
                book.n_wins += 1
            self.trades.append({
                "tick_id": sig.tick_id,
                "inst":    sig.instrument_id,
                "side":    "SELL" if book.position > 0 else "BUY",
                "price":   close_px,
                "pnl":     pnl,
            })
            book.position = sig.signal
            book.entry_px = exec_px * (1 + sig.signal * self.COMMISSION)

    def run(self):
        while not self.stop.is_set():
            try:
                sig = self.q.get(timeout=0.2)
                self._fill(sig)
            except queue.Empty:
                continue

    @property
    def total_pnl(self) -> float:
        return sum(b.realized for b in self.books.values())

    @property
    def total_trades(self) -> int:
        return sum(b.n_trades for b in self.books.values())

    @property
    def win_rate(self) -> float:
        wins = sum(b.n_wins for b in self.books.values())
        return wins / self.total_trades if self.total_trades > 0 else 0.0

    def sharpe(self) -> float:
        pnls = [t["pnl"] for t in self.trades]
        if len(pnls) < 2:
            return 0.0
        mean = sum(pnls) / len(pnls)
        var  = sum((p - mean) ** 2 for p in pnls) / (len(pnls) - 1)
        return mean / math.sqrt(var) if var > 0 else 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Data source  (replay or live, reused from data_source.py logic)
# ─────────────────────────────────────────────────────────────────────────────

def make_send_socket() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                    socket.inet_aton("0.0.0.0"))
    return sock


def run_replay_source(csv_path: str, rate_hz: int, stop: threading.Event,
                       stats: dict):
    rows = []
    with open(csv_path, newline="") as f:
        for row in csv.DictReader(f):
            rows.append({
                "instrument_id": int(row["instrument_id"]),
                "bid":        float(row["bid"]),
                "ask":        float(row["ask"]),
                "last_price": float(row["last_price"]),
                "volume":     float(row["volume"]),
            })
    if not rows:
        print(f"[source] ERROR: no rows in {csv_path}", file=sys.stderr)
        return

    sock = make_send_socket()
    dest = (MCAST_ADDR, MCAST_PORT)
    ns_per_tick = 1_000_000_000 / rate_hz
    tick_id = 0
    next_ns = time.perf_counter_ns()

    while not stop.is_set():
        for row in rows:
            if stop.is_set():
                break
            payload = struct.pack(TICK_FMT,
                                   time.time_ns(),
                                   tick_id,
                                   row["instrument_id"],
                                   SOURCE_REPLAY, 0,
                                   row["bid"], row["ask"],
                                   row["last_price"], row["volume"])
            while time.perf_counter_ns() < next_ns:
                pass
            sock.sendto(payload, dest)
            tick_id += 1
            next_ns += int(ns_per_tick)
    stats["sent"] = tick_id
    sock.close()


async def _live_source_async(symbols: list[str], stop: threading.Event,
                              stats: dict):
    import websockets
    streams = "/".join(f"{s.lower()}@bookTicker/{s.lower()}@aggTrade"
                        for s in symbols)
    url = f"wss://stream.binance.com:9443/stream?streams={streams}"
    sock = make_send_socket()
    dest = (MCAST_ADDR, MCAST_PORT)
    tick_id = 0

    while not stop.is_set():
        try:
            async with websockets.connect(url, ping_interval=20) as ws:
                async for raw in ws:
                    if stop.is_set():
                        break
                    try:
                        data = json.loads(raw).get("data", json.loads(raw))
                        sym  = data.get("s", "")
                        if not sym:
                            continue
                        iid = symbol_to_id(sym)
                        if "b" in data and "a" in data:
                            bid = float(data["b"]); ask = float(data["a"])
                            last = (bid + ask) / 2; vol = 0.0
                        elif "p" in data and "q" in data:
                            bid = ask = last = float(data["p"])
                            vol = float(data["q"])
                        else:
                            continue
                        payload = struct.pack(TICK_FMT,
                                               time.time_ns(), tick_id, iid,
                                               SOURCE_LIVE, 0,
                                               bid, ask, last, vol)
                        sock.sendto(payload, dest)
                        tick_id += 1
                    except (KeyError, ValueError):
                        pass
        except Exception as e:
            if not stop.is_set():
                await __import__("asyncio").sleep(3)
    stats["sent"] = tick_id
    sock.close()


def run_live_source(symbols: list[str], stop: threading.Event, stats: dict):
    try:
        import websockets as _  # noqa: F401
    except ImportError:
        print("[source] ERROR: pip install websockets", file=sys.stderr)
        return
    import asyncio
    asyncio.run(_live_source_async(symbols, stop, stats))


# ─────────────────────────────────────────────────────────────────────────────
# Result collector + CSV writer
# ─────────────────────────────────────────────────────────────────────────────

def collect_and_write(result_queue: queue.Queue,
                       stop: threading.Event,
                       warmup_sec: int,
                       output_csv: str) -> list[dict]:
    """Drain result_queue, discard warmup, return list of row dicts."""
    rows: list[dict] = []
    warmup_end = time.monotonic() + warmup_sec

    while not stop.is_set() or not result_queue.empty():
        try:
            br: BenchmarkResult = result_queue.get(timeout=0.1)
        except queue.Empty:
            continue
        if time.monotonic() < warmup_end:
            continue   # discard warmup
        rows.append({
            "tier":    br.tier,
            "e2e_us":    br.e2e_us,
            "ingest_us": br.ingest_us,
            "compute_us": br.compute_us,
        })

    return rows


def compute_stats(rows: list[dict]) -> dict[int, dict]:
    """Compute per-tier stats from collected rows."""
    from collections import defaultdict
    buckets: dict[int, list[dict]] = defaultdict(list)
    for r in rows:
        buckets[r["tier"]].append(r)

    stats = {}
    for tier, data in buckets.items():
        e2e     = sorted(d["e2e_us"]    for d in data)
        ingest  = sorted(d["ingest_us"] for d in data)
        compute = sorted(d["compute_us"] for d in data)
        n = len(e2e)

        def pct(v, p): return v[int(p * (n-1))] if n else 0

        stats[tier] = {
            "n":          n,
            "throughput": n,   # ticks measured
            "e2e_p50":    pct(e2e, 0.50),
            "e2e_p95":    pct(e2e, 0.95),
            "e2e_p99":    pct(e2e, 0.99),
            "e2e_mean":   sum(e2e) / n if n else 0,
            "ingest_p50": pct(ingest, 0.50),
            "ingest_p95": pct(ingest, 0.95),
            "ingest_p99": pct(ingest, 0.99),
            "ingest_mean": sum(ingest) / n if n else 0,
            "compute_p50": pct(compute, 0.50),
            "compute_p95": pct(compute, 0.95),
            "compute_p99": pct(compute, 0.99),
            "compute_mean": sum(compute) / n if n else 0,
        }
    return stats


def write_csv(stats: dict[int, dict], path: str, duration_sec: int):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "run_id","tier","rate_hz","repetition","n_ticks","drop_rate",
            "e2e_p50_us","e2e_p95_us","e2e_p99_us","e2e_mean_us",
            "ingest_p50_us","ingest_p95_us","ingest_p99_us","ingest_mean_us",
            "compute_p50_us","compute_p95_us","compute_p99_us","compute_mean_us",
            "throughput_per_sec",
        ])
        for tier, s in sorted(stats.items()):
            tput = s["n"] / duration_sec if duration_sec > 0 else 0
            w.writerow([
                tier, tier, 0, 1, s["n"], 0.0,
                round(s["e2e_p50"],2),  round(s["e2e_p95"],2),
                round(s["e2e_p99"],2),  round(s["e2e_mean"],2),
                round(s["ingest_p50"],2), round(s["ingest_p95"],2),
                round(s["ingest_p99"],2), round(s["ingest_mean"],2),
                round(s["compute_p50"],2), round(s["compute_p95"],2),
                round(s["compute_p99"],2), round(s["compute_mean"],2),
                round(tput, 1),
            ])


# ─────────────────────────────────────────────────────────────────────────────
# Live stats display
# ─────────────────────────────────────────────────────────────────────────────

def print_live_stats(receivers: list[TierReceiver],
                      fill_sim: FillSimulator,
                      source_stats: dict,
                      elapsed: float):
    print(f"\n{'─'*72}")
    print(f"  Elapsed: {elapsed:.0f}s   "
          f"Source sent: {source_stats.get('sent', '...')}")
    print(f"  {'Tier':<22} {'Rx ticks':>10} {'Signals':>10}")
    print(f"  {'─'*42}")
    for r in receivers:
        print(f"  {r.profile.name:<22} {r.n_rx:>10,} {r.n_signals:>10,}")
    print(f"\n  Fill simulator  (T1 signals only):")
    print(f"    Trades:   {fill_sim.total_trades:,}")
    print(f"    P&L:      {fill_sim.total_pnl:.6f}")
    print(f"    Win rate: {fill_sim.win_rate*100:.1f}%")
    print(f"    Sharpe:   {fill_sim.sharpe():.3f}")


def print_summary(stats: dict[int, dict], fill_sim: FillSimulator,
                   csv_path: str):
    print(f"\n{'═'*72}")
    print("  PIPELINE TEST SUMMARY")
    print(f"{'═'*72}")
    t1_e2e = stats.get(1, {}).get("e2e_p50", 1)
    print(f"\n  {'Tier':<22} {'n ticks':>8} "
          f"{'p50 µs':>8} {'p99 µs':>8} {'speedup':>8}")
    print(f"  {'─'*56}")
    for tier, s in sorted(stats.items()):
        speedup = t1_e2e / s["e2e_p50"] if s["e2e_p50"] > 0 else 0
        name = TIER_PROFILES[tier].name
        print(f"  {name:<22} {s['n']:>8,} "
              f"{s['e2e_p50']:>8.1f} {s['e2e_p99']:>8.1f} {speedup:>7.1f}x")

    print(f"\n  Fill Simulator (T1 signals):")
    print(f"    Total trades : {fill_sim.total_trades:,}")
    print(f"    Total P&L    : {fill_sim.total_pnl:.6f}")
    print(f"    Win rate     : {fill_sim.win_rate*100:.1f}%")
    print(f"    Sharpe ratio : {fill_sim.sharpe():.3f}")
    print(f"\n  Results CSV: {csv_path}")
    print(f"  Visualise : python src/dashboard/dashboard.py "
          f"--results {csv_path}")
    print(f"{'═'*72}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Full pipeline integration test (laptop, no GPU required)")
    parser.add_argument("--mode",     choices=["replay","live","both"],
                        default="replay")
    parser.add_argument("--csv",      default="data/ticks.csv")
    parser.add_argument("--rate",     type=int, default=2000,
                        help="Replay rate in msg/sec (default: 2000)")
    parser.add_argument("--symbols",  default="BTCUSDT,ETHUSDT")
    parser.add_argument("--duration", type=int, default=30,
                        help="Measurement duration in seconds (default: 30)")
    parser.add_argument("--warmup",   type=int, default=3,
                        help="Warmup period in seconds (default: 3)")
    parser.add_argument("--tiers",    default="1,2,3,4,5",
                        help="Comma-separated tiers to run (default: 1,2,3,4,5)")
    parser.add_argument("--output",    default="results/laptop_test.csv")
    parser.add_argument("--alpha",     type=float, default=0.05,
                        help="EMA alpha, higher = faster tracking (default: 0.05)")
    parser.add_argument("--threshold", type=float, default=0.0002,
                        help="Signal threshold fraction (default: 0.0002 = 2 bps)")
    args = parser.parse_args()

    tiers   = [int(t) for t in args.tiers.split(",") if t.strip()]
    symbols = [s.strip() for s in args.symbols.split(",") if s.strip()]
    total   = args.warmup + args.duration

    print(f"\n{'═'*72}")
    print(f"  GPU Tick Pipeline — Integration Test")
    print(f"{'═'*72}")
    print(f"  Mode     : {args.mode}")
    print(f"  Tiers    : {tiers}")
    if args.mode in ("replay", "both"):
        print(f"  CSV      : {args.csv}  rate={args.rate:,}/sec")
    if args.mode in ("live", "both"):
        print(f"  Symbols  : {', '.join(symbols)}")
    print(f"  Warmup   : {args.warmup}s   Measure: {args.duration}s")
    print(f"  Output   : {args.output}")
    print(f"{'─'*72}\n")

    stop        = threading.Event()
    result_q    = queue.Queue(maxsize=200_000)
    signal_q    = queue.Queue(maxsize=50_000)
    source_stats: dict = {}

    # ── Data source thread ────────────────────────────────────────────────
    if args.mode == "replay":
        src_thread = threading.Thread(
            target=run_replay_source,
            args=(args.csv, args.rate, stop, source_stats),
            daemon=True, name="data-source")
    elif args.mode == "live":
        src_thread = threading.Thread(
            target=run_live_source,
            args=(symbols, stop, source_stats),
            daemon=True, name="data-source")
    else:  # both
        src_thread = threading.Thread(
            target=lambda: (
                run_replay_source(args.csv, args.rate // 2, stop, source_stats),
                run_live_source(symbols, stop, source_stats)
            ),
            daemon=True, name="data-source")

    # ── Tier receivers ────────────────────────────────────────────────────
    receivers = []
    for tier in tiers:
        sig_q = signal_q if tier == 1 else None
        rx = TierReceiver(tier, result_q, sig_q, stop,
                          alpha=args.alpha, threshold=args.threshold)
        receivers.append(rx)

    # ── Fill simulator ────────────────────────────────────────────────────
    fill_sim = FillSimulator(signal_q, stop)

    # ── Start everything ──────────────────────────────────────────────────
    print("[pipeline] starting components...")
    fill_sim.start()
    for rx in receivers:
        rx.start()
    time.sleep(0.3)   # let receivers bind sockets
    src_thread.start()

    print(f"[pipeline] running for {total}s "
          f"(first {args.warmup}s warmup discarded)...\n")

    # ── Collect results while running ─────────────────────────────────────
    all_rows: list[dict] = []
    warmup_end  = time.monotonic() + args.warmup
    measure_end = time.monotonic() + total
    t_start     = time.monotonic()
    last_print  = t_start

    while time.monotonic() < measure_end:
        now = time.monotonic()
        # Drain result queue
        while True:
            try:
                br: BenchmarkResult = result_q.get_nowait()
                if now > warmup_end:
                    all_rows.append({
                        "tier":       br.tier,
                        "e2e_us":     br.e2e_us,
                        "ingest_us":  br.ingest_us,
                        "compute_us": br.compute_us,
                    })
            except queue.Empty:
                break

        # Progress print every 5s
        if now - last_print >= 5.0:
            print_live_stats(receivers, fill_sim, source_stats,
                              now - t_start)
            last_print = now

        time.sleep(0.05)

    # ── Stop all threads ──────────────────────────────────────────────────
    print("\n[pipeline] stopping...")
    stop.set()
    src_thread.join(timeout=3)
    for rx in receivers:
        rx.join(timeout=2)
    fill_sim.join(timeout=2)

    # Drain any remaining results
    while True:
        try:
            br = result_q.get_nowait()
            all_rows.append({
                "tier":       br.tier,
                "e2e_us":     br.e2e_us,
                "ingest_us":  br.ingest_us,
                "compute_us": br.compute_us,
            })
        except queue.Empty:
            break

    # ── Compute stats + write CSV ─────────────────────────────────────────
    stats = compute_stats(all_rows)
    write_csv(stats, args.output, args.duration)

    print_summary(stats, fill_sim, args.output)


if __name__ == "__main__":
    main()
