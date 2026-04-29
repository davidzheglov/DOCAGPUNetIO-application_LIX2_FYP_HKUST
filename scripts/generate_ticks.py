#!/usr/bin/env python3
"""
generate_ticks.py — generate a synthetic tick CSV for replay mode.

Simulates mid-price random walk with realistic bid/ask spread and volume.

Usage:
    python scripts/generate_ticks.py --rows 1000000 --output data/ticks.csv
    python scripts/generate_ticks.py --rows 100000 --symbols 2  # 2 instruments
"""
import argparse
import csv
import os
import random
import time

MAX_INSTRUMENTS = 256  # matches MAX_INSTRUMENTS in tick_message.h


def _starting_prices(n: int):
    """Generate plausible starting mid prices across n instruments.
    First three are calibrated to BTC/ETH/SOL-ish; the rest are spread
    log-uniformly across [1, 100_000] so the per-instrument EMA tables
    in the receivers see a realistic distribution of magnitudes."""
    seeds = [42000.0, 2500.0, 300.0]
    if n <= len(seeds):
        return [(i, seeds[i]) for i in range(n)]
    rng = random.Random(0xBEEF)
    extras = [10 ** rng.uniform(0, 5) for _ in range(n - len(seeds))]
    return [(i, p) for i, p in enumerate(seeds + extras)]


def generate(rows: int, n_instruments: int, output: str) -> None:
    n_instruments = max(1, min(MAX_INSTRUMENTS, n_instruments))
    instruments = _starting_prices(n_instruments)
    mids = {iid: mid for iid, mid in instruments}

    print(f"Generating {rows:,} ticks for {n_instruments} instrument(s) -> {output}")
    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)

    t_ns = int(time.time_ns())
    interval_ns = 1_000_000  # 1 ms between ticks (doesn't matter — replay re-stamps)

    with open(output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp_ns", "instrument_id", "bid", "ask",
                          "last_price", "volume"])

        for i in range(rows):
            iid, _ = instruments[i % n_instruments]
            mid = mids[iid]

            # Random walk: ±0.1%
            mid *= 1.0 + random.gauss(0, 0.001)
            mids[iid] = mid

            spread = mid * 0.0002  # 2 bps spread
            bid = mid - spread / 2
            ask = mid + spread / 2
            last = mid + random.gauss(0, spread * 0.1)
            volume = abs(random.gauss(1.0, 0.5))

            writer.writerow([
                t_ns + i * interval_ns,
                iid,
                f"{bid:.8f}",
                f"{ask:.8f}",
                f"{last:.8f}",
                f"{volume:.6f}",
            ])

    print(f"Done. {rows:,} rows written.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows",        type=int, default=1_000_000)
    parser.add_argument("--symbols",     type=int, default=32,
                        help=f"Number of instruments (1-{MAX_INSTRUMENTS})")
    parser.add_argument("--output",      default="data/ticks.csv")
    args = parser.parse_args()

    generate(args.rows, args.symbols, args.output)
