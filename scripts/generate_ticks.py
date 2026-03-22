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
import random
import time

INSTRUMENTS = [
    (0, 42000.0),   # instrument_id=0, starting mid
    (1, 2500.0),    # instrument_id=1
    (2, 300.0),     # instrument_id=2
]


def generate(rows: int, n_instruments: int, output: str) -> None:
    instruments = INSTRUMENTS[:n_instruments]
    mids = {iid: mid for iid, mid in instruments}

    print(f"Generating {rows:,} ticks for {n_instruments} instrument(s) -> {output}")

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
    parser.add_argument("--symbols",     type=int, default=2,
                        help="Number of instruments (1-3)")
    parser.add_argument("--output",      default="data/ticks.csv")
    args = parser.parse_args()

    args.symbols = max(1, min(3, args.symbols))
    generate(args.rows, args.symbols, args.output)
