#!/usr/bin/env python3
"""
send_ticks.py — Reusable UDP tick sender for testing gpu_receiver.

Sends 48-byte TickMessage packets (matching tick_message.h) via UDP
multicast on 239.0.0.1:5005. Works in two modes:

  generate  — synthesize ticks on the fly (no CSV needed)
  replay    — read from a CSV file (same format as data/ticks.csv)

The --iface option binds multicast to a specific network interface IP,
which is critical for cross-PF loopback testing on BlueField-3.

Examples:
  # Generate 1000 ticks at 100/sec on PF0 (cross-PF loopback)
  python3 scripts/send_ticks.py --mode generate --rate 100 --count 1000 --iface 10.10.10.1

  # Generate forever at 10000/sec
  python3 scripts/send_ticks.py --mode generate --rate 10000 --iface 10.10.10.1

  # Replay from CSV
  python3 scripts/send_ticks.py --mode replay --csv data/ticks.csv --rate 5000 --iface 10.10.10.1

  # Quick 100-tick burst (no rate limiting)
  python3 scripts/send_ticks.py --mode generate --count 100 --burst --iface 10.10.10.1

  # Default (generate 1000 ticks at 1000/sec on default interface)
  python3 scripts/send_ticks.py
"""

import argparse
import csv
import random
import socket
import struct
import sys
import time

# ── TickMessage wire format (must match tick_message.h exactly) ────────────────
TICK_FMT  = "=QIHBBdddd"
TICK_SIZE = struct.calcsize(TICK_FMT)
assert TICK_SIZE == 48, f"TickMessage size mismatch: {TICK_SIZE}"

MCAST_ADDR = "239.0.0.1"
MCAST_PORT = 5005
SOURCE_REPLAY = 0


def make_socket(iface_ip: str) -> socket.socket:
    """Create a UDP multicast send socket bound to the given interface IP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                    socket.inet_aton(iface_ip))
    return sock


def pack_tick(tick_id: int, instrument_id: int,
              bid: float, ask: float, last_price: float, volume: float) -> bytes:
    """Pack a single TickMessage into 48 bytes."""
    return struct.pack(TICK_FMT,
                       time.time_ns(),  # timestamp_ns
                       tick_id,
                       instrument_id,
                       SOURCE_REPLAY,
                       0,               # _pad
                       bid, ask, last_price, volume)


def generate_ticks(sock: socket.socket, dest: tuple,
                   rate_hz: int, count: int, burst: bool) -> None:
    """Synthesize and send ticks with a random-walk mid price."""
    mid = 42000.0  # starting price (like BTC)
    spread = mid * 0.0002
    ns_per_tick = 0 if burst else (1_000_000_000 / rate_hz)

    label = "burst" if burst else f"{rate_hz}/sec"
    total = "∞" if count == 0 else str(count)
    print(f"[send_ticks] generate mode | {label} | count={total}")

    tick_id = 0
    next_send_ns = time.perf_counter_ns()

    try:
        while count == 0 or tick_id < count:
            # Random walk
            mid *= 1.0 + random.gauss(0, 0.001)
            spread = mid * 0.0002
            bid = mid - spread / 2
            ask = mid + spread / 2
            last = mid + random.gauss(0, spread * 0.1)
            vol = random.uniform(0.01, 10.0)

            payload = pack_tick(tick_id, tick_id % 256, bid, ask, last, vol)

            if not burst:
                while time.perf_counter_ns() < next_send_ns:
                    pass

            sock.sendto(payload, dest)
            tick_id += 1
            next_send_ns += int(ns_per_tick)

            if tick_id % 1000 == 0:
                print(f"  sent {tick_id:,} ticks", end="\r", flush=True)

    except KeyboardInterrupt:
        pass

    print(f"\n[send_ticks] done — sent {tick_id:,} ticks")


def replay_ticks(sock: socket.socket, dest: tuple,
                 csv_path: str, rate_hz: int, loop: bool) -> None:
    """Read ticks from CSV and replay at the given rate."""
    rows = []
    with open(csv_path, newline="") as f:
        for row in csv.DictReader(f):
            rows.append(row)

    if not rows:
        print(f"[send_ticks] ERROR: no rows in {csv_path}", file=sys.stderr)
        return

    ns_per_tick = 1_000_000_000 / rate_hz
    tick_id = 0
    print(f"[send_ticks] replay mode | {len(rows):,} rows | {rate_hz}/sec | loop={loop}")

    try:
        while True:
            next_send_ns = time.perf_counter_ns()
            for row in rows:
                payload = pack_tick(
                    tick_id,
                    int(row["instrument_id"]),
                    float(row["bid"]),
                    float(row["ask"]),
                    float(row["last_price"]),
                    float(row["volume"]),
                )

                while time.perf_counter_ns() < next_send_ns:
                    pass

                sock.sendto(payload, dest)
                tick_id += 1
                next_send_ns += int(ns_per_tick)

                if tick_id % 1000 == 0:
                    print(f"  sent {tick_id:,} ticks", end="\r", flush=True)

            if not loop:
                break

    except KeyboardInterrupt:
        pass

    print(f"\n[send_ticks] done — sent {tick_id:,} ticks")


def main():
    parser = argparse.ArgumentParser(
        description="Send TickMessage UDP multicast packets for gpu_receiver testing")
    parser.add_argument("--mode", choices=["generate", "replay"], default="generate",
                        help="generate = synthetic ticks (no CSV); replay = from CSV")
    parser.add_argument("--iface", default="0.0.0.0",
                        help="IP of the network interface to send from (e.g. 10.10.10.1)")
    parser.add_argument("--rate", type=int, default=1000,
                        help="Send rate in ticks/sec (default: 1000)")
    parser.add_argument("--count", type=int, default=1000,
                        help="Number of ticks to send. 0 = infinite (default: 1000)")
    parser.add_argument("--burst", action="store_true",
                        help="Send all ticks as fast as possible (ignore --rate)")
    parser.add_argument("--csv", default="data/ticks.csv",
                        help="CSV file for replay mode")
    parser.add_argument("--loop", action="store_true",
                        help="Loop CSV replay forever")
    args = parser.parse_args()

    sock = make_socket(args.iface)
    dest = (MCAST_ADDR, MCAST_PORT)

    print(f"[send_ticks] target={MCAST_ADDR}:{MCAST_PORT} iface={args.iface}")

    if args.mode == "generate":
        generate_ticks(sock, dest, args.rate, args.count, args.burst)
    else:
        replay_ticks(sock, dest, args.csv, args.rate, args.loop)

    sock.close()


if __name__ == "__main__":
    main()
