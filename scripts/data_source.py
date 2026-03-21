#!/usr/bin/env python3
"""
data_source.py — Python equivalent of data_source.cpp for local testing.

Sends TickMessage UDP multicast packets on 239.0.0.1:5005.
Same 48-byte wire format as the C++ version — the C++ receivers will
understand packets from this script and vice versa.

Modes:
  replay  — reads CSV, sends at --rate msg/sec with busy-wait timing
  live    — subscribes to Binance WebSocket, forwards as UDP multicast
  both    — replay + live simultaneously on separate threads

Usage:
  python scripts/data_source.py --mode replay --rate 1000
  python scripts/data_source.py --mode live --symbols BTCUSDT,ETHUSDT
  python scripts/data_source.py --mode replay --rate 500 --loop

Dependencies (live mode only):
  pip install websockets
"""

import argparse
import asyncio
import csv
import json
import socket
import struct
import threading
import time
import sys
from dataclasses import dataclass
from pathlib import Path

# ── TickMessage wire format (must match tick_message.h exactly) ────────────────
#   timestamp_ns  uint64   8
#   tick_id       uint32   4
#   instrument_id uint16   2
#   source        uint8    1   (0=replay, 1=live)
#   _pad          uint8    1
#   bid           double   8
#   ask           double   8
#   last_price    double   8
#   volume        double   8
#                        = 48 bytes
TICK_FMT  = "=QIHBBdddd"
TICK_SIZE = struct.calcsize(TICK_FMT)
assert TICK_SIZE == 48, f"TickMessage size mismatch: {TICK_SIZE}"

MCAST_ADDR = "239.0.0.1"
MCAST_PORT = 5005
SOURCE_REPLAY = 0
SOURCE_LIVE   = 1


def symbol_to_id(sym: str) -> int:
    """djb2 hash matching symbol_to_id() in tick_message.h"""
    h = 5381
    for c in sym.encode():
        h = ((h << 5) + h) ^ c
        h &= 0xFFFFFFFF
    return h % 256


def pack_tick(tick_id: int, instrument_id: int, source: int,
              bid: float, ask: float, last_price: float, volume: float) -> bytes:
    ts_ns = time.time_ns()
    return struct.pack(TICK_FMT,
                       ts_ns, tick_id, instrument_id, source, 0,
                       bid, ask, last_price, volume)


def make_send_socket() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    # On Windows, send multicast on the default interface (0.0.0.0)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                    socket.inet_aton("0.0.0.0"))
    return sock


# ── Replay mode ────────────────────────────────────────────────────────────────

def load_csv(path: str) -> list[dict]:
    rows = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            rows.append({
                "instrument_id": int(row["instrument_id"]),
                "bid":        float(row["bid"]),
                "ask":        float(row["ask"]),
                "last_price": float(row["last_price"]),
                "volume":     float(row["volume"]),
            })
    return rows


def run_replay(csv_path: str, rate_hz: int, stop_event: threading.Event,
               loop_forever: bool = True) -> None:
    rows = load_csv(csv_path)
    if not rows:
        print(f"[replay] ERROR: no rows loaded from {csv_path}", file=sys.stderr)
        return

    sock = make_send_socket()
    dest = (MCAST_ADDR, MCAST_PORT)
    ns_per_tick = 1_000_000_000 / rate_hz
    tick_id = 0

    print(f"[replay] {len(rows):,} ticks loaded | rate={rate_hz:,} msg/sec "
          f"| interval={ns_per_tick/1000:.1f} µs")

    while not stop_event.is_set():
        next_send_ns = time.perf_counter_ns()

        for row in rows:
            if stop_event.is_set():
                break

            payload = pack_tick(tick_id, row["instrument_id"], SOURCE_REPLAY,
                                 row["bid"], row["ask"], row["last_price"], row["volume"])
            # Busy-wait until send slot
            while time.perf_counter_ns() < next_send_ns:
                pass

            sock.sendto(payload, dest)
            tick_id += 1
            next_send_ns += int(ns_per_tick)

            if tick_id % 10000 == 0:
                print(f"[replay] sent {tick_id:,} ticks", end="\r", flush=True)

        if not loop_forever:
            break

    sock.close()
    print(f"\n[replay] done — sent {tick_id:,} ticks total")


# ── Live Binance mode ──────────────────────────────────────────────────────────

async def _live_worker(symbols: list[str], stop_event: threading.Event) -> None:
    try:
        import websockets
    except ImportError:
        print("[live] ERROR: 'websockets' not installed. Run: pip install websockets",
              file=sys.stderr)
        return

    streams = "/".join(
        f"{sym.lower()}@bookTicker/{sym.lower()}@aggTrade"
        for sym in symbols
    )
    url = f"wss://stream.binance.com:9443/stream?streams={streams}"

    sock = make_send_socket()
    dest = (MCAST_ADDR, MCAST_PORT)
    tick_id = 0
    RECONNECT_DELAY = 3

    print(f"[live] connecting to Binance | symbols: {', '.join(symbols)}")

    while not stop_event.is_set():
        try:
            async with websockets.connect(url, ping_interval=20) as ws:
                print("[live] connected")
                async for raw in ws:
                    if stop_event.is_set():
                        break
                    try:
                        msg = json.loads(raw)
                        data = msg.get("data", msg)
                        sym  = data.get("s", "")
                        if not sym:
                            continue

                        inst_id = symbol_to_id(sym)

                        # bookTicker: b=best bid, a=best ask
                        if "b" in data and "a" in data:
                            bid  = float(data["b"])
                            ask  = float(data["a"])
                            last = (bid + ask) / 2
                            vol  = 0.0
                        # aggTrade: p=price, q=quantity
                        elif "p" in data and "q" in data:
                            px  = float(data["p"])
                            bid = ask = last = px
                            vol = float(data["q"])
                        else:
                            continue

                        payload = pack_tick(tick_id, inst_id, SOURCE_LIVE,
                                             bid, ask, last, vol)
                        sock.sendto(payload, dest)
                        tick_id += 1

                        if tick_id % 100 == 0:
                            print(f"[live] {sym:10s} bid={bid:.2f} ask={ask:.2f} "
                                  f"(tick #{tick_id})", end="\r", flush=True)

                    except (KeyError, ValueError):
                        pass

        except Exception as e:
            if stop_event.is_set():
                break
            print(f"\n[live] disconnected: {e} — retrying in {RECONNECT_DELAY}s")
            await asyncio.sleep(RECONNECT_DELAY)

    sock.close()
    print(f"\n[live] done — sent {tick_id:,} ticks total")


def run_live(symbols: list[str], stop_event: threading.Event) -> None:
    asyncio.run(_live_worker(symbols, stop_event))


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="GPU tick pipeline — Python data source (for local testing)")
    parser.add_argument("--mode", choices=["replay", "live", "both"],
                        required=True)
    parser.add_argument("--csv",     default="data/ticks.csv")
    parser.add_argument("--rate",    type=int, default=1000,
                        help="Replay send rate in msg/sec (default: 1000)")
    parser.add_argument("--symbols", default="BTCUSDT,ETHUSDT",
                        help="Comma-separated Binance symbols for live mode")
    parser.add_argument("--loop",    action="store_true",
                        help="Loop CSV replay forever (default: True for mode=replay)")
    args = parser.parse_args()

    symbols   = [s.strip() for s in args.symbols.split(",") if s.strip()]
    stop_flag = threading.Event()

    try:
        if args.mode == "replay":
            run_replay(args.csv, args.rate, stop_flag, loop_forever=True)

        elif args.mode == "live":
            run_live(symbols, stop_flag)

        elif args.mode == "both":
            print(f"[both] replay @ {args.rate // 2}/sec + live simultaneously")
            t_replay = threading.Thread(
                target=run_replay,
                args=(args.csv, args.rate // 2, stop_flag, True),
                daemon=True)
            t_live = threading.Thread(
                target=run_live,
                args=(symbols, stop_flag),
                daemon=True)
            t_replay.start()
            t_live.start()
            t_replay.join()
            t_live.join()

    except KeyboardInterrupt:
        print("\n[data_source] stopping...")
        stop_flag.set()


if __name__ == "__main__":
    main()
