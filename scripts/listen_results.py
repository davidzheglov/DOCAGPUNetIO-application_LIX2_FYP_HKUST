#!/usr/bin/env python3
"""
listen_results.py — Listen for BenchmarkResult and SignalResult UDP packets
from gpu_receiver, and print them in real time.

This is the diagnostic tool to verify gpu_receiver is actually processing
packets end-to-end. It listens on the same ports as benchmark_harness (5010)
and fill_simulator (5006).

Usage:
  python3 scripts/listen_results.py              # listen on both ports
  python3 scripts/listen_results.py --port 5010  # harness results only
  python3 scripts/listen_results.py --port 5006  # signal results only
"""

import argparse
import select
import socket
import struct
import sys
import time

# BenchmarkResult: 56 bytes
BENCH_FMT  = "=QQQQQQBBxxxxxx"
BENCH_SIZE = 56
BENCH_PORT = 5010

# SignalResult: 64 bytes
SIGNAL_FMT  = "=QQQHbbfdddd"
SIGNAL_SIZE = 64
SIGNAL_PORT = 5006


def make_listener(port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.setblocking(False)
    return s


def decode_bench(data: bytes) -> dict:
    if len(data) < BENCH_SIZE:
        return {"error": f"too short: {len(data)} bytes"}
    fields = struct.unpack(BENCH_FMT, data[:BENCH_SIZE])
    return {
        "tick_id": fields[0],
        "t1_ns":   fields[1],
        "t2_ns":   fields[2],
        "t3_ns":   fields[3],
        "t4_ns":   fields[4],
        "compute_ns": fields[5],
        "tier":    fields[6],
        "dropped": fields[7],
    }


def decode_signal(data: bytes) -> dict:
    if len(data) < SIGNAL_SIZE:
        return {"error": f"too short: {len(data)} bytes"}
    fields = struct.unpack(SIGNAL_FMT, data[:SIGNAL_SIZE])
    return {
        "tick_id":       fields[0],
        "t3_ns":         fields[1],
        "t4_ns":         fields[2],
        "instrument_id": fields[3],
        "signal":        fields[4],
        "rsi_signal":    fields[5],
        "rsi":           fields[6],
        "mid_price":     fields[7],
        "spread":        fields[8],
        "fast_ema":      fields[9],
        "slow_ema":      fields[10],
    }


def main():
    parser = argparse.ArgumentParser(description="Listen for gpu_receiver output")
    parser.add_argument("--port", type=int, default=0,
                        help="Listen on specific port only (0 = both 5010 and 5006)")
    args = parser.parse_args()

    sockets = {}
    if args.port == 0 or args.port == BENCH_PORT:
        sockets[BENCH_PORT] = make_listener(BENCH_PORT)
        print(f"[listen] listening on port {BENCH_PORT} (BenchmarkResult)")
    if args.port == 0 or args.port == SIGNAL_PORT:
        sockets[SIGNAL_PORT] = make_listener(SIGNAL_PORT)
        print(f"[listen] listening on port {SIGNAL_PORT} (SignalResult)")

    if not sockets:
        print(f"[listen] ERROR: invalid port {args.port}", file=sys.stderr)
        return

    bench_count = 0
    signal_count = 0
    start_time = time.time()
    last_print = start_time

    print("[listen] waiting for packets from gpu_receiver...")
    print("=" * 80)

    try:
        while True:
            readable, _, _ = select.select(list(sockets.values()), [], [], 1.0)

            for sock in readable:
                data, addr = sock.recvfrom(4096)
                port = sock.getsockname()[1]

                if port == BENCH_PORT:
                    bench_count += 1
                    r = decode_bench(data)
                    if bench_count <= 10 or bench_count % 100 == 0:
                        print(f"[BENCH #{bench_count:>6}] tick={r.get('tick_id',0):>6} "
                              f"tier={r.get('tier',0)} "
                              f"t1={r.get('t1_ns',0)} "
                              f"t2={r.get('t2_ns',0)} "
                              f"t3={r.get('t3_ns',0)} "
                              f"t4={r.get('t4_ns',0)} "
                              f"compute={r.get('compute_ns',0)} "
                              f"drop={r.get('dropped',0)}")

                elif port == SIGNAL_PORT:
                    signal_count += 1
                    r = decode_signal(data)
                    if signal_count <= 10 or signal_count % 100 == 0:
                        print(f"[SIGNAL #{signal_count:>6}] tick={r.get('tick_id',0):>6} "
                              f"inst={r.get('instrument_id',0):>3} "
                              f"sig={r.get('signal',0):+d} "
                              f"rsi={r.get('rsi',0):6.2f} "
                              f"mid={r.get('mid_price',0):12.2f} "
                              f"spread={r.get('spread',0):10.4f} "
                              f"fast={r.get('fast_ema',0):12.2f} "
                              f"slow={r.get('slow_ema',0):12.2f}")

            # Periodic summary every 2 seconds
            now = time.time()
            if now - last_print > 2.0:
                elapsed = now - start_time
                print(f"  --- {elapsed:.1f}s elapsed | "
                      f"bench={bench_count} ({bench_count/max(elapsed,0.001):.0f}/s) | "
                      f"signal={signal_count} ({signal_count/max(elapsed,0.001):.0f}/s) ---",
                      flush=True)
                last_print = now

    except KeyboardInterrupt:
        elapsed = time.time() - start_time
        print(f"\n{'=' * 80}")
        print(f"[listen] stopped after {elapsed:.1f}s")
        print(f"  BenchmarkResults received: {bench_count}")
        print(f"  SignalResults received:    {signal_count}")

    for s in sockets.values():
        s.close()


if __name__ == "__main__":
    main()
