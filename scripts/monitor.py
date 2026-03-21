#!/usr/bin/env python3
"""
monitor.py — receive and display TickMessage UDP multicast packets.

Shows each tick arriving from data_source.py (or the C++ data_source binary).
Decodes the exact same 48-byte TickMessage wire format.

Useful for:
  - Verifying replay and live modes produce valid packets
  - Measuring receive rate and one-way latency (T1 → now)
  - Checking that instrument IDs and prices look correct

Usage:
  python scripts/monitor.py                    # show all ticks
  python scripts/monitor.py --rate-only        # just show msg/sec
  python scripts/monitor.py --max 1000         # stop after 1000 ticks

Run in a separate terminal while data_source.py is running.
"""

import argparse
import socket
import struct
import time
import sys

# ── TickMessage wire format (matches tick_message.h) ─────────────────────────
TICK_FMT  = "=QIHBBdddd"
TICK_SIZE = struct.calcsize(TICK_FMT)  # must be 48
assert TICK_SIZE == 48

MCAST_ADDR = "239.0.0.1"
MCAST_PORT = 5005

SOURCE_NAMES = {0: "replay", 1: "live"}


def unpack_tick(data: bytes) -> dict:
    ts_ns, tick_id, instrument_id, source, _pad, bid, ask, last, volume = \
        struct.unpack(TICK_FMT, data)
    return {
        "ts_ns":         ts_ns,
        "tick_id":       tick_id,
        "instrument_id": instrument_id,
        "source":        SOURCE_NAMES.get(source, f"?{source}"),
        "bid":           bid,
        "ask":           ask,
        "last_price":    last,
        "volume":        volume,
        "mid":           (bid + ask) / 2,
        "spread_bps":    (ask - bid) / ((bid + ask) / 2) * 10000 if bid > 0 else 0,
    }


def make_recv_socket() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
        pass  # SO_REUSEPORT not available on Windows

    sock.bind(("", MCAST_PORT))

    # Join multicast group
    import struct as s
    mreq = s.pack("4s4s",
                   socket.inet_aton(MCAST_ADDR),
                   socket.inet_aton("0.0.0.0"))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.settimeout(2.0)
    return sock


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Monitor TickMessage UDP multicast stream")
    parser.add_argument("--rate-only", action="store_true",
                        help="Only show msg/sec, not individual ticks")
    parser.add_argument("--max",  type=int, default=0,
                        help="Stop after N ticks (0 = unlimited)")
    parser.add_argument("--every", type=int, default=1,
                        help="Print every Nth tick (default: 1 = all)")
    args = parser.parse_args()

    sock = make_recv_socket()
    print(f"[monitor] listening on {MCAST_ADDR}:{MCAST_PORT} "
          f"(waiting for data_source to send...)\n")

    n_rx        = 0
    n_errors    = 0
    window_rx   = 0
    window_start = time.perf_counter()
    last_rate_report = window_start
    latencies   = []   # T1 → receive time, in µs

    # Header
    if not args.rate_only:
        print(f"{'tick_id':>10}  {'src':>6}  {'inst':>4}  "
              f"{'mid':>12}  {'spread_bps':>10}  {'volume':>10}  "
              f"{'latency_us':>12}")
        print("─" * 80)

    try:
        while True:
            try:
                data, _ = sock.recvfrom(TICK_SIZE + 64)
            except socket.timeout:
                elapsed = time.perf_counter() - last_rate_report
                if elapsed > 2.0:
                    print("[monitor] no packets received (is data_source running?)",
                          flush=True)
                    last_rate_report = time.perf_counter()
                continue

            if len(data) < TICK_SIZE:
                n_errors += 1
                continue

            recv_ns = time.time_ns()
            tick = unpack_tick(data[:TICK_SIZE])
            latency_us = (recv_ns - tick["ts_ns"]) / 1000.0

            n_rx      += 1
            window_rx += 1
            latencies.append(latency_us)
            if len(latencies) > 10000:
                latencies.pop(0)

            # Rate report every second
            now = time.perf_counter()
            if now - last_rate_report >= 1.0:
                rate = window_rx / (now - last_rate_report)
                avg_lat = sum(latencies[-min(1000, len(latencies)):]) / \
                          min(1000, len(latencies)) if latencies else 0
                print(f"\n  ── {rate:,.0f} msg/sec | "
                      f"avg latency: {avg_lat:.1f} µs | "
                      f"total: {n_rx:,} ticks ──", flush=True)
                window_rx = 0
                last_rate_report = now

            # Per-tick display
            if not args.rate_only and n_rx % args.every == 0:
                print(f"{tick['tick_id']:>10}  "
                      f"{tick['source']:>6}  "
                      f"{tick['instrument_id']:>4}  "
                      f"{tick['mid']:>12.4f}  "
                      f"{tick['spread_bps']:>10.2f}  "
                      f"{tick['volume']:>10.4f}  "
                      f"{latency_us:>12.1f}",
                      flush=True)

            if args.max and n_rx >= args.max:
                break

    except KeyboardInterrupt:
        pass
    finally:
        sock.close()

    # Summary
    if latencies:
        s_lat = sorted(latencies)
        n = len(s_lat)
        print(f"\n[monitor] summary — {n_rx:,} ticks received, "
              f"{n_errors} bad packets")
        print(f"  One-way latency (T1 → receive):")
        print(f"    p50  : {s_lat[n//2]:.1f} µs")
        print(f"    p95  : {s_lat[int(n*0.95)]:.1f} µs")
        print(f"    p99  : {s_lat[int(n*0.99)]:.1f} µs")
        print(f"    min  : {s_lat[0]:.1f} µs")
        print(f"    max  : {s_lat[-1]:.1f} µs")


if __name__ == "__main__":
    main()
