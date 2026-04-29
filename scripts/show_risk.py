#!/usr/bin/env python3
"""
show_risk.py — Live monitor for SignalResult packets emitted by any tier receiver.

Listens on UDP 5006 and prints a one-line dashboard per second showing the
latest Monte Carlo risk numbers (var_95, cvar_95, mc_mean, mc_std) plus the
trading signal. Designed for the Binance live demo so you can show the GPU
producing real, evolving risk numbers per tick.

Run on lxcpu1 alongside one of the receivers (T1/T2/T3/T4). Do NOT run while
benchmark_harness is running — both bind UDP 5006 and would race.

Wire format: matches src/common/signal_result.h (96 bytes packed).

Usage:
  python3 scripts/show_risk.py                      # default — top symbol
  python3 scripts/show_risk.py --symbol BTCUSDT     # filter by symbol
  python3 scripts/show_risk.py --raw                # one line per tick (firehose)
"""

from __future__ import annotations
import argparse
import socket
import struct
import sys
import time
from collections import defaultdict

# 96 bytes packed — must match signal_result.h exactly.
#  Q=u64 H=u16 b=i8 f=f32 d=f64 ; xN=N pad bytes
SIG_FMT  = "=QQQHbbfdddddddd"
SIG_SIZE = struct.calcsize(SIG_FMT)
assert SIG_SIZE == 96, f"SignalResult struct size mismatch: got {SIG_SIZE}"

PORT = 5006

# Same djb2-folded hash as symbol_to_id() in tick_message.h, but only for
# pretty-printing — we hash a few symbols and reverse-lookup at runtime.
def symbol_id(s: str) -> int:
    h = 5381
    for ch in s.encode():
        h = (((h << 5) + h) ^ ch) & 0xFFFFFFFF
    return h % 256

KNOWN_SYMBOLS = ["BTCUSDT", "ETHUSDT", "SOLUSDT", "BNBUSDT", "XRPUSDT",
                 "ADAUSDT", "DOGEUSDT", "MATICUSDT", "DOTUSDT", "AVAXUSDT"]
ID_TO_NAME = {symbol_id(s): s for s in KNOWN_SYMBOLS}

SIGNAL_NAME = {1: "BUY ", -1: "SELL", 0: "----"}


def fmt_money(x: float) -> str:
    if abs(x) >= 1e6: return f"{x/1e6:7.3f}M"
    if abs(x) >= 1e3: return f"{x/1e3:7.3f}k"
    return f"{x:8.2f}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port",   type=int, default=PORT)
    ap.add_argument("--symbol", help="only show this symbol (default: all)")
    ap.add_argument("--raw",    action="store_true", help="print every tick")
    ap.add_argument("--rate-hz", type=float, default=1.0,
                    help="dashboard refresh in Hz (default: 1.0)")
    args = ap.parse_args()

    sym_filter = symbol_id(args.symbol) if args.symbol else None

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", args.port))
    s.settimeout(0.2)

    latest: dict[int, dict] = {}      # iid -> last tick
    counts                  = defaultdict(int)
    actionable              = defaultdict(int)
    last_print = 0.0

    print(f"[show_risk] listening on UDP {args.port} "
          f"({'all' if args.symbol is None else args.symbol})", flush=True)

    while True:
        try:
            data, _ = s.recvfrom(2048)
        except socket.timeout:
            data = None

        if data and len(data) >= SIG_SIZE:
            (tick_id, _t3, _t4, iid, sig, rsi_sig, rsi,
             mid, spread, fast_ema, slow_ema,
             var_95, cvar_95, mc_mean, mc_std) = struct.unpack(SIG_FMT, data[:SIG_SIZE])

            if sym_filter is not None and iid != sym_filter:
                pass
            else:
                counts[iid] += 1
                if sig != 0:
                    actionable[iid] += 1
                latest[iid] = dict(tick_id=tick_id, sig=sig, rsi=rsi,
                                    mid=mid, spread=spread,
                                    var_95=var_95, cvar_95=cvar_95,
                                    mc_mean=mc_mean, mc_std=mc_std)
                if args.raw:
                    name = ID_TO_NAME.get(iid, f"id={iid}")
                    print(f"  {name:<10} mid={fmt_money(mid)} "
                          f"VaR95={fmt_money(var_95)} CVaR95={fmt_money(cvar_95)} "
                          f"σ={fmt_money(mc_std):>9}  {SIGNAL_NAME[sig]}  "
                          f"RSI={rsi:5.1f}",
                          flush=True)

        # Periodic dashboard
        now = time.time()
        if not args.raw and now - last_print >= 1.0 / args.rate_hz and latest:
            last_print = now
            print(f"\n── {time.strftime('%H:%M:%S')} "
                  f"────────────────────────────────────────────────")
            header = (f"  {'symbol':<10} {'mid':>10} {'VaR 95':>10} "
                      f"{'CVaR 95':>10} {'MC σ':>9} {'sig':>5} "
                      f"{'RSI':>5} {'ticks':>9} {'actionable':>11}")
            print(header)
            for iid, d in sorted(latest.items(), key=lambda kv: -counts[kv[0]]):
                name = ID_TO_NAME.get(iid, f"id={iid}")
                tail_pct = 100.0 * (d['mid'] - d['var_95']) / d['mid'] if d['mid'] > 0 else 0
                print(f"  {name:<10} {fmt_money(d['mid'])} "
                      f"{fmt_money(d['var_95'])} {fmt_money(d['cvar_95'])} "
                      f"{fmt_money(d['mc_std']):>9} "
                      f"{SIGNAL_NAME[d['sig']]:>5} {d['rsi']:>5.1f} "
                      f"{counts[iid]:>9,} {actionable[iid]:>11,}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[show_risk] stopped", flush=True)
