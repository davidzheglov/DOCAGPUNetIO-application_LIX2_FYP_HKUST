#!/usr/bin/env python3
"""
clock_cal_server.py — tiny UDP echo server used by benchmark.py to estimate
the clock offset between the DPU ARM (where send_ticks.py runs) and the host
(where gpu_receiver runs).

Runs ON DPU ARM. Binds to --ip:--port and for every request echoes an NTP-
style 4-timestamp reply:

    client sends:  [t_a : uint64 ns]
    we respond:    [t_a, t_b, t_c : 3 × uint64 ns]

where
    t_a = client wall-clock at send        (host clock)
    t_b = server wall-clock at recv        (dpu  clock)
    t_c = server wall-clock at reply-send  (dpu  clock)
    t_d = client wall-clock at recv reply  (host clock, measured client-side)

The client then computes:
    offset     = ((t_b - t_a) + (t_c - t_d)) / 2
    one_way    = ((t_d - t_a) - (t_c - t_b)) / 2

Apply `t_host = t_dpu + offset_ns` to bring DPU timestamps into the host frame.
"""

import argparse
import selectors
import socket
import struct
import sys
import time

REQ_FMT  = "=Q"
REP_FMT  = "=QQQ"
REP_SIZE = struct.calcsize(REP_FMT)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip",   default="0.0.0.0",
                    help="Bind address (e.g. 10.10.10.1 for data-path PF)")
    ap.add_argument("--port", type=int, default=6006)
    args = ap.parse_args()

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind((args.ip, args.port))

    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.bind((args.ip, args.port))
    tcp_sock.listen(16)
    tcp_sock.setblocking(False)

    sel = selectors.DefaultSelector()
    sel.register(udp_sock, selectors.EVENT_READ, "udp")
    sel.register(tcp_sock, selectors.EVENT_READ, "tcp_listen")
    print(f"[clock_cal] listening on {args.ip}:{args.port} udp+tcp", flush=True)

    try:
        while True:
            for key, _ in sel.select():
                kind = key.data
                if kind == "udp":
                    data, addr = udp_sock.recvfrom(64)
                    t_b = time.time_ns()
                    if len(data) < 8:
                        continue
                    t_a = struct.unpack(REQ_FMT, data[:8])[0]
                    t_c = time.time_ns()
                    udp_sock.sendto(struct.pack(REP_FMT, t_a, t_b, t_c), addr)
                elif kind == "tcp_listen":
                    conn, _ = tcp_sock.accept()
                    conn.setblocking(False)
                    sel.register(conn, selectors.EVENT_READ, "tcp_conn")
                else:
                    conn = key.fileobj
                    data = conn.recv(8)
                    t_b = time.time_ns()
                    if not data:
                        sel.unregister(conn)
                        conn.close()
                        continue
                    if len(data) < 8:
                        continue
                    t_a = struct.unpack(REQ_FMT, data[:8])[0]
                    t_c = time.time_ns()
                    conn.sendall(struct.pack(REP_FMT, t_a, t_b, t_c))
    except KeyboardInterrupt:
        print("\n[clock_cal] bye", flush=True)


if __name__ == "__main__":
    sys.exit(main())
