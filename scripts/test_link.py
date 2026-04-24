#!/usr/bin/env python3
"""
test_link.py — Simple UDP link test between two machines.

Usage:
  Receiver (run first):
    python3 test_link.py recv --bind <LOCAL_IP>

  Sender:
    python3 test_link.py send --dest <REMOTE_IP> --bind <LOCAL_IP>

Examples:
  ON cpu1:  python3 test_link.py recv --bind 10.10.10.2
  ON cpu2:  python3 test_link.py send --dest 10.10.10.2 --bind 10.10.10.3
"""

import argparse
import socket
import struct
import time
import sys

PORT = 9999
MAGIC = 0xDEADBEEF


def recv_mode(bind_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_ip, PORT))
    sock.settimeout(1.0)
    print(f"[recv] Listening on {bind_ip}:{PORT} ...")

    count = 0
    while True:
        try:
            data, addr = sock.recvfrom(256)
            if len(data) >= 12:
                magic, seq, ts_ns = struct.unpack("!IIQ", data[:16])
                now = time.time_ns()
                rtt_us = (now - ts_ns) / 1000.0
                count += 1
                print(f"  [#{seq}] from {addr[0]} | {len(data)} bytes | "
                      f"latency ~{rtt_us:.0f} us | total={count}")

                sock.sendto(struct.pack("!IIQ", MAGIC, seq, ts_ns), addr)
            else:
                print(f"  from {addr[0]}: {data}")
        except socket.timeout:
            pass
        except KeyboardInterrupt:
            print(f"\n[recv] Stopped. Received {count} packets.")
            break


def send_mode(dest_ip, bind_ip, count, rate):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if bind_ip:
        sock.bind((bind_ip, 0))
    sock.settimeout(1.0)

    print(f"[send] Sending {count} packets to {dest_ip}:{PORT} "
          f"from {bind_ip or 'default'} at {rate}/sec")

    sent = 0
    acked = 0
    interval = 1.0 / rate

    for seq in range(count):
        ts_ns = time.time_ns()
        pkt = struct.pack("!IIQ", MAGIC, seq, ts_ns)
        sock.sendto(pkt, (dest_ip, PORT))
        sent += 1

        try:
            reply, _ = sock.recvfrom(256)
            if len(reply) >= 12:
                acked += 1
        except socket.timeout:
            pass

        if sent % 10 == 0:
            print(f"  sent={sent} acked={acked}", end="\r", flush=True)

        if seq < count - 1:
            time.sleep(interval)

    print(f"\n[send] Done. sent={sent} acked={acked} loss={sent - acked}")


def main():
    parser = argparse.ArgumentParser(description="UDP link tester")
    sub = parser.add_subparsers(dest="mode", required=True)

    r = sub.add_parser("recv", help="Receive mode")
    r.add_argument("--bind", required=True, help="IP to bind to")

    s = sub.add_parser("send", help="Send mode")
    s.add_argument("--dest", required=True, help="Destination IP")
    s.add_argument("--bind", default=None, help="Source IP to bind to")
    s.add_argument("--count", type=int, default=50, help="Packets to send")
    s.add_argument("--rate", type=int, default=10, help="Packets per second")

    args = parser.parse_args()

    if args.mode == "recv":
        recv_mode(args.bind)
    else:
        send_mode(args.dest, args.bind, args.count, args.rate)


if __name__ == "__main__":
    main()
