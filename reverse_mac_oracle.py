#!/usr/bin/env python3
"""Compute the local sphostd challenge MAC using its supplied binary.

This is the MAC helper used during the Reverse challenge; by itself it is not
the complete network exploit. It requires the original sphostd binary and GDB.
"""

import argparse
import re
import subprocess
import sys


def crypto_mac(binary: str, nonce: bytes) -> bytes:
    if len(nonce) != 16:
        raise ValueError("expected exactly 16 challenge bytes")
    first = int.from_bytes(nonce[:8], "little")
    second = int.from_bytes(nonce[8:], "little")
    command = [
        "gdb", "-q", "-batch", binary,
        "-ex", "set pagination off",
        "-ex", "start",
        "-ex", "set $m=(unsigned char*)malloc(16)",
        "-ex", f"set *(unsigned long long*)$m={first}",
        "-ex", f"set *(unsigned long long*)($m+8)={second}",
        "-ex", "set $o=(unsigned char*)malloc(32)",
        "-ex", "call (void)crypto_mac($m,16,$o)",
        "-ex", "x/16bx $o",
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=12)
    values = []
    for line in result.stdout.splitlines():
        if re.match(r"0x[0-9a-f]+:", line):
            values.extend(re.findall(r"0x([0-9a-f]{2})", line.split(":", 1)[1]))
    mac = bytes.fromhex("".join(values))
    if result.returncode or len(mac) != 16:
        raise RuntimeError("GDB MAC oracle failed: " + result.stderr[-300:])
    return mac


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("nonce_hex", help="16-byte challenge nonce as 32 hex characters")
    parser.add_argument("--binary", default="./sphostd", help="path to supplied sphostd binary")
    args = parser.parse_args()
    try:
        print(crypto_mac(args.binary, bytes.fromhex(args.nonce_hex)).hex())
    except Exception as exc:
        print(f"MAC calculation failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
