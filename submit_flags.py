#!/usr/bin/env python3
"""Submit captured IBOH Game 2 flags from a private one-flag-per-line file.

Requires AD_API_TOKEN in the environment. It prints statuses, never flag values.
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

URL = "https://warzone.battleofhackers.com/api/Game/2/Ad/Submit"
FLAG_RE = re.compile(r"^flag\{[^{}\r\n]{1,200}\}$")

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("flags_file")
    args = ap.parse_args()
    token = os.environ.get("AD_API_TOKEN", "").strip()
    if not token:
        print("AD_API_TOKEN is not set", file=sys.stderr)
        return 2
    with open(args.flags_file, encoding="utf-8") as f:
        flags = [line.strip() for line in f if line.strip()]
    flags = list(dict.fromkeys(flags))
    if not 1 <= len(flags) <= 100:
        print("provide 1 to 100 unique flags", file=sys.stderr)
        return 2
    if any(not FLAG_RE.fullmatch(flag) for flag in flags):
        print("input contains a malformed flag", file=sys.stderr)
        return 2
    body = json.dumps({"flags": flags}).encode()
    req = urllib.request.Request(URL, data=body, method="POST", headers={
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            result = json.load(response)
    except urllib.error.HTTPError as exc:
        print(f"submit failed: HTTP {exc.code}", file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"submit failed: {type(exc).__name__}", file=sys.stderr)
        return 3
    print('Submission response received')
    for item in result.get("results", []):
        print(item.get("status", "unknown"))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
