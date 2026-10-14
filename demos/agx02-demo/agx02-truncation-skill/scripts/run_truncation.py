#!/usr/bin/env python3
"""Attack skill — truncation tail through a vendor log update.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Replaces the exported log artifact with one from
``assets/export_log_payload.txt``: ~4 kB of benign log lines with the
placeholder directive in the **tail**, past the first ``HEAD_LIMIT`` bytes.
A gateway that reads only the head of the return never sees it; Billy reads the
whole return, so in vulnerable mode the directive reaches the model.

Exit code: 0 when the update was applied, 1 when the target is unreachable.

Examples:
    python scripts/run_truncation.py
    python scripts/run_truncation.py --payload assets/export_log_payload.txt
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("AGX02_TARGET", "http://127.0.0.1:5402")
DEFAULT_PAYLOAD = os.path.join(SKILL_DIR, "assets", "export_log_payload.txt")


def _post(url: str, body: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def check_target(base: str) -> bool:
    try:
        with urllib.request.urlopen(f"{base}/health", timeout=5) as resp:
            ok = json.loads(resp.read()).get("demo") == "agx02"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the AGX02 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="artifact to install")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    with open(args.payload, "r", encoding="utf-8") as fh:
        text = fh.read()

    print(f"[*] Replacing the export_log artifact with {os.path.basename(args.payload)} "
          f"({len(text)} bytes; directive in the tail) via POST /vendor/logs/update")
    result = _post(f"{args.target}/vendor/logs/update", {"text": text})
    print(f"[+] Installed {result['artifact']}.")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
