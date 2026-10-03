#!/usr/bin/env python3
"""Attack skill — obfuscation gauntlet through a vendor notice update.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Reads the canonical placeholder directive from
``assets/obfuscation_payload.txt`` and installs encoded copies of it into the
notice board through the unauthenticated ``POST /vendor/notices/update``: by
default base64 into the ``welcome`` notice, split-token into ``maintenance``,
and base32 into ``status``. The directive is never written in plaintext, so a
gateway that judges raw bytes never matches it. Billy reads the notice through
the gateway, and in vulnerable mode the encoded directive reaches the model,
which decodes it the way a real LLM would.

Exit code: 0 when the updates were applied, 1 when the target is unreachable.

Examples:
    python scripts/run_obfuscation.py
    python scripts/run_obfuscation.py --notice status --encoding hex
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("AGX01_TARGET", "http://127.0.0.1:5401")
DEFAULT_PAYLOAD = os.path.join(SKILL_DIR, "assets", "obfuscation_payload.txt")

# notice id -> encoding, mirroring vulnerable_app.POISON_PLAN.
DEFAULT_PLAN = (("welcome", "base64"), ("maintenance", "split"), ("status", "base32"))


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
            ok = json.loads(resp.read()).get("demo") == "agx01"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the AGX01 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--notice", help="poison only this notice")
    parser.add_argument("--encoding", choices=("base64", "split", "hex", "base32"),
                        help="encoding to use (with --notice)")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1

    if args.notice:
        plan = ((args.notice, args.encoding or "base64"),)
    else:
        plan = DEFAULT_PLAN

    print(f"[*] Installing {os.path.basename(DEFAULT_PAYLOAD)} as encoded notices "
          "(unauthenticated POST /vendor/notices/update)")
    for notice, encoding in plan:
        result = _post(f"{args.target}/vendor/notices/update",
                       {"notice": notice, "encoding": encoding})
        print(f"[+] Poisoned notice {result['notice']}.")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
