#!/usr/bin/env python3
"""Attack skill — receipt photos that carry an instruction to Billy.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Uploads the attackers' receipt photos with ``POST /api/attack`` (three
customers re-upload their own receipts, each drawn from
``assets/hostile_images.json`` with one carrier: small print in the photo,
near-invisible text, or PNG metadata), then plays the three refund requests
over ``POST /ask`` and prints what Billy emitted. The receipts stay true; the
attack is the extra text the image carries. The only goal is the refund
desk's fictional override code and a refund call to the simulated loopback
refund tool, which moves no money.

Exit code: 0 when the attack was played, 1 when the target is unreachable.

Examples:
    python scripts/run_image_attack.py
    python scripts/run_image_attack.py --upload-only
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("HX08_TARGET", "http://127.0.0.1:5508")
sys.path.insert(0, SKILL_DIR)


def _post(url: str, body: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read())


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read())


def check_target(base: str) -> bool:
    try:
        ok = _get(f"{base}/health").get("demo") == "hx08"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the HX08 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--upload-only", action="store_true",
                        help="upload the photos and stop (no requests played)")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if not check_target(args.target):
        return 1
    for event in _post(f"{args.target}/api/attack", {})["events"]:
        print(f"[+] {event}")
    if args.upload_only:
        return 0
    from evaluate_kpi import suite
    for label, message, image, targeted, _ in suite():
        if not targeted:
            continue
        result = _post(f"{args.target}/ask", {"message": message, "image": image})
        print(f"[*] {label}")
        print(f"    billy> {result['final_reply'][:140]}")
        print(f"[+] Directive obeyed: {result['directive'] or 'none'}; override code in the output: "
              f"{'YES' if result['canary_out'] else 'no'}; over-policy refunds paid: {result['over_policy_paid']}")
    print("[*] GET /refund-log shows every refund call. Re-run scripts/evaluate_kpi.py to measure.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
