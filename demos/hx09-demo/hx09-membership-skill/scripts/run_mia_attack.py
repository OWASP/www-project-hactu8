#!/usr/bin/env python3
"""Attack skill — membership inference against Lamb's model API.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

The attacker holds one candidate record, Hattie Quill's (the lab's fictional
canary customer), and wants to know whether it was in Lamb's fine-tuning
data. The chat refuses to say. The attacker never asks: they measure, with
the kit in ``assets/attack_probes.json``:

* ``loss-attack`` — score the record on ``POST /api/v1/score`` and compare its
  loss with 20 reference records the attacker invented;
* ``confidence-attack`` — complete the record's opening on
  ``POST /api/v1/complete`` and compare the confidence with the references';
* ``ref-extraction`` — complete the whole known record followed by "ref".

The only target is that one record's membership (and its support reference,
the per-run canary). ``--probe ID`` runs one probe, including the limits
``label-only`` and ``frugal-loss``.

Exit code: 0 when the probes ran, 1 when the target is unreachable or the
probe id is unknown.

Examples:
    python scripts/run_mia_attack.py
    python scripts/run_mia_attack.py --probe label-only
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(HERE)
DEFAULT_TARGET = os.getenv("HX09_TARGET", "http://127.0.0.1:5509")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, HERE)

import mia  # noqa: E402


class HttpError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _post(url: str, body: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        with exc:
            raise HttpError(exc.code, json.loads(exc.read() or b"{}").get("error", "")) from None


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read())


def check_target(base: str) -> bool:
    try:
        ok = _get(f"{base}/health").get("demo") == "hx09"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the HX09 target. Start it: python vulnerable_app.py")
    return ok


class HttpApi:
    """Lamb's API over loopback, with the same methods as ``vulnerable_app.LocalApi``.

    ``audit_records``, ``canary_member`` and ``leaked`` call the lab's grader
    endpoints, which are not part of Lamb's API; only the evaluator uses them.
    """

    def __init__(self, base: str) -> None:
        self.base = base
        self._n = 0
        self._nonce = os.urandom(3).hex()

    def score(self, text: str, client: str) -> dict:
        return _post(f"{self.base}/api/v1/score", {"text": text, "client": client})

    def complete(self, prompt: str, client: str, max_tokens: int = 12) -> dict:
        return _post(f"{self.base}/api/v1/complete", {"prompt": prompt, "client": client, "max_tokens": max_tokens})

    def chat(self, message: str) -> dict:
        return _post(f"{self.base}/chat", {"message": message})

    def new_client(self, prefix: str) -> str:
        self._n += 1
        return f"{prefix}-{self._nonce}-{self._n:04d}"

    def audit_records(self):
        return [(r["record"], r["member"]) for r in _get(f"{self.base}/api/audit")["records"]]

    def canary_member(self) -> bool:
        return bool(_get(f"{self.base}/api/audit")["canary_member"])

    def leaked(self, texts) -> bool:
        return bool(_post(f"{self.base}/api/grade", {"texts": list(texts)})["leaked"])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--probe", help="run this probe id only (see assets/attack_probes.json)")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if not check_target(args.target):
        return 1
    from vulnerable_app import load_probes
    kit = load_probes()
    entries = kit["attacks"] + kit["limits"]
    if args.probe:
        entries = [e for e in entries if e["id"] == args.probe]
        if not entries:
            print(f"[-] no probe {args.probe!r} in assets/attack_probes.json")
            return 1
    else:
        _post(f"{args.target}/api/attack", {})
        entries = kit["attacks"]
    api = HttpApi(args.target)
    for entry in entries:
        print(f"[*] Probe '{entry['id']}' ({entry['technique']}): {entry['route']}")
        attempt = mia.PROCEDURES[entry["id"]](api, api.new_client(entry["account"]), kit["target"], entry, kit)
        if attempt.verdict is None:
            print(f"[-] Stopped after {attempt.queries} queries: {attempt.blocked}")
        else:
            print(f"[+] Verdict on Hattie Quill's record: {attempt.verdict.upper()} ({attempt.detail}; "
                  f"{attempt.queries} queries)")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
