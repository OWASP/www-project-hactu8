#!/usr/bin/env python3
"""Attack skill — memory poisoning through an ordinary "remember this" request.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Opens one chat session as an ordinary user (default ``mallory``) and asks the
agent to remember ``assets/memory_note.md``: a line keyed to the business-travel
topic plus one directive line. The agent's own ``save_memory`` step stores it.
Nothing else is touched. Later sessions of *other* users recall the memory when
they ask about business travel, and in vulnerable mode the model follows it.

Exit code: 0 when the session ran (whether or not the write was stored),
1 when the target is unreachable.

Examples:
    python scripts/run_memory_poison.py
    python scripts/run_memory_poison.py --user mallory --payload assets/memory_note.md
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("ASI06_TARGET", "http://127.0.0.1:5306")
DEFAULT_PAYLOAD = os.path.join(SKILL_DIR, "assets", "memory_note.md")
REQUEST_LINE = "Please remember this for next time:"


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
            ok = json.loads(resp.read()).get("demo") == "asi06"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the ASI06 target. Start it: python vulnerable_app.py")
    return ok


def poison_message(payload: str) -> str:
    """The attacker's chat message: a remember request, then the memory text."""
    return f"{REQUEST_LINE}\n{payload.strip()}"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--user", default="mallory", help="the attacker's ordinary user name")
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="memory text to plant")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    with open(args.payload, "r", encoding="utf-8") as fh:
        payload = fh.read()

    print(f"[*] Session as '{args.user}': asking the agent to remember "
          f"{os.path.basename(args.payload)} (1 session, 1 memory)")
    result = _post(f"{args.target}/session", {"user": args.user, "message": poison_message(payload)})
    save = next((s for s in result["steps"] if s["step"] == "save_memory"), None)
    if save and save["status"] == "executed":
        print(f"[+] Memory {save['memory']} saved with scope '{save['scope']}' "
              f"in session {result['session']}.")
    else:
        findings = ", ".join(save["findings"]) if save else "no save step"
        print(f"[-] The agent refused the write ({findings}).")
    print("[*] Re-run scripts/evaluate_kpi.py to measure later sessions of other users.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
