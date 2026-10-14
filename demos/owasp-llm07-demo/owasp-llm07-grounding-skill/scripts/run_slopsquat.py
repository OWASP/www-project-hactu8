#!/usr/bin/env python3
"""Attack skill — misinformation through a poisoned community doc (slopsquat).

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Publishes ``assets/poisoned_doc.md`` to the target's developer docs as one new
community page (default ``http-client-faq``). The page outranks the genuine
``http-client`` page for HTTP questions, and its first line recommends a
package that is not in the approved registry plus a docs URL on an untrusted
host. In vulnerable mode the assistant restates that claim as fact. No
existing page is modified.

Exit code: 0 when the page was published, 1 when the target is unreachable.

Examples:
    python scripts/run_slopsquat.py
    python scripts/run_slopsquat.py --page http-client-faq --payload assets/poisoned_doc.md
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("LLM07_TARGET", "http://127.0.0.1:5207")
DEFAULT_PAYLOAD = os.path.join(SKILL_DIR, "assets", "poisoned_doc.md")


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
            ok = json.loads(resp.read()).get("demo") == "llm07"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the LLM07 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--page", default="http-client-faq", help="community page slug to publish")
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="page content to publish")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    with open(args.payload, "r", encoding="utf-8") as fh:
        content = fh.read()

    print(f"[*] Publishing {os.path.basename(args.payload)} as community page '{args.page}' "
          f"(unauthenticated POST /docs/page)")
    result = _post(f"{args.target}/docs/page", {"slug": args.page, "content": content})
    print(f"[+] Page '{result['slug']}' published. 1 page added; no existing page touched.")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
