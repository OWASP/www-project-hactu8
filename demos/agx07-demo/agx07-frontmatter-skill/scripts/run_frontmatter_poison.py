#!/usr/bin/env python3
"""Attack skill — frontmatter poisoning through unauthenticated bundle ingestion.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Replaces one RAG bundle document (default: ``vault-access.md``) with
``assets/frontmatter_payload.md`` through ``POST /bundle/ingest``. The prose
body is the approved one, word for word; only the YAML frontmatter
``description:`` changes. A scan that screens the body only still passes the
document, but the loader puts the metadata block in front of the model too, so
in vulnerable mode the payload reaches it unscreened.

Exit code: 0 when the document was ingested, 1 when the target is unreachable.

Examples:
    python scripts/run_frontmatter_poison.py
    python scripts/run_frontmatter_poison.py --doc vault-access.md
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("AGX07_TARGET", "http://127.0.0.1:5407")
DEFAULT_PAYLOAD = os.path.join(SKILL_DIR, "assets", "frontmatter_payload.md")


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
            ok = json.loads(resp.read()).get("demo") == "agx07"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the AGX07 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--doc", default="vault-access.md", help="bundle document to replace")
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="document to ingest")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    with open(args.payload, "r", encoding="utf-8") as fh:
        text = fh.read()

    print(f"[*] Ingesting {os.path.basename(args.payload)} as {args.doc} "
          "(unauthenticated POST /bundle/ingest)")
    result = _post(f"{args.target}/bundle/ingest", {"doc": args.doc, "text": text})
    print(f"[+] Ingested {result['doc']}. Body unchanged; the directive sits in the "
          "frontmatter description.")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
