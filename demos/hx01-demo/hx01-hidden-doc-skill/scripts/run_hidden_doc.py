#!/usr/bin/env python3
"""Attack skill — indirect prompt injection through text hidden in a document.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Delivers a revised Alpine Feed invoice (``assets/poisoned_invoice.pdf.json``)
through the target's unauthenticated intake (``POST /docs/upload``, standing in
for the mail gateway). It renders exactly like the real invoice; one extra text
object is white on the white page. The naive extractor passes it to Billy with
the rest of the text, and in vulnerable mode Billy follows it.

``--variant ID`` hides the same directive another way instead, from
``assets/hiding_variants.json`` (zero-size font, off-page box, PDF Subject,
Word hidden run or comment, ``display:none`` HTML, and the measured limits).

Exit code: 0 when the document was delivered, 1 when the target is unreachable.

Examples:
    python scripts/run_hidden_doc.py
    python scripts/run_hidden_doc.py --variant pdf-subject
    python scripts/run_hidden_doc.py --variant faint-tiny-paraphrase
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("HX01_TARGET", "http://127.0.0.1:5501")
DEFAULT_PAYLOAD = os.path.join(SKILL_DIR, "assets", "poisoned_invoice.pdf.json")


def _post(url: str, body: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read())


def check_target(base: str) -> bool:
    try:
        ok = _get(f"{base}/health").get("demo") == "hx01"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the HX01 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD,
                        help="document to deliver over the Alpine Feed invoice")
    parser.add_argument("--variant", help="hide the directive this way instead (assets/hiding_variants.json)")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    if args.variant:
        sys.path.insert(0, SKILL_DIR)
        from vulnerable_app import inject_variant, load_baseline, load_variants
        variant = next((v for v in load_variants() if v["id"] == args.variant), None)
        if variant is None:
            print(f"[-] No variant {args.variant!r}; see assets/hiding_variants.json")
            return 1
        doc_id, document = inject_variant(load_baseline(), variant)
        label = f"variant '{variant['id']}' ({variant['technique']})"
    else:
        with open(args.payload, "r", encoding="utf-8") as fh:
            document = json.load(fh)
        doc_id, label = "invoice-alpine-feed", os.path.basename(args.payload)

    print(f"[*] Delivering {label} as '{doc_id}' (unauthenticated POST /docs/upload)")
    result = _post(f"{args.target}/docs/upload", {"id": doc_id, "document": document})
    print(f"[+] Document '{result['id']}' delivered. 1 document changed; it looks the same when opened.")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
