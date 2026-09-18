#!/usr/bin/env python3
"""Poisoning execution — Scenario #1 (RAG KB) and Scenario #6 (prompt template).

Attacks the vulnerable financial-advisor app by (1) injecting semantically dense
adversarial documents into the retrieval pipeline, and/or (2) replacing the app's
prompt template with a tampered artifact carrying a trigger-activated backdoor.

AUTHORIZED SECURITY-LAB USE ONLY. Target the local demo app or a system you are
explicitly permitted to test.

Examples:
    python scripts/run_poisoning.py --scenario rag        # Scenario #1 only
    python scripts/run_poisoning.py --scenario template   # Scenario #6 only
    python scripts/run_poisoning.py --scenario all --count 5
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(HERE)
POISON_TEMPLATE = os.path.join(SKILL_DIR, "assets", "poison_template.txt")
PROMPT_TEMPLATE = os.path.join(SKILL_DIR, "assets", "prompt_template.json")


def _check_target(base_url: str) -> None:
    try:
        health = requests.get(f"{base_url}/health", timeout=5)
    except Exception as exc:  # noqa: BLE001
        sys.exit(
            f"Cannot reach target {base_url} ({exc}).\n"
            f"Start it with:  python vulnerable_app.py"
        )
    if health.status_code != 200 or (health.json() or {}).get("status") != "ok":
        sys.exit(
            f"{base_url}/health did not return the demo app's response "
            f"(HTTP {health.status_code}). Another service is on that port "
            f"(on macOS, port 5000 is AirPlay). Start on another port:\n"
            f"  LLM05_PORT=5001 python vulnerable_app.py\n"
            f"  python scripts/run_poisoning.py --target http://127.0.0.1:5001"
        )


def poison_rag(base_url: str, count: int) -> None:
    if not os.path.exists(POISON_TEMPLATE):
        sys.exit(f"Adversarial template missing: {POISON_TEMPLATE}")
    with open(POISON_TEMPLATE, "r", encoding="utf-8") as fh:
        base_content = fh.read()

    print(f"[*] Scenario #1 — injecting {count} semantically optimized documents ...")
    for i in range(count):
        doc_name = f"policy_update_v{i}.txt"
        payload = {"filename": doc_name, "content": f"{base_content}\n[REFERENCE_ID: AUTH-{i:03d}]"}
        resp = requests.post(f"{base_url}/ingest", json=payload, timeout=30)
        if resp.status_code == 200:
            print(f"    [+] Injected adversarial document: {resp.json().get('stored_as', doc_name)}")
        else:
            print(f"    [-] Failed ({resp.status_code}) for {doc_name}")
    print("    Note: coherent, low-perplexity text bypasses perplexity filters "
          "(CorruptRAG, Zhang et al. 2025).")


def poison_template(base_url: str) -> None:
    if not os.path.exists(PROMPT_TEMPLATE):
        sys.exit(f"Prompt template missing: {PROMPT_TEMPLATE}")
    with open(PROMPT_TEMPLATE, "r", encoding="utf-8") as fh:
        artifact = json.load(fh)

    print("[*] Scenario #6 — replacing the prompt template with a tampered artifact ...")
    resp = requests.post(f"{base_url}/config/template", json=artifact, timeout=30)
    if resp.status_code == 200:
        print(f"    [+] Active template is now '{artifact.get('version')}'. "
              f"Trigger phrase: {artifact.get('trigger_keyword')!r}")
        print("    Backdoor is dormant until the trigger phrase appears "
              "(sleeper behavior; Fogel et al. 2026 / Hubinger et al. 2024).")
    else:
        print(f"    [-] Template replacement failed ({resp.status_code}).")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default=os.getenv("LLM05_TARGET", "http://127.0.0.1:5100"))
    parser.add_argument("--scenario", choices=["rag", "template", "all"], default="all")
    parser.add_argument("--count", type=int, default=5, help="RAG documents to inject (3-10 recommended).")
    args = parser.parse_args(argv)

    _check_target(args.target)
    if args.scenario in ("rag", "all"):
        poison_rag(args.target, args.count)
    if args.scenario in ("template", "all"):
        poison_template(args.target)
    print("\n[*] Done. Measure impact with:  python scripts/evaluate_kpi.py --target", args.target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
