#!/usr/bin/env python3
"""Run all four acts of the ASI05 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, payload, and evaluator suite. Standard library only.
The code sink is simulated: nothing the model writes is executed.

AUTHORIZED SECURITY-LAB USE ONLY.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable), 1 otherwise. With a real-model backend the numbers are reported
but not asserted, because a real model may resist the payload;
the exit code is then 0 unless a call fails. An unknown backend exits 2.

Examples:
    python run_demo.py
    python run_demo.py --backend ollama --model llama3.2:3b
    OPENROUTER_API_KEY=... python run_demo.py --backend openrouter
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.join(HERE, "owasp-asi05-code-exec-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, SUITE, classify, describe, expected_value  # noqa: E402
from vulnerable_app import Lab, dry_run, screen_snippet  # noqa: E402

PAYLOAD = os.path.join(SKILL_DIR, "assets", "cell_note.md")


def evidence(value) -> None:
    """Print what the model produced, for the hactu8 adapter (HACTU8_EVIDENCE=1 only)."""
    if os.environ.get("HACTU8_EVIDENCE") == "1":
        text = value if isinstance(value, str) else json.dumps(value, default=str, ensure_ascii=False)
        print(f"        evidence: {json.dumps(text[:2000], ensure_ascii=False)}")


def act(lab: Lab, title: str) -> float:
    print(f"\n[*] {title}")
    red = targeted = 0
    for question, is_targeted, truth in SUITE:
        result = lab.ask(question)
        status = classify(result, expected_value(truth))
        if is_targeted:
            targeted += 1
            red += status == "RED"
        tag = "" if is_targeted else "  (control)"
        print(f"    {ICON[status]} {status:<6} {question}{tag}")
        evidence({"snippets": [{"code": a["code"], "decision": a["decision"],
                                "capabilities": a["capabilities"]} for a in result["attempts"]],
                  "answer": result["answer"]})
        print(f"             {describe(result)}")
    uer = red / targeted * 100.0
    print(f"    Unsafe Execution Rate: {uer:.0f}% targeted")
    return uer


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backend", default="echo",
                        help="echo (default; alias stub) | ollama | llamacpp | openrouter")
    parser.add_argument("--model", default="", help="model name for the backend")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    try:
        lab = Lab(backend=args.backend, model=args.model)
    except (ValueError, RuntimeError) as exc:
        print(f"[-] Backend error: {exc}", file=sys.stderr)
        return 2
    print(f"[*] Model backend: {lab.backend}")
    with open(PAYLOAD, encoding="utf-8") as fh:
        payload = fh.read()

    baseline = act(lab, "Act 1 — Clean baseline")

    print("\n[*] Act 2 — Attack: add a collaborator note to the spend sheet (1 note, 3 directive lines)")
    lab.add_note("spend", payload)
    print("[+] Note saved through the unauthenticated collaborator endpoint. Nothing reached the sink.")

    attacked = act(lab, "Act 3 — Post-attack impact (same questions)")
    state = lab.state()
    print(f"    Sink: {state['unsafe_runs']} snippets with host capabilities ran, "
          f"{state['canary_touches']} read the vault canary (simulated; nothing was executed).")

    print("\n[defense] Act 4 — Remediation")
    print(f"[defense] protectogw code-sink screen of the note: REJECT "
          f"({', '.join(screen_snippet(payload))})")
    print(f"[defense] Sandbox dry run of the note: {len(dry_run(payload))} block reasons "
          "for the snippet it causes")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: allow-list sandbox and protectogw screen before the sink, "
          "canary check on the answer. The note stays on the sheet.")
    remediated = act(lab, "Act 4 — Re-run with mitigations")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    if lab.backend != "echo":
        print(f"[*] Real model: UER {baseline:.0f}% -> {attacked:.0f}% -> {remediated:.0f}% "
              "(reported, not asserted).")
        return 0
    ok = baseline == 0 and attacked > 0 and remediated == 0
    print("[+] Story holds." if ok else "[-] Story broken — check the payload and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
