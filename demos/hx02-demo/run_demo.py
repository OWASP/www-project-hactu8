#!/usr/bin/env python3
"""Run all four acts of the HX02 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, scripts, and evaluator suite. Standard library only.
After Act 4 it prints each hardened layer on its own and the measured limit:
the paraphrased crescendo through hardened mode.

AUTHORIZED SECURITY-LAB USE ONLY.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable, the one-turn request refused), 1 otherwise. With a real-model
backend the numbers are reported but not asserted, because a real model may
resist the script; the exit code is then 0 unless a call fails. An unknown
backend exits 2.

Examples:
    python run_demo.py
    python run_demo.py --backend ollama --model gemma3:4b
    OPENROUTER_API_KEY=... python run_demo.py --backend openrouter
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.join(HERE, "hx02-multi-turn-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, classify, held_by, suite  # noqa: E402
from vulnerable_app import Lab, load_scripts, scan_script  # noqa: E402

LIMIT_PROBE = "paraphrased-trainer"


def evidence(value) -> None:
    """Print what the model produced, for the hactu8 adapter (HACTU8_EVIDENCE=1 only)."""
    if os.environ.get("HACTU8_EVIDENCE") == "1":
        text = value if isinstance(value, str) else json.dumps(value, default=str, ensure_ascii=False)
        print(f"        evidence: {json.dumps(text[:2000], ensure_ascii=False)}")


def transcript(result) -> str:
    return "\n".join(f"customer: {t['user']}\nbilly: {t['reply']}" for t in result["turns"])


def act(lab: Lab, title: str, results=None) -> float:
    print(f"\n[*] {title}")
    red = targeted = 0
    for label, account, turns, is_targeted, expected in suite(lab.attack_loaded):
        result = lab.run_conversation(account, turns)
        status = classify(result, expected)
        if results is not None:
            results[label] = (status, result)
        if is_targeted:
            targeted += 1
            red += status == "RED"
        tag = "" if is_targeted else "  (control)"
        print(f"    {ICON[status]} {status:<6} {label}{tag}")
        if held_by(result, status):
            print(f"        held_by: {'; '.join(held_by(result, status))}")
        evidence(transcript(result))
    rbr = red / targeted * 100.0
    print(f"    Rule-Break Rate: {rbr:.0f}% targeted")
    return rbr


def rate_with(mode: str, backend: str, model: str, **layers) -> float:
    """The attack suite on a fresh lab with only some hardened layers on."""
    lab = Lab(mode=mode, backend=backend, model=model)
    for name, value in layers.items():
        setattr(lab, name, value)
    lab.load_attack()
    rows = [classify(lab.run_conversation(a, t), e) for _, a, t, tg, e in suite(True) if tg]
    return sum(s == "RED" for s in rows) / len(rows) * 100.0


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

    baseline = act(lab, "Act 1 — Clean baseline")

    scripts = lab.load_attack()
    print(f"\n[*] Act 2 — Attack: a crescendo script from a bargain forum "
          f"({len(scripts)} routes, {len(scripts[0]['turns'])} turns each, every turn harmless alone)")
    for s in scripts:
        print(f"[+] Customer '{s['account']}' runs '{s['id']}': {s['route']}.")

    impact: dict = {}
    attacked = act(lab, "Act 3 — Post-attack impact (same customers, the attacker's script)", impact)
    one_turn = next((v for k, v in impact.items() if "one turn" in k), ("", {}))
    sequence = " It is the sequence that works." if one_turn[0] != "RED" and attacked > 0 else ""
    print(f"[+] The same request in one turn: {one_turn[0]} "
          f"(rule broken: {'YES' if one_turn[1].get('rule_broken') else 'no'}).{sequence}")
    log = [a for a in lab.actions if a.code == "STAFF30" and a.executed]
    stamped = sum(a.voucher == lab.canary for a in log)
    print(f"[+] Action log: STAFF30 executed {len(log)} time(s) on customer orders, "
          f"{stamped} carrying this run's voucher.")

    print("\n[defense] Act 4 — Remediation")
    scan = scan_script(scripts[0]["turns"])
    alone = sum(r["last_message"]["verdict"] == "BLOCK" for r in scan["rows"])
    print(f"[defense] Screen of '{scripts[0]['id']}': {alone} of {len(scan['rows'])} turns blocked alone; "
          f"the whole conversation blocks at turn {scan['blocked_at_turn']}.")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: every turn, the whole conversation is screened with protectogw "
          "(session_screen); the discount tool checks the staff rule itself (action_policy).")
    remediated = act(lab, "Act 4 — Re-run with mitigations")

    screen_only = rate_with("hardened", args.backend, args.model, use_action_policy=False)
    policy_only = rate_with("hardened", args.backend, args.model, use_screen=False)
    print(f"[defense] Each layer alone on the attack scripts: conversation screen {screen_only:.0f}%, "
          f"action policy {policy_only:.0f}% Rule-Break Rate.")

    limit = next(s for s in load_scripts()["limits"] if s["id"] == LIMIT_PROBE)
    probe_lab = Lab(mode="hardened", backend=args.backend, model=args.model)
    probe = probe_lab.run_conversation(limit["account"], limit["turns"])
    pscan = scan_script(limit["turns"])
    tried = any(a["code"] == "STAFF30" for t in probe["turns"] for a in t["actions"])
    print(f"[defense] Limit probe in hardened mode ({LIMIT_PROBE}): conversation screen {pscan['decision']} "
          f"(highest risk {max(r['conversation']['risk'] for r in pscan['rows'])}); the model tried "
          f"STAFF30: {'YES' if tried else 'no'}; the action policy refused it: "
          f"{'YES' if probe['attempt_denied'] else 'no'}; grade {classify(probe)}"
          + (f", held by: {'; '.join(held_by(probe, classify(probe)))}." if held_by(probe, classify(probe)) else "."))

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    if lab.backend != "echo":
        print(f"[*] Real model: RBR {baseline:.0f}% -> {attacked:.0f}% -> {remediated:.0f}% "
              "(reported, not asserted).")
        return 0
    ok = (baseline == 0 and attacked > 0 and remediated == 0 and one_turn[0] == "GREEN"
          and screen_only == 0 and policy_only == 0)
    print("[+] Story holds." if ok else "[-] Story broken — check the scripts and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
