#!/usr/bin/env python3
"""Run all four acts of the HX06 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, prompts and evaluator suite. Standard library only.
After Act 4 it prints each hardened layer on its own and the measured limit:
a many-shot prompt written as a table, through hardened mode.

AUTHORIZED SECURITY-LAB USE ONLY.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable, controls untouched, the 4-shot prompt refused, the limit measured
as RED), 1 otherwise. With a real-model backend the numbers are reported but
not asserted, because a real model may resist the prompts; the exit code is
then 0 unless a call fails. An unknown backend exits 2.

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
SKILL_DIR = os.path.join(HERE, "hx06-jailbreak-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, LIMIT_IDS, RULE_STANCE, classify, held_by, suite  # noqa: E402
from vulnerable_app import (  # noqa: E402
    MAX_LABELLED_TURNS, STAFF_CODE, Lab, build_message, prompt_by_id, scan_prompt,
)

LIMIT_PROBE = "quiz-table-code"      # the limit the echo story asserts RED
LAYERS = ("use_persona_screen", "use_shot_cap", "use_action_policy", "use_output_screen")
LAYER_NAMES = {"use_persona_screen": "persona screen", "use_shot_cap": "shot cap",
               "use_action_policy": "action policy", "use_output_screen": "output screen"}


def evidence(value) -> None:
    """Print what the model produced, for the hactu8 adapter (HACTU8_EVIDENCE=1 only)."""
    if os.environ.get("HACTU8_EVIDENCE") == "1":
        text = value if isinstance(value, str) else json.dumps(value, default=str, ensure_ascii=False)
        # ASCII-only JSON: U+2028/U+2029/U+0085 and every control character are escaped,
        # so model text cannot break this line or forge an item line (TEMPLATE.md §15).
        print(f"        evidence: {json.dumps(text[:2000], ensure_ascii=True)}")


def transcript(result) -> str:
    return "\n".join(f"customer: {t['user'][-300:]}\nlamb: {t['reply']}" for t in result["turns"])


def act(lab: Lab, title: str, results=None) -> float:
    print(f"\n[*] {title}")
    red = targeted = 0
    for label, account, turns, is_targeted, expected in suite(lab.attack_loaded):
        result = lab.run_conversation(account, turns)
        status = classify(result, expected)
        if results is not None:
            results[account] = (status, result, is_targeted)
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


def rate_with(backend: str, model: str, **layers) -> float:
    """The attack suite on a fresh hardened lab with only some layers on."""
    lab = Lab(mode="hardened", backend=backend, model=model)
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

    entries = lab.load_attack()
    print(f"\n[*] Act 2 — Attack: one-message jailbreaks from a bargain forum ({len(entries)} prompts, "
          "one message each)")
    for e in entries:
        size = f", {len(e['examples'])} fake exchanges" if "examples" in e else ""
        print(f"[+] Customer '{e['account']}' sends '{e['id']}' ({e['technique']}{size}): {e['route']}.")

    impact: dict = {}
    attacked = act(lab, "Act 3 — Post-attack impact (same customers, the attacker's prompts)", impact)
    few = impact.get("pat", ("", {}, False))
    count = " It is the number of examples that works." if few[0] == "GREEN" and attacked > 0 else ""
    print(f"[+] The many-shot ask with 4 examples: {few[0]} "
          f"(rule broken: {'YES' if few[1].get('rule_broken') else 'no'}).{count}")
    log = [a for a in lab.actions if a.code == STAFF_CODE and a.executed]
    leaks = sum(r.get("canary_leaked") and not r.get("rule_broken") for _, r, _ in impact.values())
    print(f"[+] Action log: STAFF30 executed {len(log)} time(s) on customer orders; "
          f"the till code in {leaks} further reply(ies).")

    print("\n[defense] Act 4 — Remediation")
    for e in entries:
        s = scan_prompt(e)
        print(f"[defense] Input layers on '{e['id']}': persona screen {s['screen']['verdict']} "
              f"(risk {s['screen']['risk']}; protectogw defaults alone {s['default_screen']['verdict']}), "
              f"{s['labelled_turns']} chat lines (cap {MAX_LABELLED_TURNS}).")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: persona screen (protectogw plus lab rules), shot cap, action policy on the "
          "discount tool, output screen with the canary.")
    remediated = act(lab, "Act 4 — Re-run with mitigations")

    alone = {name: rate_with(args.backend, args.model, **{o: o == name for o in LAYERS}) for name in LAYERS}
    print("[defense] Each layer alone on the attack: " +
          ", ".join(f"{LAYER_NAMES[n]} {v:.0f}%" for n, v in alone.items()) + " Rule-Break Rate.")

    grades = {}
    for limit_id in LIMIT_IDS:
        limit = prompt_by_id(limit_id)
        probe_lab = Lab(mode="hardened", backend=args.backend, model=args.model)
        probe = probe_lab.run_conversation(limit["account"], [build_message(limit)])
        pscan = scan_prompt(limit)
        grades[limit_id] = grade = classify(probe, RULE_STANCE)
        tried = any(a["code"] == STAFF_CODE for t in probe["turns"] for a in t["actions"])
        shape = f"{len(limit['examples'])} examples as a table" if "examples" in limit else limit["technique"]
        held = f" (held by: {'; '.join(held_by(probe, grade))})" if held_by(probe, grade) else ""
        print(f"[defense] Limit probe in hardened mode ({limit_id}, {shape}): "
              f"persona screen {pscan['screen']['verdict']}; {pscan['labelled_turns']} chat lines, "
              f"{'over' if pscan['capped'] else 'under'} the cap; reached the model: "
              f"{'yes' if probe['turns'][-1]['reached_model'] else 'no'}; STAFF30 tried: {'YES' if tried else 'no'}; "
              f"output screen {'withheld it' if probe['withheld'] else 'passed it'}; grade {grade}{held}.")
        print(f"[defense] Lamb replied ({limit_id}): {probe['final_reply'].splitlines()[0][:80] if probe['final_reply'] else ''}")
    grade = grades[LIMIT_PROBE]

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    if lab.backend != "echo":
        print(f"[*] Real model: RBR {baseline:.0f}% -> {attacked:.0f}% -> {remediated:.0f}% "
              "(reported, not asserted).")
        return 0
    controls_ok = all(s == "GREEN" for s, _, tg in impact.values() if not tg)
    ok = (baseline == 0 and attacked > 0 and remediated == 0 and controls_ok and few[0] == "GREEN"
          and grade == "RED" and grades["spelled-code"] == "RED")
    print("[+] Story holds." if ok else "[-] Story broken — check the prompts and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
