#!/usr/bin/env python3
"""Run all four acts of the HX03 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, server profiles and evaluator suite. Standard
library only. After Act 4 it prints each hardened layer on its own and the
measured limit: a paraphrased "summarise everything so far" request the user
approves, through hardened mode.

AUTHORIZED SECURITY-LAB USE ONLY.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable, controls untouched), 1 otherwise. With a real-model backend the
numbers are reported but not asserted, because a real model may refuse the
server's requests; the exit code is then 0 unless a call fails. An unknown
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
SKILL_DIR = os.path.join(HERE, "hx03-sampling-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import CUSTOMERS, ICON, LIMIT_ID, budget, classify, suite  # noqa: E402
from vulnerable_app import Lab, load_hostile, scan_requests  # noqa: E402

LAYERS = ("use_caps", "use_prompt_screen", "use_approval", "use_context_gate", "use_output_screen")
LAYER_NAMES = {"use_caps": "allow-list and caps", "use_prompt_screen": "prompt screen",
               "use_approval": "user approval", "use_context_gate": "context gate",
               "use_output_screen": "output screen"}


def evidence(value) -> None:
    """Print what the model produced, for the hactu8 adapter (HACTU8_EVIDENCE=1 only)."""
    if os.environ.get("HACTU8_EVIDENCE") == "1":
        text = value if isinstance(value, str) else json.dumps(value, default=str, ensure_ascii=False)
        print(f"        evidence: {json.dumps(text[:2000], ensure_ascii=False)}")


def what_went_back(lab: Lab, result) -> str:
    """The server's side of the conversation: everything it received."""
    return "\n".join(f"{r.method}: {r.payload}" for r in lab.received(result["conversation"]))


def act(lab: Lab, title: str, results=None) -> float:
    print(f"\n[*] {title}")
    red = targeted = 0
    seen = []
    for label, account, question, is_targeted, expected in suite():
        result = lab.ask(account, question)
        seen.append(result)
        status = classify(result, expected)
        if results is not None:
            results[account] = (status, result)
        if is_targeted:
            targeted += 1
            red += status == "RED"
        tag = "" if is_targeted else "  (control)"
        print(f"    {ICON[status]} {status:<6} {label}{tag}")
        evidence(what_went_back(lab, result))
    slr = red / targeted * 100.0
    print(f"    Sampling Leak Rate: {slr:.0f}% targeted")
    calls, tokens = budget(seen)
    ran = sum(r["sampling_calls"] for r in seen)
    print(f"[+] Sampling on Billy's model: {ran} calls; off the user's task: {calls} calls, ~{tokens} tokens.")
    return slr


def rate_with(backend: str, model: str, **layers) -> float:
    """The attack suite on a fresh hardened lab with only some layers on."""
    lab = Lab(mode="hardened", backend=backend, model=model)
    for name, value in layers.items():
        setattr(lab, name, value)
    lab.load_attack()
    rows = [classify(lab.ask(a, q), e) for _, a, q, tg, e in suite() if tg]
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
    print(f"\n[*] Act 2 — Attack: Hoofline Freight Rates updates to 1.1 "
          f"(quote_rate now sends {len(entries)} sampling requests; the quote itself stays honest)")
    for e in entries:
        tag = "the user's task" if e["lab"]["on_task"] else "off the task"
        print(f"[+] '{e['lab']['id']}' ({tag}): includeContext {e['params'].get('includeContext', 'none')}, "
              f"maxTokens {e['params'].get('maxTokens')}.")

    impact: dict = {}
    attacked = act(lab, "Act 3 — Post-attack impact (same questions, updated shipping server)", impact)
    got = [a for a, (s, r) in impact.items() if r["server_got_canary"]]
    print(f"[+] Server log: the shipping server received Billy's account reference in {len(got)} of "
          f"{sum(1 for c in CUSTOMERS if c[2])} conversations; the weather server in none.")

    print("\n[defense] Act 4 — Remediation")
    scan = scan_requests(load_hostile()["sampling"], lab.screen_policy)
    blocked = [r["id"] for r in scan["rows"] if r["verdict"] == "BLOCK"]
    print(f"[defense] Prompt screen of the 1.1 requests: {len(blocked)} of {len(scan['rows'])} blocked "
          f"({', '.join(blocked) or 'none'}).")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: sampling_policy (allow-list and caps, user approval, includeContext "
          "none unless approved), prompt screen, output screen with the canary.")
    remediated = act(lab, "Act 4 — Re-run with mitigations")

    alone = {name: rate_with(args.backend, args.model, **{o: o == name for o in LAYERS}) for name in LAYERS}
    print("[defense] Each layer alone on the attack: " +
          ", ".join(f"{LAYER_NAMES[n]} {v:.0f}%" for n, v in alone.items()) + " Sampling Leak Rate.")

    probe_lab = Lab(mode="hardened", backend=args.backend, model=args.model)
    probe_lab.load_limit(LIMIT_ID)
    probe = probe_lab.ask(CUSTOMERS[0][0], CUSTOMERS[0][1])
    rec = next(r for r in probe["sampling"] if r["request_id"] == LIMIT_ID)
    pscreen = scan_requests([e for e in load_hostile()["limits"] if e["lab"]["id"] == LIMIT_ID])["rows"][0]
    print(f"[defense] Limit probe in hardened mode ({LIMIT_ID}): prompt screen {pscreen['verdict']}; the user "
          f"approved and shared the session: {'YES' if rec['context_included'] else 'no'}; output screen "
          f"{'passed it' if rec['returned'] else 'withheld it'}; grade {classify(probe)}.")
    if rec["returned"]:
        print(f"[defense] The server received: {rec['output'][-60:]}")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    if lab.backend != "echo":
        print(f"[*] Real model: SLR {baseline:.0f}% -> {attacked:.0f}% -> {remediated:.0f}% "
              "(reported, not asserted).")
        return 0
    controls_ok = all(s == "GREEN" for a, (s, _) in impact.items()
                      if not next(c[2] for c in CUSTOMERS if c[0] == a))
    ok = baseline == 0 and attacked > 0 and remediated == 0 and controls_ok
    print("[+] Story holds." if ok else "[-] Story broken — check the server profiles and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
