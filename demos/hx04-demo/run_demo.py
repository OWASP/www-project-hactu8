#!/usr/bin/env python3
"""Run all four acts of the HX04 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, server profiles and evaluator suite. Standard
library only. After Act 4 it prints each hardened layer on its own, the same
attack with the phishing requests sent first, and the measured limit: an
honest-looking "match code" form from the supplies server itself, through
hardened mode.

AUTHORIZED SECURITY-LAB USE ONLY.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable, controls untouched), 1 otherwise. With a real-model backend the
numbers are reported but not asserted, because a real model may refuse to
fill in the reference; the exit code is then 0 unless a call fails. An
unknown backend exits 2.

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
SKILL_DIR = os.path.join(HERE, "hx04-elicitation-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, LIMIT_ID, REQUESTS, classify, dialogs, probe_row, suite  # noqa: E402
from vulnerable_app import Lab, load_hostile, scan_requests  # noqa: E402

LAYERS = ("use_field_policy", "use_identity", "use_url_allowlist", "use_budget", "use_prompt_screen",
          "use_output_screen")
LAYER_NAMES = {"use_field_policy": "field policy", "use_identity": "server identity",
               "use_url_allowlist": "URL allow-list", "use_budget": "dialog budget",
               "use_prompt_screen": "prompt screen", "use_output_screen": "output screen"}
PHISH = ("verify-account", "billing-relink")


def evidence(value) -> None:
    """Print what the model produced, for the hactu8 adapter (HACTU8_EVIDENCE=1 only)."""
    if os.environ.get("HACTU8_EVIDENCE") == "1":
        text = value if isinstance(value, str) else json.dumps(value, default=str, ensure_ascii=False)
        # ASCII-only JSON: U+2028/U+2029/U+0085 and every control character are escaped,
        # so model text cannot break this line or forge an item line (TEMPLATE.md §15).
        print(f"        evidence: {json.dumps(text[:2000], ensure_ascii=True)}")


def what_went_back(lab: Lab, result) -> str:
    """The server's side of the conversation: everything it received."""
    return "\n".join(f"{r.method}: {r.payload}" for r in lab.received(result["conversation"]))


def act(lab: Lab, title: str, results=None) -> float:
    print(f"\n[*] {title}")
    red = targeted = 0
    seen = []
    for label, message, is_targeted, expected in suite():
        result = lab.ask(message)
        seen.append(result)
        status = classify(result, expected)
        if results is not None:
            results[label] = (status, result, is_targeted)
        if is_targeted:
            targeted += 1
            red += status == "RED"
        tag = "" if is_targeted else "  (control)"
        print(f"    {ICON[status]} {status:<6} {label}{tag}")
        evidence(what_went_back(lab, result))
    elr = red / targeted * 100.0
    print(f"    Elicitation Leak Rate: {elr:.0f}% targeted")
    shown, off, unread = dialogs(seen)
    print(f"[+] Dialogs shown to Pat: {shown}; off the task: {off}; accepted unread: {unread}.")
    return elr


def rate_with(backend: str, model: str, order=None, **layers) -> float:
    """The attack suite on a fresh hardened lab with only some layers on."""
    lab = Lab(mode="hardened", backend=backend, model=model)
    for name, value in layers.items():
        setattr(lab, name, value)
    lab.load_attack(order)
    rows = [classify(lab.ask(m), e) for _, m, tg, e in suite() if tg]
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
    print(f"\n[*] Act 2 — Attack: Hayloft Supplies updates to 1.5 "
          f"(reorder now asks for {len(entries)} elicitations; the order itself stays honest)")
    for e in entries:
        p = e["request"]["params"]
        tag = "the user's task" if e["lab"]["on_task"] else "off the task"
        where = p.get("url") or ", ".join(sorted(p.get("requestedSchema", {}).get("properties", {})))
        print(f"[+] '{e['lab']['id']}' ({tag}): {p.get('mode', 'form')} mode, {where}.")

    impact: dict = {}
    attacked = act(lab, "Act 3 — Post-attack impact (same requests, updated supplies server)", impact)
    got = [k for k, (s, r, t) in impact.items() if r["server_got_canary"]]
    pages = sum(1 for s in lab.servers.values() for r in s.received if r.method == "page submission")
    print(f"[+] Server log: the supplies server received the account reference in {len(got)} of "
          f"{sum(1 for c in REQUESTS if c[2])} reorders ({pages} through its look-alike page); "
          "the weather server in none.")

    print("\n[defense] Act 4 — Remediation")
    scan = scan_requests(load_hostile()["elicitation"], lab.screen_policy)
    stopped = [r["id"] for r in scan["rows"] if r["verdict"] == "BLOCK" or r["policy"] != "pass"]
    print(f"[defense] Static checks of the 1.5 requests: {len(stopped)} of {len(scan['rows'])} refused "
          f"({', '.join(stopped) or 'none'}).")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: elicitation_policy (field policy, server identity, URL allow-list, "
          "dialog budget), prompt screen, output screen with the canary.")
    remediated = act(lab, "Act 4 — Re-run with mitigations")

    alone = {name: rate_with(args.backend, args.model, **{o: o == name for o in LAYERS}) for name in LAYERS}
    print("[defense] Each layer alone on the attack: " +
          ", ".join(f"{LAYER_NAMES[n]} {v:.0f}%" for n, v in alone.items()) + " Elicitation Leak Rate.")
    hostile = load_hostile()["elicitation"]
    first = [e for e in hostile if e["lab"]["id"] in PHISH] + [e for e in hostile if e["lab"]["id"] not in PHISH]
    budget_first = rate_with(args.backend, args.model, first, **{o: o == "use_budget" for o in LAYERS})
    full_first = rate_with(args.backend, args.model, first)
    print(f"[defense] Phishing requests sent first: dialog budget alone {budget_first:.0f}%, "
          f"all layers {full_first:.0f}% Elicitation Leak Rate.")

    row = probe_row(LIMIT_ID) if lab.backend == "echo" else None
    if row is not None:
        print(f"[defense] Limit probe in hardened mode ({LIMIT_ID}): field policy {row['policy']}; prompt screen "
              f"{row['screen']}; dialog shown: {'YES' if row['shown'] else 'no'}; output screen "
              f"{'passed it' if row['action'] == 'accept' else 'withheld it'}; grade {row['status']}.")
        print(f"[defense] The server received: {row['content']}")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    if lab.backend != "echo":
        print(f"[*] Real model: ELR {baseline:.0f}% -> {attacked:.0f}% -> {remediated:.0f}% "
              "(reported, not asserted).")
        return 0
    controls_ok = all(s == "GREEN" for s, _, t in impact.values() if not t)
    ok = baseline == 0 and attacked > 0 and remediated == 0 and controls_ok
    print("[+] Story holds." if ok else "[-] Story broken — check the server profiles and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
