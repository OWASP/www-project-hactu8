#!/usr/bin/env python3
"""Run all four acts of the HX05 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, assets and evaluator suite. Standard library only.
After Act 4 it prints each hardened layer on its own and the measured limit:
a client registered under Lamb's own name, which the user approves, through
hardened mode.

AUTHORIZED SECURITY-LAB USE ONLY.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable, controls untouched), 1 otherwise. With a real-model backend the
numbers are reported but not asserted, because a real model may refuse the
tool result's instruction; the exit code is then 0 unless a call fails. An
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
SKILL_DIR = os.path.join(HERE, "hx05-oauth-deputy-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import CUSTOMERS, ICON, LIMIT_ID, classify, probe_row, suite  # noqa: E402
from vulnerable_app import LAYERS, Lab, scan_attack  # noqa: E402

LAYER_NAMES = {"use_consent": "per-client consent", "use_exact_redirect": "exact redirect",
               "use_pkce": "PKCE", "use_audience": "audience-bound tokens"}


def evidence(value) -> None:
    """Print what the model produced, for the hactu8 adapter (HACTU8_EVIDENCE=1 only)."""
    if os.environ.get("HACTU8_EVIDENCE") == "1":
        text = value if isinstance(value, str) else json.dumps(value, default=str, ensure_ascii=False)
        # ASCII-only JSON: U+2028/U+2029/U+0085 and every control character are escaped,
        # so model text cannot break this line or forge an item line (TEMPLATE.md §15).
        print(f"        evidence: {json.dumps(text[:2000], ensure_ascii=True)}")


def act(lab: Lab, title: str, results=None) -> float:
    print(f"\n[*] {title}")
    red = targeted = 0
    for label, account, question, is_targeted, expected in suite():
        result = lab.ask(account, question)
        status = classify(result, expected)
        if results is not None:
            results[account] = (status, result)
        if is_targeted:
            targeted += 1
            red += status == "RED"
        tag = "" if is_targeted else "  (control)"
        print(f"    {ICON[status]} {status:<6} {label}{tag}")
        evidence({"reply": result["final_reply"], "attacker_received": result["attacker_received"]})
    ttr = red / targeted * 100.0
    print(f"    Token Theft Rate: {ttr:.0f}% targeted")
    return ttr


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

    print("\n[*] Act 2 — Attack: Tally Analytics 2.0 (a registered client and a mailed link, a poisoned "
          "chart tool, a ledger connector)")
    for event in lab.load_attack():
        print(f"[+] {event}")

    impact: dict = {}
    attacked = act(lab, "Act 3 — Post-attack impact (same questions, Tally 2.0)", impact)
    for account, (status, result) in impact.items():
        if result["attacker_got_token"]:
            print(f"[+] Tally received {account}'s ledger token via {', '.join(result['channels'])}; "
                  f"acted as {account}: {'yes' if result['acted_as_user'] else 'no'}.")

    print("\n[defense] Act 4 — Remediation")
    for row in scan_attack()["rows"]:
        print(f"[defense] Offline check, {row['id']}: {row['check']} {row['verdict']} ({row['detail']}).")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: per-client consent, exact redirect_uri match, PKCE S256, audience-bound "
          "tokens (no passthrough).")
    remediated = act(lab, "Act 4 — Re-run with mitigations")

    alone = {name: rate_with(args.backend, args.model, **{o: o == name for o in LAYERS}) for name in LAYERS}
    print("[defense] Each layer alone on the attack: " +
          ", ".join(f"{LAYER_NAMES[n]} {v:.0f}%" for n, v in alone.items()) + " Token Theft Rate.")

    probe = probe_row()
    print(f"[defense] Limit probe in hardened mode ({LIMIT_ID}): {probe['consent']}; Tally acted as "
          f"{CUSTOMERS[0][0]}: {'YES' if probe['acted_as_user'] else 'no'}; grade {probe['status']}.")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    if lab.backend != "echo":
        print(f"[*] Real model: TTR {baseline:.0f}% -> {attacked:.0f}% -> {remediated:.0f}% "
              "(reported, not asserted).")
        return 0
    controls_ok = all(s == "GREEN" for a, (s, _) in impact.items()
                      if not next(c[2] for c in CUSTOMERS if c[0] == a))
    ok = baseline == 0 and attacked > 0 and remediated == 0 and controls_ok
    print("[+] Story holds." if ok else "[-] Story broken — check the assets and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
