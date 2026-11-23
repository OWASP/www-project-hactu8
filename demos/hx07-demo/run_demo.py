#!/usr/bin/env python3
"""Run all four acts of the HX07 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, store and evaluator suite. Standard library only.
After Act 4 it prints each hardened layer on its own, the noise sweep (where
noise is too small, and what noise costs retrieval) and the score-oracle limit
through hardened mode.

AUTHORIZED SECURITY-LAB USE ONLY.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable, controls untouched), 1 otherwise. The limit and the sweep are
reported, not asserted: they depend on this run's random reference. With a
real-model backend the numbers are reported but not asserted; the attack does
not use the model, only Lamb's wording changes. An unknown backend exits 2.

Examples:
    python run_demo.py
    python run_demo.py --backend ollama --model gemma3:4b
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.join(HERE, "hx07-inversion-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, QUESTIONS, SWEEP_SIGMAS, classify, probe_row, suite  # noqa: E402
from vulnerable_app import NOISE_SIGMA, Lab, noise_sweep, scan_notes  # noqa: E402

LAYERS = ("use_no_raw_vectors", "use_tenant_acl", "use_noise", "use_ingest_screen")
LAYER_NAMES = {"use_no_raw_vectors": "no raw vectors", "use_tenant_acl": "tenant ACL",
               "use_noise": "noise and quantisation", "use_ingest_screen": "ingestion screen"}


def evidence(value) -> None:
    """Print what the attacker produced, for the hactu8 adapter (HACTU8_EVIDENCE=1 only)."""
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
            results[label] = (status, is_targeted, result)
        if is_targeted:
            targeted += 1
            red += status == "RED"
        tag = "" if is_targeted else "  (control)"
        print(f"    {ICON[status]} {status:<6} {label}{tag}")
        evidence(result["attacker_recovered"] or "(the attacker recovered nothing for this note)")
    ilr = red / targeted * 100.0
    print(f"    Inversion Leak Rate: {ilr:.0f}% targeted")
    return ilr


def rate_with(backend: str, model: str, canary: str, **layers) -> float:
    """The attack suite on a fresh hardened lab with only some layers on."""
    lab = Lab(mode="hardened", backend=backend, model=model, canary=canary)
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

    plan = lab.load_attack()
    pulled = lab.attack()
    print(f"\n[*] Act 2 — Attack: partner account '{plan['attacker']}' reads {plan['endpoint']} "
          f"({pulled['records']} records, {pulled['vectors']} raw vectors, no text) and inverts each vector")
    for nid, got in sorted(pulled["recovered"].items()):
        print(f"[+] '{nid}': {'complete' if got['complete'] else 'partial'} after {got['nodes']} search nodes.")

    impact: dict = {}
    attacked = act(lab, "Act 3 — Post-attack impact (same questions, the attacker's reconstructions)", impact)
    hits = sum(1 for s, t, _ in impact.values() if s == "RED")
    print(f"[+] The staff access reference was rebuilt from vectors alone for {hits} of "
          f"{sum(1 for q in QUESTIONS if q[2])} staff notes; Lamb's answers were all still right.")

    print("\n[defense] Act 4 — Remediation")
    scan = scan_notes(lab)
    blocked = [r["id"] for r in scan["rows"] if r["verdict"] == "BLOCK"]
    print(f"[defense] Ingestion screen of the notes: {len(blocked)} of {len(scan['rows'])} embedded redacted "
          f"({', '.join(blocked) or 'none'}).")
    lab.set_mode("hardened")
    print(f"[defense] Hardened mode: no raw vectors, tenant ACL on the export, noise sigma {NOISE_SIGMA} with "
          "8-bit quantisation on any vector that leaves, scores to 2 decimals, ingestion screen.")
    remediated = act(lab, "Act 4 — Re-run with mitigations")

    alone = {name: rate_with(args.backend, args.model, lab.canary, **{o: o == name for o in LAYERS})
             for name in LAYERS}
    print("[defense] Each layer alone on the attack: " +
          ", ".join(f"{LAYER_NAMES[n]} {v:.0f}%" for n, v in alone.items()) + " Inversion Leak Rate.")

    sweep = noise_sweep(SWEEP_SIGMAS, canary=lab.canary)
    print("[defense] Noise sweep, vectors leaving the store (sigma: references rebuilt, probe retrieval): " +
          "; ".join(f"{r['sigma']}: {r['recovered']}/{r['targets']}, {r['retrieval']}/{r['probes']}"
                    for r in sweep) + ".")

    probe = probe_row(canary=lab.canary)
    print(f"[defense] Limit probe in hardened mode ({probe['id']}): a helper account that may search but not "
          f"read the restricted locker note; no vector returned, text withheld: "
          f"{'YES' if probe['text_withheld'] else 'no'}; {probe['queries']} search queries; grade {probe['status']}.")
    print(f"[defense] Rebuilt from scores alone: {probe['recovered']}")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    if lab.backend != "echo":
        print(f"[*] Real model: ILR {baseline:.0f}% -> {attacked:.0f}% -> {remediated:.0f}% "
              "(reported, not asserted).")
        return 0
    controls_ok = all(s == "GREEN" for s, t, _ in impact.values() if not t)
    ok = baseline == 0 and attacked > 0 and remediated == 0 and controls_ok
    print("[+] Story holds." if ok else "[-] Story broken — check the store and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
