#!/usr/bin/env python3
"""Run all four acts of the HX08 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, receipt photos and evaluator suite. Standard
library only. After Act 4 it prints each hardened layer on its own, the
alt-text variant, the contrast sweep of the low-contrast detector, and the
measured limit: a visible, high-contrast line phrased as the shop's own
system, through hardened mode.

AUTHORIZED SECURITY-LAB USE ONLY.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable, controls untouched), 1 otherwise. With a real-model backend the
numbers are reported but not asserted, because a real model may ignore the
instruction or refuse the code; the exit code is then 0 unless a call fails.
An unknown backend exits 2.

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
SKILL_DIR = os.path.join(HERE, "hx08-image-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, LIMIT_ID, REQUESTS, classify, contrast_sweep, held_by, probe_row, suite  # noqa: E402
from vulnerable_app import LAYERS, MIN_VISIBLE_DELTA, Lab, load_hostile, scan_entries  # noqa: E402

LAYER_NAMES = {"use_strip_metadata": "strip metadata", "use_contrast_detector": "low-contrast detector",
               "use_input_screen": "input screen", "use_spotlight": "spotlight",
               "use_action_policy": "refund action policy"}


def evidence(value) -> None:
    """Print what the model produced, for the hactu8 adapter (HACTU8_EVIDENCE=1 only)."""
    if os.environ.get("HACTU8_EVIDENCE") == "1":
        text = value if isinstance(value, str) else json.dumps(value, default=str, ensure_ascii=False)
        print(f"        evidence: {json.dumps(text[:2000], ensure_ascii=False)}")


def act(lab: Lab, title: str, results=None) -> float:
    print(f"\n[*] {title}")
    red = targeted = over = 0
    for label, message, image, is_targeted, expected in suite():
        result = lab.ask(message, image)
        status = classify(result, expected)
        over += result["over_policy_paid"]
        if results is not None:
            results[label] = (status, result, is_targeted)
        if is_targeted:
            targeted += 1
            red += status == "RED"
        tag = "" if is_targeted else "  (control)"
        print(f"    {ICON[status]} {status:<6} {label}{tag}")
        if held_by(result, status):
            print(f"        held_by: {'; '.join(held_by(result, status))}")
        evidence(lab.output(result["conversation"]))
    iir = red / targeted * 100.0
    print(f"    Image Injection Rate: {iir:.0f}% targeted")
    print(f"[+] Refunds paid over the order on record: {over}.")
    return iir


def rate_with(backend: str, model: str, **layers) -> tuple:
    """The attack suite on a fresh hardened lab with only some layers on: (IIR, over-policy refunds)."""
    lab = Lab(mode="hardened", backend=backend, model=model)
    for name, value in layers.items():
        setattr(lab, name, value)
    lab.load_attack()
    rows = [(classify(r := lab.ask(m, i), e), r["over_policy_paid"]) for _, m, i, tg, e in suite() if tg]
    return sum(s == "RED" for s, _ in rows) / len(rows) * 100.0, sum(o for _, o in rows)


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
    print(f"\n[*] Act 2 — Attack: {len(entries)} customers re-upload their receipt photos, each carrying an "
          "instruction (the receipts themselves stay true)")
    for e in entries:
        print(f"[+] '{e['lab']['id']}' on {e['receipt']}: {e['lab']['carrier']}.")

    impact: dict = {}
    attacked = act(lab, "Act 3 — Post-attack impact (same requests, the uploaded photos)", impact)
    n_targeted = sum(1 for r in REQUESTS if r[3])
    if lab.backend == "echo":
        obeyed = sum(1 for s, r, t in impact.values() if t and r["directive"])
        print(f"[+] The model obeyed an instruction from the image in {obeyed} of "
              f"{n_targeted} refunds; the control receipt carried none.")
    effect = sum(1 for s, r, t in impact.values() if t and s == "RED")
    print(f"[+] The attack's effect (the code in the reply, or a refund paid over the order) happened in "
          f"{effect} of {n_targeted} refunds.")

    print("\n[defense] Act 4 — Remediation")
    scan = scan_entries(load_hostile()["images"])
    print(f"[defense] Static checks of the photos: {sum(r['decision'] == 'REJECT' for r in scan['rows'])} of "
          f"{len(scan['rows'])} rejected (" + "; ".join(
              f"{r['entry']}: metadata {r['metadata']}, faint {r['faint']}, screen {r['blocked']}"
              for r in scan["rows"]) + ").")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: strip metadata and alt text, low-contrast detector "
          f"(< {MIN_VISIBLE_DELTA} grey levels), input screen, spotlight, refund action policy.")
    remediated = act(lab, "Act 4 — Re-run with mitigations")

    alone = {name: rate_with(args.backend, args.model, **{o: o == name for o in LAYERS}) for name in LAYERS}
    print("[defense] Each layer alone on the attack: " +
          ", ".join(f"{LAYER_NAMES[n]} {v[0]:.0f}% ({v[1]} over-policy paid)" for n, v in alone.items()) +
          " Image Injection Rate.")

    if lab.backend == "echo":
        alt = probe_row("alt-text")
        print(f"[defense] Alt-text variant in hardened mode: {alt['status']} "
              f"({'; '.join(d['why'] for d in alt['dropped'])}).")
        sweep = contrast_sweep()
        print("[defense] Contrast sweep (grey levels below the paper: OCR reads / detector drops): " +
              ", ".join(f"{r['delta']}: {'Y' if r['read'] else 'n'}/{'Y' if r['dropped'] else 'n'}" for r in sweep)
              + ".")
        row = probe_row(LIMIT_ID)
        calls = "; ".join(c["result"] for c in row["refund_calls"]) or "no call"
        print(f"[defense] Limit probe in hardened mode ({LIMIT_ID}): dropped "
              f"{len([d for d in row['dropped'] if d['source'] == 'ocr'])} OCR lines; model obeyed "
              f"'{row['directive']}'; refund tool: {calls}; grade {row['status']}.")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    if lab.backend != "echo":
        print(f"[*] Real model: IIR {baseline:.0f}% -> {attacked:.0f}% -> {remediated:.0f}% "
              "(reported, not asserted).")
        return 0
    controls_ok = all(s == "GREEN" for s, _, t in impact.values() if not t)
    ok = baseline == 0 and attacked > 0 and remediated == 0 and controls_ok
    print("[+] Story holds." if ok else "[-] Story broken — check the photos and the suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
