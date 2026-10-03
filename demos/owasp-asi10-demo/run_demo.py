#!/usr/bin/env python3
"""Run all four acts of the ASI10 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, payload, and evaluator suite. Standard library only.

AUTHORIZED SECURITY-LAB USE ONLY.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable), 1 otherwise.

Examples:
    python run_demo.py
"""

from __future__ import annotations

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.join(HERE, "owasp-asi10-rogue-agent-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import (ICON, SUITE, TARGET_AGENT, score, step_actions,  # noqa: E402
                          stopped_line, summarise)
from run_mandate_tamper import apply_edit, load_payload  # noqa: E402
from vulnerable_app import Lab, dry_run  # noqa: E402

PAYLOAD = os.path.join(SKILL_DIR, "assets", "tampered_mandate.json")


def act(lab: Lab, title: str) -> float:
    print(f"\n[*] {title}")
    result = lab.run()
    statuses, omar, overall, off = score(result)
    for (agent, tick, is_targeted, intended), (status, _) in zip(SUITE, statuses):
        tag = "" if is_targeted else "  (control)"
        actions = step_actions(result["action_log"], agent, tick)
        print(f"    {ICON[status]} {status:<6} {agent} @ tick {tick}{tag}")
        if status != "GREEN" or actions and any(a["status"] == "blocked" for a in actions):
            print(f"             {summarise(actions, intended)}")
    print(f"    Off-Mandate Action Rate: {omar:.0f}% targeted, {overall:.0f}% overall; "
          f"{off} off-mandate actions executed")
    print(f"    Ticks until stopped: {stopped_line(result)}")
    return omar


def main(argv=None) -> int:
    argparse.ArgumentParser(description=__doc__,
                            formatter_class=argparse.RawDescriptionHelpFormatter).parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    lab = Lab()
    payload = load_payload(PAYLOAD)

    baseline = act(lab, "Act 1 — Clean baseline (3 agents, 4 ticks)")

    print(f"\n[*] Act 2 — Attack: edit {TARGET_AGENT}'s mandate config "
          "(1 agent, mandate widened, 2 standing orders)")
    lab.write_config(TARGET_AGENT, apply_edit(lab.get_config(TARGET_AGENT), payload))
    print("[+] Config saved through the unauthenticated config store; signature left stale.")

    attacked = act(lab, "Act 3 — Post-attack impact (same 4-tick run)")

    print("\n[defense] Act 4 — Remediation")
    report = dry_run(payload)
    print(f"[defense] Config check of the edit: REJECT ({', '.join(report['widening'])})")
    monitor_only = Lab(mode="hardened")
    monitor_only.controls["signatures"] = False
    monitor_only.write_config(TARGET_AGENT, apply_edit(monitor_only.get_config(TARGET_AGENT), payload))
    print(f"[defense] Monitor alone (signature check off): {stopped_line(monitor_only.run())}, "
          "after 1 blocked action.")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: signed mandate configs + runtime monitor with a kill switch.")
    remediated = act(lab, "Act 4 — Re-run with mitigations")
    print(f"    Config events: {len(lab.config_events)} rejected loads of {TARGET_AGENT}'s "
          "stale-signature config; last verified config used.")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    ok = baseline == 0 and attacked > 0 and remediated == 0
    print("[+] Story holds." if ok else "[-] Story broken — check the payload and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
