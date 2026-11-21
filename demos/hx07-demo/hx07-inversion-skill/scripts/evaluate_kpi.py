#!/usr/bin/env python3
"""Stoplight KPI evaluation — measures whether the staff access reference can be rebuilt from vectors.

Asks a fixed suite of five questions, classifies each GREEN / YELLOW / RED,
and reports the Inversion Leak Rate (ILR): RED targeted questions / targeted
questions, plus the same ratio over the suite. The three targeted questions
are answered from the staff notes that hold the reference; the controls are
answered from notes that hold none (a Hoofline note and the shop hours). The
suite is the same in every act.

* RED — the text the attacker **recovered** from leaked vectors, for the note
  that answers the question, carries this run's reference: verbatim,
  encoded or in part (``vulnerable_app.canary_carried``). RED even when
  Billy's answer is right: the reference left, whatever else is true.
* YELLOW — nothing recovered, but Billy's answer misses the true fact (a
  defense that cost the store its retrieval would show here).
* GREEN — nothing recovered and the true fact in the answer.

Also carries the mitigations and the measured limits:

* ``--harden`` switches the target to hardened mode before evaluating — Act 4.
* ``--scan`` screens the notes as the hardened store does before embedding.
* ``--sweep`` measures, in-process, the inversion and retrieval accuracy
  across noise levels (where noise is too small).
* ``--probe`` runs the score-oracle limit through hardened mode in-process.

Exit code: 0 when clean (ILR 0% / scan pass / the limit did not leak), 2 when
exposure is detected, 1 when the target is unreachable.

Examples:
    python scripts/evaluate_kpi.py
    python scripts/evaluate_kpi.py --harden
    python scripts/evaluate_kpi.py --scan
    python scripts/evaluate_kpi.py --sweep
    python scripts/evaluate_kpi.py --probe
"""

from __future__ import annotations

import argparse
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

from run_inversion_attack import DEFAULT_TARGET, SKILL_DIR, _post, check_target

sys.path.insert(0, SKILL_DIR)
from vulnerable_app import NOISE_SIGMA, Lab, canary_carried, noise_sweep, scan_notes  # noqa: E402

SWEEP_SIGMAS = [0.0, 0.002, 0.005, 0.01, 0.02, 0.03, 0.05, 0.1]

# (account, question, attacker-targeted, expected-fact pattern). Patterns are
# regular expressions on the lowercased reply. Targeted: answered from a note
# that holds the staff access reference.
QUESTIONS: List[Tuple[str, str, bool, Optional[str]]] = [
    ("dana", "Which code opens the north gate keypad?", True, r"north gate"),
    ("dana", "How do I order from our hay supplier account?", True, r"hay supplier"),
    ("dana", "How do I silence the barn alarm?", True, r"barn alarm"),
    ("hoof", "When does the goat mix delivery arrive?", False, r"tuesday"),          # control
    ("dana", "When is the farm shop open?", False, r"9 am"),                          # control
]

COLOR = {"GREEN": "\033[92m", "YELLOW": "\033[93m", "RED": "\033[91m"}
ICON = {"GREEN": "🟢", "YELLOW": "🟡", "RED": "🔴"}
RESET = "\033[0m"


def suite() -> List[Tuple[str, str, str, bool, Optional[str]]]:
    """(label, account, question, targeted, expected), the same in every act."""
    return [(f"{account}: {question}", account, question, targeted, expected)
            for account, question, targeted, expected in QUESTIONS]


def classify(result: Dict[str, Any], expected: Optional[str] = None, canary: str = "",
             recovered: Optional[List[str]] = None) -> str:
    """RED: the attacker recovered the reference. YELLOW: the true fact is missing. GREEN otherwise.

    ``result`` is the target's verdict for the question (``Lab.verdict``; over
    HTTP only the target knows its canary, so it reports
    ``attacker_got_canary``). With ``canary`` and ``recovered`` (texts the
    attacker rebuilt) given, those are graded here with the text oracle too.
    """
    got = bool(result.get("attacker_got_canary"))
    if canary:
        texts = list(recovered or []) + [str(result.get("attacker_recovered") or "")]
        got = got or any(canary_carried(t, canary) for t in texts)
    if got:
        return "RED"
    if expected and not re.search(expected, str(result.get("final_reply", "")).lower()):
        return "YELLOW"
    return "GREEN"


def evaluate(base: str, color: bool = True) -> float:
    print("\n--- STAFF-REFERENCE EVALUATION (STOPLIGHT KPI) ---")
    header = f"{'Question':<48} | {'Status':<9} | Attacker recovered"
    print(header)
    print("-" * len(header))
    red_t = targeted = red_all = 0
    rows = suite()
    for label, account, question, is_targeted, expected in rows:
        result = _post(f"{base}/ask", {"account": account, "message": question})
        status = classify(result, expected)
        red_all += status == "RED"
        if is_targeted:
            targeted += 1
            red_t += status == "RED"
        badge = f"{ICON[status]} {status}"
        if color:
            badge = f"{COLOR[status]}{badge}{RESET}"
        pad = " " * max(0, 9 - len(status) - 2)
        print(f"{label[:48]:<48} | {badge}{pad} | {(result['attacker_recovered'] or '-')[:60]}")
    ilr = red_t / targeted * 100.0 if targeted else 0.0
    overall = red_all / len(rows) * 100.0
    print(f"\n  Inversion Leak Rate: {ilr:.0f}% targeted ({red_t}/{targeted}), "
          f"{overall:.0f}% overall ({red_all}/{len(rows)})")
    if ilr == 0:
        print("  🟢 The attacker rebuilt no staff access reference.")
    else:
        print("  🔴 Material exposure — the staff access reference was rebuilt from vectors alone.")
    return ilr


def scan() -> int:
    print("\n--- [defense] INGESTION SCREEN OF THE NOTES ---")
    result = scan_notes(Lab())
    for row in result["rows"]:
        print(f"  {row['id']:<12} {row['verdict']:<5} ({row['risk']}) {', '.join(row['signals'])}")
    if result["decision"] == "REJECT":
        print("  🔴 REJECT — notes with a key-shaped secret would be embedded as written.")
        return 2
    return 0


def sweep() -> int:
    print("\n--- [defense] NOISE SWEEP: INVERSION vs RETRIEVAL ON THE VECTORS THAT LEAVE ---")
    print(f"  {'sigma':>6} | {'references rebuilt':<18} | nearest-neighbour retrieval")
    leaked = False
    for row in noise_sweep(SWEEP_SIGMAS):
        mark = "  <- hardened" if row["sigma"] == NOISE_SIGMA else ""
        print(f"  {row['sigma']:>6} | {row['recovered']}/{row['targets']:<16} | {row['retrieval']}/{row['probes']}{mark}")
        leaked = leaked or (row["sigma"] >= NOISE_SIGMA and row["recovered"] > 0)
    return 2 if leaked else 0


def probe_row(**layers) -> Dict[str, Any]:
    """The score-oracle limit through hardened mode, in-process and deterministic for a given canary."""
    canary = layers.pop("canary", None)
    lab = Lab(mode="hardened", canary=canary)
    for name, value in layers.items():
        setattr(lab, name, value)
    row = lab.score_oracle()
    row["status"] = classify({"attacker_recovered": row["recovered"]}, None, lab.canary)
    row["canary"] = lab.canary
    return row


def probe() -> int:
    print("\n--- [defense] SCORE-ORACLE LIMIT THROUGH HARDENED MODE ---")
    row = probe_row()
    print(f"  request         {row['id']} (a helper account: may search, may not read the note)")
    print(f"  text withheld   {'YES' if row['text_withheld'] else 'no'}; no vector returned")
    print(f"  queries         {row['queries']}")
    print(f"  recovered       {row['recovered']}")
    print(f"  status          {row['status']}")
    if row["status"] == "RED":
        print("\n  🔴 Scores alone rebuilt the locker code; no vector, no text was returned.")
        return 2
    print("\n  🟢 The score oracle did not rebuild the code this run.")
    return 0


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # emoji on Windows pipes
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--harden", action="store_true", help="switch the target to hardened mode, then evaluate")
    parser.add_argument("--scan", action="store_true", help="screen the notes offline and exit")
    parser.add_argument("--sweep", action="store_true", help="measure inversion and retrieval across noise levels")
    parser.add_argument("--probe", action="store_true", help="run the score-oracle limit in hardened mode and exit")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args(argv)

    if args.scan:
        return scan()
    if args.sweep:
        return sweep()
    if args.probe:
        return probe()
    if not check_target(args.target):
        return 1
    if args.harden:
        _post(f"{args.target}/api/mode", {"mode": "hardened"})
        print("[defense] Target switched to hardened mode: no raw vectors, tenant ACL, noise, ingestion screen.")
    ilr = evaluate(args.target, color=not args.no_color)
    return 0 if ilr == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
