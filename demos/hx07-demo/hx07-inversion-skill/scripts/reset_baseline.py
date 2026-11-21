#!/usr/bin/env python3
"""Reset — restore the target to the clean baseline, in vulnerable mode.

Calls ``POST /api/reset``, which reloads the notes from ``assets/store.json``,
stops the attack, removes the limit note, clears the export log and the query
count, and restores vulnerable mode, so the four acts can be re-run.
``--keep-mode`` reads the mode first and re-applies it after.

Exit code: 0 when reset, 1 when the target is unreachable.

Examples:
    python scripts/reset_baseline.py
    python scripts/reset_baseline.py --keep-mode
"""

from __future__ import annotations

import argparse

from run_inversion_attack import DEFAULT_TARGET, _get, _post, check_target


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--keep-mode", action="store_true",
                        help="leave the current vulnerable/hardened mode as is")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    mode = _get(f"{args.target}/api/state")["mode"]
    state = _post(f"{args.target}/api/reset", {})        # also restores vulnerable mode
    if args.keep_mode and mode != state["mode"]:
        state = _post(f"{args.target}/api/mode", {"mode": mode})
    print(f"[+] Baseline restored: {state['notes']} notes, attack stopped; mode={state['mode']}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
