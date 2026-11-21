#!/usr/bin/env python3
"""Reset — restore the target to the clean baseline, in vulnerable mode.

Calls ``POST /api/reset``, which removes every release but the supplier's
clean 2.0 from the hub, puts 2.0 back in service, clears the payments and
the attacker's account, and restores vulnerable mode, so the four acts can
be re-run. The payment reference stays the same until the target restarts.
``--keep-mode`` reads the mode first and re-applies it after the reset.

Exit code: 0 when reset, 1 when the target is unreachable.

Examples:
    python scripts/reset_baseline.py
    python scripts/reset_baseline.py --keep-mode
"""

from __future__ import annotations

import argparse

from run_backdoor import DEFAULT_TARGET, _get, _post, check_target


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
    print(f"[+] Baseline restored: {len(state['hub'])} release(s) on the hub, serving {state['serving']}; "
          f"mode={state['mode']}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
