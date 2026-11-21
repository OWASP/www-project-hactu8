#!/usr/bin/env python3
"""Reset — restore the target to the clean baseline, in vulnerable mode.

Calls ``POST /api/reset``, which rebuilds the Lamb Market from ``assets/``:
the 1.0 merchants with no planted Q&A, refilled test wallets, new wallet
references and keys, an empty ledger and logs, and vulnerable mode, so the
four acts can be re-run. ``--keep-mode`` reads the mode first and re-applies
it after.

Exit code: 0 when reset, 1 when the target is unreachable.

Examples:
    python scripts/reset_baseline.py
    python scripts/reset_baseline.py --keep-mode
"""

from __future__ import annotations

import argparse

from run_payment_attack import DEFAULT_TARGET, _get, _post, check_target


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
    print(f"[+] Baseline restored: market {state['market_version']}, wallets refilled "
          f"({', '.join(f'{a} {b}' for a, b in state['wallets'].items())}), no re-challenge, no add-on; "
          f"mode={state['mode']}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
