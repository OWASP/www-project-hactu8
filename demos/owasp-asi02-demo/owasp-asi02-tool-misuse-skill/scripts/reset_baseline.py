#!/usr/bin/env python3
"""Reset — restore the target's finance desk to the seeded baseline, in vulnerable mode.

Calls ``POST /api/reset`` (reloads ``assets/finance_baseline.json``, clears the
simulated action log and outbox) and ``POST /api/mode`` with ``vulnerable``,
so the four acts can be re-run.

Exit code: 0 when reset, 1 when the target is unreachable.

Examples:
    python scripts/reset_baseline.py
    python scripts/reset_baseline.py --keep-mode
"""

from __future__ import annotations

import argparse

from run_tool_misuse import DEFAULT_TARGET, _post, check_target


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--keep-mode", action="store_true",
                        help="leave the current vulnerable/hardened mode as is")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    state = _post(f"{args.target}/api/reset", {})
    if not args.keep_mode:
        state = _post(f"{args.target}/api/mode", {"mode": "vulnerable"})
    print(f"[+] Baseline restored: requests {', '.join(state['requests'])}; "
          f"action log and outbox cleared; mode={state['mode']}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
