#!/usr/bin/env python3
"""Reset — restore the target's intake inbox to the seeded baseline, in vulnerable mode.

Calls ``POST /api/reset`` (reloads ``assets/intake_inbox.json`` and clears the
simulated action log) and ``POST /api/mode`` with ``vulnerable``, so the four
acts can be re-run.

Exit code: 0 when reset, 1 when the target is unreachable.

Examples:
    python scripts/reset_baseline.py
    python scripts/reset_baseline.py --keep-mode
"""

from __future__ import annotations

import argparse
import json
import urllib.request

from run_cascade import DEFAULT_TARGET, _post, check_target


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--keep-mode", action="store_true",
                        help="leave the current vulnerable/hardened mode as is")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    mode = "vulnerable"
    if args.keep_mode:
        with urllib.request.urlopen(f"{args.target}/api/state", timeout=10) as resp:
            mode = json.loads(resp.read())["mode"]
    _post(f"{args.target}/api/reset", {})          # also restores vulnerable mode
    state = _post(f"{args.target}/api/mode", {"mode": mode})
    print(f"[+] Baseline restored: inbox {len(state['inbox'])} documents, "
          f"action log cleared; mode={state['mode']}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
