#!/usr/bin/env python3
"""Reset — restore the approved tool registry, in vulnerable mode.

Calls ``POST /api/reset`` (rewrites ``registry/registry.json`` from
``assets/registry_baseline.json`` and reinstalls every tool) and
``POST /api/mode`` with ``vulnerable``, so the four acts can be re-run.

Exit code: 0 when reset, 1 when the target is unreachable.

Examples:
    python scripts/reset_baseline.py
    python scripts/reset_baseline.py --keep-mode
"""

from __future__ import annotations

import argparse

from run_rug_pull import DEFAULT_TARGET, _post, check_target


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
    versions = ", ".join(f"{n} {v['version']}" for n, v in state["installed"].items())
    print(f"[+] Baseline restored: {versions}; mode={state['mode']}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
