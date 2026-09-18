#!/usr/bin/env python3
"""Remove generated poisoning artifacts and prepare Skill B for a clean run."""

from __future__ import annotations

import glob
import os


HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(HERE)
KNOWLEDGE_BASE_DIR = os.path.join(SKILL_DIR, "knowledge_base")
POISON_GLOB = os.path.join(KNOWLEDGE_BASE_DIR, "policy_update_v*.txt")


def main() -> int:
    removed = 0
    for path in glob.glob(POISON_GLOB):
        os.remove(path)
        removed += 1

    print(f"Removed {removed} generated poisoning document(s).")
    print("Restart vulnerable_app.py to reset the in-memory prompt template.")
    print("Then run: python scripts/evaluate_kpi.py --target http://127.0.0.1:5101")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())