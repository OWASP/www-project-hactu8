#!/usr/bin/env python3
"""OWASP LLM05 — Data & Model Poisoning: end-to-end demonstration.

Thin launcher so the demo runs straight from a checkout without installing.
The orchestration lives in ``llm05_demo.cli``.

Usage:
    python run_demo.py                        # local backend, zero setup
    LLM05_BACKEND=openai python run_demo.py   # real OpenAI (needs OPENAI_API_KEY)
"""

from __future__ import annotations

import os
import sys

# Allow running straight from a checkout without installing the package.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from llm05_demo.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
