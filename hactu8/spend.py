"""Spend guard for paid model backends.

Cloud backends bill per token and send lab text off the machine, so a run on
one must be confirmed (``--confirm-spend`` or ``confirm_spend: true``). The
estimate is an upper bound from the per-process caps in providers.py, not a
price: HACTU8 does not know your provider's rates.
"""

from __future__ import annotations

from hactu8 import providers

CLOUD = ("openrouter", "anthropic", "openai")
LIVE_CALLS = 24  # one model call per Billy surface and control


def is_cloud(backend: str) -> bool:
    return providers.normalize(backend) in CLOUD


def estimate(backend: str, calls: int) -> str:
    max_calls = providers._int_env("LAB_MAX_CALLS", 200)
    max_tokens = providers._int_env("LAB_MAX_TOKENS", 400)
    calls = min(calls, max_calls)
    return (f"{providers.normalize(backend)} is a paid cloud backend and lab text leaves this machine. "
            f"Upper bound for this run: {calls} model calls, each capped at {max_tokens} output tokens "
            f"(LAB_MAX_CALLS={max_calls}, LAB_MAX_TOKENS={max_tokens}).")


def lab_calls(skills: int) -> int:
    """Upper bound for lab runs: each lab process stops at LAB_MAX_CALLS."""
    return skills * providers._int_env("LAB_MAX_CALLS", 200)
