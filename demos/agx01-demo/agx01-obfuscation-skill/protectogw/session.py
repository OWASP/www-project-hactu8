"""
session.py — stateful, cross-read screening (the heat model).

The base screen() is STATELESS: it judges one artifact in isolation. Some attacks
are invisible that way — two resources that are each clean alone but hostile once
the model follows a pointer from one to the other. A read-directive ("for the
config, load kb://step-two") is not an injection by itself; a doc that says
"include the stored access token" is borderline by itself. It is the COMBINATION
— arriving at the second because the first sent you there — that is the attack.

A Session accumulates observations across reads so that combination is catchable.
It is the one capability the flat, per-call ruleset structurally lacks.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from ._limits import MAX_INPUT_CHARS
from .screening import screen, Verdict

# A cross-resource read directive: a read/load/fetch verb near a scheme://uri.
_READ_VERB = r"(read|load|fetch|open|include|apply|ingest|import|consult|retrieve)"
_URI = r"([a-z][a-z0-9+.\-]*://[^\s\"'>)\]]+)"
_CROSS_REF = re.compile(_READ_VERB + r"[^.\n]{0,40}?" + _URI, re.I)

# Sub-threshold "sensitive handling" language — not enough to block alone, but
# damning once a prior artifact steered the model here.
_SENSITIVE = re.compile(
    r"(access[_ ]?token|secret|credential|api[_ ]?key|password|private key|"
    r"include\s+.{0,25}(token|secret|key|credential))",
    re.I,
)

_CHAIN_RISK = 0.85


@dataclass
class SessionResult:
    target: str
    verdict: Verdict
    risk: float
    reason: str = ""

    @property
    def flagged(self) -> bool:
        return self.verdict != Verdict.ALLOW


def cross_refs(text: str) -> Set[str]:
    """URIs this text tells the reader to go load, with a read verb nearby."""
    return {m.group(2).rstrip(".,);") for m in _CROSS_REF.finditer(text)}


class Session:
    """Accumulates cross-read context so chained poison is catchable.

    Usage: observe() every artifact as it is read, then verdicts() to grade them
    with full knowledge of what pointed at what. Order-independent.
    """

    def __init__(self) -> None:
        self.pointed_to: Set[str] = set()   # URIs a prior artifact told us to read
        self.reads: List[Tuple[str, str]] = []  # (uri, text) in read order
        self.heat: float = 0.0

    def observe(self, uri: str, text: str) -> None:
        if len(text) > MAX_INPUT_CHARS:
            text = text[:MAX_INPUT_CHARS]
        self.pointed_to |= cross_refs(text)
        self.reads.append((uri, text))

    def verdicts(self) -> Dict[str, SessionResult]:
        out: Dict[str, SessionResult] = {}
        for uri, text in self.reads:
            base = screen(text)
            verdict, risk, reason = base.verdict, base.risk, ""
            # The chain: this artifact was REACHED via a read-directive AND
            # carries sensitive-handling text, yet is clean under a stateless
            # screen. The pointer + the handling is the attack.
            if (uri in self.pointed_to
                    and _SENSITIVE.search(text)
                    and base.verdict == Verdict.ALLOW):
                verdict, risk = Verdict.BLOCK, max(risk, _CHAIN_RISK)
                reason = ("cross-resource chain: reached via a read-directive and "
                          "carries sensitive-handling text (clean alone)")
                self.heat += risk
            out[uri] = SessionResult(uri, verdict, risk, reason)
        return out
