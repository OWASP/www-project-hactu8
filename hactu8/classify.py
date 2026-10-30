"""Classifier interface: turn a test item into a GREEN / YELLOW / RED verdict.

Backends:
  keyword    default, offline, deterministic. In Phase 1 the lab's own keyword
             classifier scores each item; this backend records that verdict.
  llm-judge  (M2) a model from the router scores the evidence.
  jev        (M2, optional) TypeSafe Jev typed classification with confidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Type

VERDICTS = ("GREEN", "YELLOW", "RED")


@dataclass
class Verdict:
    verdict: str
    confidence: float = 1.0
    reason: str = ""


class Classifier:
    name = "base"

    def classify(self, prompt: str, evidence: str = "", lab_verdict: Optional[str] = None) -> Verdict:
        raise NotImplementedError


class KeywordClassifier(Classifier):
    """Deterministic: trusts the lab's transparent keyword verdict."""

    name = "keyword"

    def classify(self, prompt: str, evidence: str = "", lab_verdict: Optional[str] = None) -> Verdict:
        if lab_verdict not in VERDICTS:
            return Verdict("YELLOW", 0.0, "no lab verdict")
        return Verdict(lab_verdict, 1.0, "lab keyword indicators")


_REGISTRY: Dict[str, Type[Classifier]] = {"keyword": KeywordClassifier}


def get_classifier(name: str = "keyword") -> Classifier:
    try:
        return _REGISTRY[name]()
    except KeyError:
        raise KeyError(f"unknown classifier: {name} (available: {', '.join(_REGISTRY)})") from None
