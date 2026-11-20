"""ProtectoGW bench: score screen() against a labelled corpus of MCP attack surfaces.

The corpus (corpus.json) was ported from AgenticGoat's 17-act detector run. Each
item is untrusted text headed for a model's context, labelled attack or clean.
Two axes are scored separately, so a held-out miss never reads as a regression:

    coverage        attacks caught, excluding the held-out set (must stay 100%)
    generalization  held-out attacks caught (the honest probe of unseen phrasing)

False positives (clean items flagged) are reported beside both. Items of kind
``control`` are enforced by gateway and lab controls rather than screen(); they
are listed, not scored.

    python -m hactu8 bench [--json] [--misses]
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from hactu8.protectogw import Policy, Rule, Verdict, screen
from hactu8.protectogw.session import Session

CORPUS = Path(__file__).with_name("corpus.json")

# Output headed for a shell, SQL or HTML sink: metacharacter rules the default
# prompt-injection ruleset deliberately does not carry (AgenticGoat Act 13).
SINK_RULES = (
    Rule("sql_sink",
         r"(\bunion\s+(all\s+)?select\b|;\s*drop\s+table\b|;\s*delete\s+from\b|"
         r";\s*insert\s+into\b|;\s*update\s+\w|;\s*--|/\*[\s\S]{0,40}\*/|\bxp_cmdshell\b)",
         0.85, Verdict.BLOCK),
    Rule("shell_sink",
         r"(;\s*rm\s+-rf\b|&&\s*(rm|curl|wget)\b|\|\s*(bash|sh)\b|"
         r"(curl|wget)\s+\S+\s*\|\s*(ba)?sh\b|>\s*/dev/|/etc/cron)",
         0.85, Verdict.BLOCK),
    Rule("html_sink",
         r"(<\s*script\b|<\s*iframe\b|onerror\s*=|onload\s*=|javascript:|"
         r"<\s*img\b[^>]{0,200}src\s*=\s*[\"']?\s*https?://)",
         0.85, Verdict.BLOCK),
    Rule("markdown_image_exfil",
         r"!\[[^\]]{0,120}\]\(\s*https?://[^)]{0,200}[?&][^)=]{0,60}=",
         0.85, Verdict.BLOCK),
)

# The output-side screening policy. It ADDS the sink rules to the built-in set,
# so a return that also carries a prompt-injection instruction still blocks on
# the base ruleset too — this plane widens coverage, it doesn't replace it.
SINK_POLICY = Policy(extra_rules=SINK_RULES)


@dataclass
class ItemResult:
    id: str
    surface: str
    attack: bool
    holdout: bool
    flagged: bool
    baseline_flagged: bool

    @property
    def grade(self) -> str:
        if self.attack:
            return "CAUGHT" if self.flagged else "MISS"
        return "FALSE_POSITIVE" if self.flagged else "CLEAN"


@dataclass
class BenchResult:
    items: List[ItemResult] = field(default_factory=list)
    controls: int = 0
    baseline: Dict[str, float] = field(default_factory=dict)

    def _rate(self, holdout: bool) -> Optional[float]:
        attacks = [i for i in self.items if i.attack and i.holdout == holdout]
        return sum(i.flagged for i in attacks) / len(attacks) if attacks else None

    @property
    def coverage(self) -> Optional[float]:
        return self._rate(holdout=False)

    @property
    def generalization(self) -> Optional[float]:
        return self._rate(holdout=True)

    @property
    def false_positives(self) -> int:
        return sum(1 for i in self.items if not i.attack and i.flagged)

    @property
    def regressions(self) -> List[ItemResult]:
        """Items that score worse than the recorded baseline."""
        return [i for i in self.items
                if (i.attack and i.baseline_flagged and not i.flagged)
                or (not i.attack and i.flagged and not i.baseline_flagged)]

    def to_dict(self) -> dict:
        return {
            "coverage": self.coverage, "generalization": self.generalization,
            "false_positives": self.false_positives, "controls_not_scored": self.controls,
            "baseline": self.baseline,
            "regressions": [i.id for i in self.regressions],
            "items": [dict(i.__dict__, grade=i.grade) for i in self.items],
        }


def load(path: Path = CORPUS) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _flagged(item: dict) -> bool:
    if item["kind"] == "screen":
        policy = SINK_POLICY if item.get("policy") == "sink" else None
        return screen(item["text"], policy=policy).verdict != Verdict.ALLOW
    return any(screen(text).verdict != Verdict.ALLOW for text in item["texts"])


def run(corpus: Optional[dict] = None) -> BenchResult:
    corpus = corpus or load()
    session = Session()
    for read in corpus.get("session_reads", []):
        session.observe(read["uri"], read["text"])
    session_verdicts = session.verdicts()

    result = BenchResult(baseline=corpus.get("baseline", {}))
    for item in corpus["items"]:
        if item["kind"] == "control":
            result.controls += 1
            continue
        if item["kind"] == "session":
            flagged = session_verdicts[item["uri"]].flagged
        else:
            flagged = _flagged(item)
        result.items.append(ItemResult(item["id"], item["surface"], item["attack"], item["holdout"],
                                       flagged, item["baseline_flagged"]))
    return result
