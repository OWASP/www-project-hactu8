"""Build hactu8.result/v1 documents."""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Dict, List

from hactu8 import RESULT_SCHEMA, __version__

PHASES = {1: "baseline", 2: "attack", 3: "impact", 4: "remediation"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def new_run_id(skill_id: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{skill_id}-{secrets.token_hex(2)}"


def rate(items: List[dict], targeted_only: bool) -> Dict[str, object]:
    pool = [i for i in items if i["targeted"] or not targeted_only]
    red = sum(1 for i in pool if i["verdict"] == "RED")
    total = len(pool)
    return {"red": red, "total": total, "rate": round(red / total * 100.0, 1) if total else 0.0}


def summarize(acts: List[dict], backend: str) -> Dict[str, object]:
    def act_rate(n: int):
        for act in acts:
            if act["act"] == n and act["items"]:
                return act["metric"]["targeted"]["rate"]
        return None

    baseline, impact, remediated = act_rate(1), act_rate(3), act_rate(4)
    complete = None not in (baseline, impact, remediated)
    holds = bool(complete and baseline == 0 and impact > 0 and remediated == 0)
    asserted = backend in ("echo", "stub")
    if not complete:
        status = "error"
    elif asserted:
        status = "pass" if holds else "fail"
    else:
        status = "reported"
    return {
        "baseline_rate": baseline,
        "impact_rate": impact,
        "remediated_rate": remediated,
        "story_holds": holds,
        "asserted": asserted,
        "status": status,
    }


def envelope(skill, backend: str, model: str, classifier: str) -> Dict[str, object]:
    return {
        "schema": RESULT_SCHEMA,
        "run_id": new_run_id(skill.id),
        "hactu8_version": __version__,
        "started_at": now_iso(),
        "finished_at": None,
        "duration_ms": None,
        "skill": {
            "id": skill.id,
            "name": skill.name,
            "version": skill.version,
            "owasp": skill.owasp,
            "risk": skill.risk,
            "metric": {"id": skill.metric, "name": skill.metric_name},
        },
        "target": {"kind": skill.target, "id": skill.lab_dir.rsplit("/", 1)[-1], "port": skill.port},
        "model": {"backend": backend, "model": model},
        "classifier": {"name": classifier},
        "acts": [],
        "summary": {},
        "exit_code": None,
    }
