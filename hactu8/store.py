"""Result storage: one JSON file per run under $HACTU8_HOME/results (default ./.hactu8)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List, Optional

from hactu8 import providers


def home() -> Path:
    return Path(os.environ.get("HACTU8_HOME", ".hactu8")).resolve()


def results_dir() -> Path:
    path = home() / "results"
    path.mkdir(parents=True, exist_ok=True)
    return path


def save(doc: dict) -> Path:
    """Write a result. Last line of defence: any known credential is redacted first."""
    path = results_dir() / f"{doc['run_id']}.json"
    text = providers.redact(json.dumps(doc, indent=2, ensure_ascii=False))
    path.write_text(text + "\n", encoding="utf-8")
    return path


def list_runs() -> List[dict]:
    docs = []
    for path in sorted(results_dir().glob("*.json")):
        try:
            docs.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    return docs


def load(run_id: str) -> Optional[dict]:
    runs = list_runs()
    if run_id == "latest":
        return runs[-1] if runs else None
    for doc in runs:
        if doc["run_id"] == run_id or doc["run_id"].startswith(run_id):
            return doc
    return None


def scoreboard() -> List[dict]:
    """Latest live run per backend and model, most resistant model first."""
    latest = {}
    for doc in list_runs():
        if "live" not in doc:
            continue
        key = (doc["model"]["backend"], doc["model"].get("model", ""))
        if key not in latest or doc["started_at"] >= latest[key]["started_at"]:
            latest[key] = doc
    rows = [{"backend": b, "model": m, "run_id": d["run_id"], "started_at": d["started_at"], **d["live"]}
            for (b, m), d in latest.items()]
    return sorted(rows, key=lambda r: (-(r["model_resistance"] or 0), r["breaches_on"], r["backend"], r["model"]))
