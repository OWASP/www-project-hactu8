"""Result storage: one JSON file per run under $HACTU8_HOME/results (default ./.hactu8)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List, Optional


def home() -> Path:
    return Path(os.environ.get("HACTU8_HOME", ".hactu8")).resolve()


def results_dir() -> Path:
    path = home() / "results"
    path.mkdir(parents=True, exist_ok=True)
    return path


def save(doc: dict) -> Path:
    path = results_dir() / f"{doc['run_id']}.json"
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
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
