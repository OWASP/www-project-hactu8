"""Result storage: one JSON file per run under $HACTU8_HOME/results (default ./.hactu8)."""

from __future__ import annotations

import datetime
import json
import logging
import os
from pathlib import Path
from typing import List, Optional

from hactu8 import providers

log = logging.getLogger(__name__)


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
    """Every saved run, oldest first. A file that is not a run (no string run_id) is skipped with a warning."""
    docs = []
    for path in sorted(results_dir().glob("*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            log.warning("skipping unreadable result file %s: %s", path.name, exc)
            continue
        if not isinstance(doc, dict) or not isinstance(doc.get("run_id"), str) or not doc["run_id"]:
            log.warning("skipping %s: not a HACTU8 result (no run_id)", path.name)
            continue
        docs.append(doc)
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


def audit(endpoint: str, *, client: str, backend: str, model: str, confirm_spend: bool, outcome: str,
          status: Optional[int] = None, run_id: Optional[str] = None, **extra) -> None:
    """Append one JSON line to $HACTU8_HOME/audit.log for a request that could spend.

    Only these fields are written (never a key, token or header), and the line is redacted as well."""
    entry = {"time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
             "client": client, "endpoint": endpoint, "backend": backend, "model": model,
             "confirm_spend": bool(confirm_spend), "outcome": outcome, "status": status, "run_id": run_id, **extra}
    line = providers.redact(json.dumps(entry, ensure_ascii=True))
    try:
        path = home()
        path.mkdir(parents=True, exist_ok=True)
        with open(path / "audit.log", "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError as exc:
        log.warning("could not write the audit log: %s", exc)
