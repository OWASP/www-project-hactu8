#!/usr/bin/env python3
"""Merge every stored run into one SARIF 2.1.0 file, for GitHub code scanning (H-52).

    HACTU8_HOME=.hactu8 python scripts/sarif_all.py -o hactu8.sarif

Each run is rendered by hactu8.reports.sarif, then all results go into a single SARIF run
(GitHub rejects several runs from one tool in one upload). A lab finding is located at the
lab's run_demo.py, so code scanning can show it; the hactu8:// URI is kept in its properties.
Findings are the attacks each lab demonstrates on purpose: the suite's pass or fail is the
exit code of `hactu8 run`, not this file. Exits 1 when there are no stored runs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hactu8 import branding, reports, store  # noqa: E402


def merge(docs: list, brand: dict, root: Path = ROOT) -> dict:
    rules, results, runs = {}, [], []
    driver = None
    for doc in docs:
        if "acts" not in doc or "skill" not in doc:
            continue
        run = reports.sarif(doc, brand)["runs"][0]
        driver = driver or run["tool"]["driver"]
        for rule in run["tool"]["driver"]["rules"]:
            rules.setdefault(rule["id"], rule)
        for result in run["results"]:
            _locate(result, doc, root)
            results.append(result)
        runs.append({"runId": doc["run_id"], "skill": doc["skill"]["id"], "status": doc["summary"]["status"]})
    if driver is None:
        raise ValueError("no stored lab runs to report")
    tool = {**driver, "rules": [rules[key] for key in sorted(rules)]}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": tool}, "results": results, "properties": {"hactu8Runs": runs}}],
    }


def _locate(result: dict, doc: dict, root: Path) -> None:
    props = result["properties"]
    location = result["locations"][0]["physicalLocation"]
    props["hactu8Uri"] = location["artifactLocation"]["uri"]
    target = doc.get("target", {})
    runner = Path("demos") / str(target.get("id", "")) / "run_demo.py"
    if target.get("kind") == "lab" and (root / runner).is_file():
        result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": runner.as_posix()}}}]
    key = "|".join(str(v) for v in (doc["skill"]["id"], props["act"], props["phase"], props["prompt"]))
    result["partialFingerprints"] = {"hactu8/v1": hashlib.sha256(key.encode("utf-8")).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("-o", "--output", default="-", help="output file (default stdout)")
    args = parser.parse_args()
    try:
        value = merge(store.list_runs(), branding.load(ROOT / "branding.yaml"))
    except ValueError as exc:
        print(f"error: {exc} in {store.results_dir()}", file=sys.stderr)
        return 1
    text = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    if args.output == "-":
        sys.stdout.write(text)
    else:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"{len(value['runs'][0]['results'])} findings from "
              f"{len(value['runs'][0]['properties']['hactu8Runs'])} runs -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
