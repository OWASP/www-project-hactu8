#!/usr/bin/env python3
"""Write a sweep's evidence page from a folder of hactu8.result/v1 documents.

    python scripts/sweep_report.py <results-home> <backend> <model> [--bench FILE] > docs/evidence/<name>.md

Lab runs and live runs for the given backend and model are tabulated with full
provenance: model digest, quantization and size (from Ollama when it is the
backend), host, Python and HACTU8 versions, and how many samples each number
rests on. Nothing here is asserted: real models are stochastic and their
numbers are reported, not tested.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hactu8 import __version__  # noqa: E402
from hactu8.protectogw import __version__ as protectogw_version  # noqa: E402


def ollama_provenance(model: str) -> dict:
    try:
        req = urllib.request.Request("http://localhost:11434/api/show", data=json.dumps({"model": model}).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            show = json.loads(resp.read())
        with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=5) as resp:
            tags = {m["name"]: m for m in json.loads(resp.read()).get("models", [])}
    except Exception as exc:  # noqa: BLE001 - provenance is best effort
        return {"error": type(exc).__name__}
    details = show.get("details", {})
    return {"digest": tags.get(model, {}).get("digest", "")[:12], "parameter_size": details.get("parameter_size", ""),
            "quantization": details.get("quantization_level", ""), "family": details.get("family", "")}


def load(home: Path, backend: str, model: str):
    labs, live = [], []
    for path in sorted((home / "results").glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if doc["model"]["backend"] != backend or doc["model"].get("model", "") not in (model, ""):
            continue
        (live if "live" in doc else labs).append(doc)
    return labs, live


def rate(value) -> str:
    return "-" if value is None else f"{value:g}%"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("home", type=Path)
    parser.add_argument("backend")
    parser.add_argument("model")
    parser.add_argument("--bench", type=Path, help="JSON from `hactu8 bench --json` with this model as classifier")
    parser.add_argument("--date", default="")
    args = parser.parse_args(argv)
    labs, live = load(args.home, args.backend, args.model)
    date = args.date or (labs or live or [{"started_at": "unknown"}])[0]["started_at"][:10]
    out = [f"# Sweep: {args.backend} {args.model}, {date}", "",
           "Real models are stochastic. These numbers are reported, not asserted; each rests on the number of "
           "samples shown.", "", "## Provenance", "",
           f"- Backend and model: `{args.backend}` / `{args.model}`"]
    if args.backend == "ollama":
        prov = ollama_provenance(args.model)
        out.append("- Ollama: " + ", ".join(f"{k} `{v}`" for k, v in prov.items() if v))
    out += [f"- Host: {platform.system()} {platform.release()} {platform.machine()}, Python {platform.python_version()}",
            f"- HACTU8 {__version__}, ProtectoGW {protectogw_version}", ""]

    if live:
        res = [d["live"]["model_resistance"] for d in live]
        off = [d["live"]["breaches_off"] for d in live]
        on = [d["live"]["breaches_on"] for d in live]
        fb = [d["live"]["false_blocks_on"] for d in live]
        out += ["## Live: Billy's MCP surfaces, defense off vs on", "",
                f"{len(live)} samples of {live[0]['live']['attacks']} attacks and {live[0]['live']['controls']} "
                "controls each, graded by the per-run canary.", "",
                "| Sample | Model resistance | Breaches off | Breaches on | False blocks |",
                "| ---: | ---: | ---: | ---: | ---: |"]
        for i, d in enumerate(live, 1):
            lv = d["live"]
            out.append(f"| {i} | {lv['model_resistance'] * 100:.0f}% | {lv['breaches_off']} | {lv['breaches_on']} | "
                       f"{lv['false_blocks_on']} |")
        out += ["", f"Range across samples: resistance {min(res) * 100:.0f}% to {max(res) * 100:.0f}%, breaches "
                f"off {min(off)} to {max(off)}, breaches on {min(on)} to {max(on)}, false blocks {min(fb)} to "
                f"{max(fb)}.", ""]
        leaked = {}
        for d in live:
            for item in d["acts"][3]["items"]:
                if item.get("outcome_off") == "BREACH":
                    leaked.setdefault(item["id"], []).append(item.get("outcome_on"))
        if leaked:
            out += ["Surfaces that leaked with no defense, and what the gateway did:", "",
                    "| Surface | Times leaked | Outcome with the gateway |", "| --- | ---: | --- |"]
            for target, outcomes in sorted(leaked.items()):
                out.append(f"| `{target}` | {len(outcomes)} | {', '.join(sorted(set(outcomes)))} |")
            out.append("")

    if labs:
        out += ["## Labs: four acts", "",
                "Baseline, impact (attack, no defense) and remediated (hardened) targeted RED rates, one sample "
                "per lab.", "",
                "| Skill | Baseline | Impact | Remediated | Status |", "| --- | ---: | ---: | ---: | --- |"]
        for d in sorted(labs, key=lambda x: x["skill"]["id"]):
            s = d["summary"]
            out.append(f"| {d['skill']['owasp']} {d['skill']['risk']} | {rate(s['baseline_rate'])} | "
                       f"{rate(s['impact_rate'])} | {rate(s['remediated_rate'])} | {s['status']} |")
        held = sum(1 for d in labs if (d["summary"]["impact_rate"] or 0) == 0)
        fixed = sum(1 for d in labs if (d["summary"]["remediated_rate"] or 0) == 0)
        out += ["", f"The model fell for the attack in {len(labs) - held} of {len(labs)} labs; the hardened mode "
                f"brought {fixed} of {len(labs)} to 0%.", ""]

    if args.bench and args.bench.is_file():
        bench = json.loads(args.bench.read_text(encoding="utf-8"))
        out += ["## ProtectoGW bench with this model as the classifier plane", "",
                f"- Coverage: {bench['coverage'] * 100:.0f}%",
                f"- Generalization (independent held-out set): {bench['generalization'] * 100:.0f}%",
                f"- False positives: {bench['false_positives']}", ""]
    print("\n".join(out).rstrip() + "\n", end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
