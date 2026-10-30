"""hactu8 command line.

    hactu8 list [--json]
    hactu8 run <skill...|all> [--backend echo] [--model M] [--classifier keyword] [--json]
    hactu8 results [--json]
    hactu8 show <run_id|latest>

Exit code: 0 when every run passes (or is reported for a real model), 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List

from hactu8 import __version__, catalog, store
from hactu8.adapters import lab


def _print_table(rows: List[List[str]], headers: List[str]) -> None:
    widths = [max(len(str(r[i])) for r in [headers] + rows) for i in range(len(headers))]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * w for w in widths]))
    for row in rows:
        print(fmt.format(*row))


def _fmt_rate(value) -> str:
    return "-" if value is None else f"{value:g}%"


def cmd_list(args) -> int:
    skills = catalog.discover()
    if args.json:
        print(json.dumps([s.to_dict() for s in skills], indent=2))
        return 0
    _print_table([[s.id, s.owasp, s.risk, s.metric] for s in skills], ["ID", "OWASP", "RISK", "METRIC"])
    print(f"\n{len(skills)} skills")
    return 0


def cmd_run(args) -> int:
    ids = [s.id for s in catalog.discover()] if args.skills == ["all"] else args.skills
    failed = 0
    docs = []
    for skill_id in ids:
        try:
            skill = catalog.get(skill_id)
        except KeyError as exc:
            print(f"error: {exc}", file=sys.stderr)
            failed += 1
            continue
        if not args.json:
            print(f"running {skill.id} ({skill.owasp} {skill.risk}) on {args.backend}{' ' + args.model if args.model else ''} ...", flush=True)
        doc = lab.run(skill, backend=args.backend, model=args.model, classifier=args.classifier, timeout=args.timeout)
        path = store.save(doc)
        docs.append(doc)
        s = doc["summary"]
        failed += s["status"] not in ("pass", "reported")
        if not args.json:
            metric = doc["skill"]["metric"]["id"] or "rate"
            print(f"  {s['status'].upper():<8} {metric} {_fmt_rate(s['baseline_rate'])} -> "
                  f"{_fmt_rate(s['impact_rate'])} -> {_fmt_rate(s['remediated_rate'])}  ({doc['duration_ms']} ms)")
            print(f"  saved {path}")
    if args.json:
        print(json.dumps(docs if len(docs) != 1 else docs[0], indent=2, ensure_ascii=False))
    elif len(ids) > 1:
        print(f"\n{len(ids) - failed}/{len(ids)} passed")
    return 1 if failed else 0


def cmd_results(args) -> int:
    runs = store.list_runs()
    if args.json:
        print(json.dumps([{k: d[k] for k in ("run_id", "skill", "model", "summary")} for d in runs], indent=2))
        return 0
    rows = []
    for d in runs:
        s = d["summary"]
        rows.append([d["run_id"], d["skill"]["owasp"], d["model"]["backend"], s["status"],
                     f"{_fmt_rate(s['baseline_rate'])} / {_fmt_rate(s['impact_rate'])} / {_fmt_rate(s['remediated_rate'])}"])
    if rows:
        _print_table(rows, ["RUN", "OWASP", "BACKEND", "STATUS", "BASELINE / IMPACT / REMEDIATED"])
    print(f"\n{len(rows)} runs in {store.results_dir()}")
    return 0


def cmd_show(args) -> int:
    doc = store.load(args.run_id)
    if not doc:
        print(f"error: no run {args.run_id}", file=sys.stderr)
        return 1
    print(json.dumps(doc, indent=2, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hactu8", description="OWASP HACTU8 assurance test runner")
    parser.add_argument("--version", action="version", version=f"hactu8 {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("list", help="list available skills")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("run", help="run one or more skills ('all' for every skill)")
    p.add_argument("skills", nargs="+")
    p.add_argument("--backend", default="echo", help="echo (default) | ollama | llamacpp | openrouter")
    p.add_argument("--model", default="")
    p.add_argument("--classifier", default="keyword")
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("results", help="list stored runs")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_results)

    p = sub.add_parser("show", help="print a stored result")
    p.add_argument("run_id")
    p.set_defaults(func=cmd_show)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
