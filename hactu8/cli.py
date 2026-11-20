"""hactu8 command line.

    hactu8 list [--json]
    hactu8 run <skill...|all> [--tier T | --backend B [--model M]] [--classifier C] [--json]
    hactu8 results [--json]
    hactu8 show <run_id|latest>
    hactu8 router [--json]
    hactu8 bench [--json] [--misses] [--classifier-backend B [--model M]]

Without --backend, the model under test comes from the router (hactu8.yaml,
role ``target``; deterministic echo by default). --tier picks a tier instead.

Exit code: 0 when every run passes (or is reported for a real model), 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List

from hactu8 import __version__, catalog, config, store
from hactu8.adapters import lab
from hactu8.classify import get_classifier
from hactu8.router import Router, RouterError


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


def _run_routed(skill, args, router: Router, classifier) -> dict:
    """Run one skill. A routed run that cannot complete escalates to the next candidate."""
    if args.backend:
        return lab.run(skill, backend=args.backend, model=args.model, classifier=classifier, timeout=args.timeout)
    role = args.tier or "target"
    cand = router.resolve(role)
    failed: List[str] = []
    while True:
        doc = lab.run(skill, backend=cand.backend, model=args.model or cand.model,
                      classifier=classifier, timeout=args.timeout, tier=cand.tier)
        if failed:
            doc["model"]["escalated_from"] = failed
        nxt = router.fallbacks(role, cand) if doc["summary"]["status"] == "error" else []
        if not nxt:
            return doc
        failed.append(cand.label)
        if not args.json:
            print(f"  {cand.label} could not complete the run; escalating to {nxt[0].label}", flush=True)
        cand = nxt[0]


def cmd_run(args) -> int:
    ids = [s.id for s in catalog.discover()] if args.skills == ["all"] else args.skills
    failed = 0
    docs = []
    cfg = config.load()
    router = Router.from_config(cfg)
    try:
        classifier = get_classifier(args.classifier or (cfg.get("classifiers") or {}).get("default", "keyword"),
                                    cfg, router)
        label = args.backend or router.resolve(args.tier or "target").label
    except (KeyError, RuntimeError, RouterError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for skill_id in ids:
        try:
            skill = catalog.get(skill_id)
        except KeyError as exc:
            print(f"error: {exc}", file=sys.stderr)
            failed += 1
            continue
        if not args.json:
            print(f"running {skill.id} ({skill.owasp} {skill.risk}) on {label} ...", flush=True)
        doc = _run_routed(skill, args, router, classifier)
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


def cmd_router(args) -> int:
    try:
        router = Router.from_config()
    except (config.ConfigError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    rows = router.describe()
    if args.json:
        print(json.dumps({"config": str(config.find_config() or ""), "roles": router.roles,
                          "max_tier": router.max_tier, "on_error": router.on_error, "candidates": rows}, indent=2))
        return 0
    print(f"config: {config.find_config() or 'built-in defaults'}")
    print(f"roles: {', '.join(f'{k}={v}' for k, v in router.roles.items())}; "
          f"auto-escalation up to {router.max_tier}; on_error={router.on_error}\n")
    _print_table([[r["tier"] + ("" if r["auto"] else " (opt-in)"), r["backend"], r["model"] or "-",
                   "yes" if r["available"] else "no", r["reason"]] for r in rows],
                 ["TIER", "BACKEND", "MODEL", "AVAILABLE", "WHY"])
    for role in router.roles:
        try:
            print(f"\n{role}: {router.resolve(role).label}", end="")
        except RouterError as exc:
            print(f"\n{role}: none ({exc})", end="")
    print()
    return 0


def _pct(value) -> str:
    return "-" if value is None else f"{value * 100:.0f}%"


def cmd_bench(args) -> int:
    from hactu8 import bench
    classifier = bench.llm_classifier(args.classifier_backend, args.model) if args.classifier_backend else None
    result = bench.run(classifier=classifier)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return 1 if result.regressions else 0
    print(f"coverage        {_pct(result.coverage)}   (baseline {_pct(result.baseline.get('coverage'))})")
    independent = result.baseline.get("independent", {})
    before = independent["caught"] / independent["attacks"] if independent.get("attacks") else None
    print(f"generalization  {_pct(result.generalization)}   (independent held-out set; baseline {_pct(before)})")
    print(f"false positives {result.false_positives}      (baseline {result.baseline.get('false_positives', 0)})")
    print(f"scored items    {len(result.items)}; controls listed, not scored: {result.controls}")
    shown = [i for i in result.items if i.grade in ("MISS", "FALSE_POSITIVE")] if args.misses else []
    if shown:
        _print_table([[i.id, i.surface, i.grade, "held-out" if i.holdout else ""] for i in shown],
                     ["ITEM", "SURFACE", "GRADE", ""])
    for item in result.regressions:
        print(f"REGRESSION: {item.id} ({item.grade})")
    return 1 if result.regressions else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hactu8", description="OWASP HACTU8 assurance test runner")
    parser.add_argument("--version", action="version", version=f"hactu8 {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("list", help="list available skills")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("run", help="run one or more skills ('all' for every skill)")
    p.add_argument("skills", nargs="+")
    p.add_argument("--backend", default="", help="echo | ollama | llamacpp | openrouter | anthropic | openai "
                   "(default: from the router)")
    p.add_argument("--model", default="")
    p.add_argument("--tier", default="", help="router tier for the model under test: deterministic | local | cloud")
    p.add_argument("--classifier", default="", help="keyword (default) | llm-judge | jev")
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("results", help="list stored runs")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_results)

    p = sub.add_parser("show", help="print a stored result")
    p.add_argument("run_id")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("router", help="show router tiers and which models are available")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_router)

    p = sub.add_parser("bench", help="score ProtectoGW against the labelled attack corpus")
    p.add_argument("--json", action="store_true")
    p.add_argument("--misses", action="store_true", help="list misses and false positives")
    p.add_argument("--classifier-backend", default="", help="add ProtectoGW's model plane: ollama | llamacpp | "
                   "openrouter | anthropic | openai")
    p.add_argument("--model", default="")
    p.set_defaults(func=cmd_bench)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
