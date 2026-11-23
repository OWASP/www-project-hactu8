"""hactu8 command line.

    hactu8 list [--json]
    hactu8 path [--json]
    hactu8 coverage [--status S] [--json]
    hactu8 defenses [--json]
    hactu8 run <skill...|all> [--tier T | --backend B [--model M]] [--classifier C] [--json]
    hactu8 results [--json]
    hactu8 show <run_id|latest>
    hactu8 router [--json]
    hactu8 bench [--json] [--misses] [--classifier-backend B [--model M]]
    hactu8 live [--backend B] [--model M] [--json]
    hactu8 scoreboard [--json]
    hactu8 wolf [--backend B] [--model M] [--target-backend B] [--target-model M] [--rounds N] [--attempts N]
    hactu8 mcp [--http] [--port P]

Without --backend, the model under test comes from the router (hactu8.yaml,
role ``target``; deterministic echo by default). --tier picks a tier instead.

Exit code: 0 when every run passes (or is reported for a real model), 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List

from hactu8 import __version__, catalog, config, defenses, store, techniques
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


def cmd_path(args) -> int:
    track = catalog.learning_path(catalog.discover())
    if args.json:
        print(json.dumps(track, indent=2))
        return 0
    for stage in track["stages"]:
        print(f"{stage['title']}: {stage['summary']}")
        for s in stage["skills"]:
            print(f"  {s['step']:>2}. {s['id']:<6} {s['owasp']:<11} {s['risk']}"
                  f"{'' if s['has_lesson'] else '  (no lesson yet)'}")
        if not stage["skills"]:
            print("  (no labs yet)")
        print()
    if track["unassigned"]:
        print("not on the path: " + ", ".join(track["unassigned"]))
    print(f"{track['total']} labs on the path")
    return 0


def cmd_coverage(args) -> int:
    report = techniques.coverage(store.list_runs())
    rows = [r for r in report["techniques"] if not args.status or r["status"] == args.status]
    if args.json:
        print(json.dumps({**report, "techniques": rows}, indent=2))
        return 0
    _print_table([[r["id"], r["status_title"], ",".join(r["labs"]) or "-", ",".join(r["defenses"]) or "-"]
                  for r in rows], ["TECHNIQUE", "STATUS", "LABS", "DEFENSES"])
    counts = report["counts"]
    print("\n" + ", ".join(f"{counts[s]} {t.lower()}" for s, t in techniques.STATUSES.items())
          + f" ({report['total']} techniques)")
    for key, info in report["by_list"].items():
        print(f"  {info['name']} {info['edition']}: {info['with_lab']} of {info['ids']} IDs have a lab")
    leaky = [r["id"] for r in report["techniques"] if r["leaky_labs"]]
    if leaky:
        print("latest run left impact after remediation: " + ", ".join(leaky))
    return 0


def cmd_defenses(args) -> int:
    from hactu8 import bench
    report = defenses.report(catalog.discover(), store.list_runs(), bench.run().items)
    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    rows = []
    for d in report["defenses"]:
        b = d["bench"]
        shown = f"{b['caught']}/{b['attacks']} caught, {b['false_positives']}/{b['clean']} FP" if b and b["attacks"] else "-"
        rows.append([d["id"], d["kind_title"], str(len(d["techniques"])), ",".join(d["labs"]) or "-", shown])
    _print_table(rows, ["DEFENSE", "KIND", "TECHNIQUES", "LABS", "BENCH"])
    for key, title in report["evidence"].items():
        ids = [d["id"] for d in report["defenses"] if d["evidence"] == key]
        print(f"\n{title} ({len(ids)}): {', '.join(ids) or '-'}", end="")
    print()
    print(f"techniques with no defense ({len(report['gaps'])}): " + ", ".join(g["id"] for g in report["gaps"]))
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
    from hactu8 import spend
    chosen = args.backend or label.split(":", 1)[0]
    if spend.is_cloud(chosen) and not args.confirm_spend:
        print(spend.estimate(chosen, spend.lab_calls(len(ids))) + " Re-run with --confirm-spend.", file=sys.stderr)
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
    known = [i for i in result.known_misses if not i.holdout]
    print(f"known misses    {len(known)}      (recorded attacks the rules pass; counted in coverage)")
    shown = [i for i in result.items if i.grade in ("MISS", "FALSE_POSITIVE")] if args.misses else []
    if shown:
        _print_table([[i.id, i.surface, i.grade, "held-out" if i.holdout else ""] for i in shown],
                     ["ITEM", "SURFACE", "GRADE", ""])
    for item in result.regressions:
        print(f"REGRESSION: {item.id} ({item.grade})")
    for item in result.improvements:
        print(f"IMPROVEMENT: {item.id} (a recorded miss is now {item.grade}; re-record the baseline)")
    return 1 if result.regressions else 0


def cmd_live(args) -> int:
    import time

    from hactu8.result import now_iso
    from hactu8 import spend
    if spend.is_cloud(args.backend) and not args.confirm_spend:
        print(spend.estimate(args.backend, spend.LIVE_CALLS) + " Re-run with --confirm-spend.", file=sys.stderr)
        return 2
    started, clock = now_iso(), time.monotonic()
    try:
        from hactu8 import live
        result = live.run(args.backend, args.model)
    except (RuntimeError, ValueError) as exc:
        print(f"hactu8 live: {exc}", file=sys.stderr)
        return 2
    doc = live.to_result(result, started, int((time.monotonic() - clock) * 1000))
    path = store.save(doc)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return 0
    _print_table([[s.target, "attack" if s.attack else "control", s.outcome_off, s.outcome_on,
                   "suspected" if s.suspected else ""] for s in result.surfaces],
                 ["SURFACE", "KIND", "OFF", "ON", ""])
    print(f"\nmodel: {result.backend} / {result.model}")
    print(f"model resistance  {_pct(result.model_resistance)}  ({result.resisted} of {result.attacks} attacks held)")
    print(f"app exposure      {result.breaches_off} breaches with the gateway off, {result.breaches_on} with it on")
    print(f"false blocks      {result.false_blocks_on}")
    print(f"saved {path}")
    return 0


def cmd_wolf(args) -> int:
    import time

    from hactu8 import wolf_agent
    from hactu8.result import now_iso
    rounds, attempts = wolf_agent.bounds(args.rounds, args.attempts)
    notice = wolf_agent.spend_notice(args.backend, args.target_backend, rounds, attempts)
    if notice and not args.confirm_spend:
        print(notice + " Re-run with --confirm-spend.", file=sys.stderr)
        return 2

    def show(a) -> None:
        if not args.json:
            state = f"REJECTED ({a.reject_reason})" if not a.screened else f"{a.outcome_off:<7} {a.outcome_on}"
            print(f"  {a.id:<10} {a.strategy:<16} {state}", flush=True)

    started, clock = now_iso(), time.monotonic()
    try:
        result = wolf_agent.run(args.backend, args.model, target_backend=args.target_backend,
                                target_model=args.target_model, rounds=rounds, attempts=attempts, progress=show)
    except (RuntimeError, ValueError) as exc:
        print(f"hactu8 wolf: {exc}", file=sys.stderr)
        return 2
    doc = wolf_agent.to_result(result, started, int((time.monotonic() - clock) * 1000))
    path = store.save(doc)
    if args.json:
        print(json.dumps(doc, indent=2, ensure_ascii=False))
        return 0
    w = doc["wolf"]
    print(f"\nattacker {result.attacker_backend} / {result.attacker_model}; target {result.backend} / {result.model}")
    print(f"landed            {w['landed_off']} of {w['sent']} sent with the gateway off, {w['landed_on']} with it on"
          f" ({w['rejected']} rejected by the safety screen)")
    print(f"control           {result.control.outcome_off} off, {result.control.outcome_on} on")
    print(f"wolf den          {sum(c['confirmed'] for c in w['den'])} confirmed captures")
    print(f"status            {doc['summary']['status']}")
    print(f"saved {path}")
    return 0


def cmd_mcp(args) -> int:
    from hactu8.lamb._mcp import McpUnavailable
    try:
        from hactu8 import mcp_server
        mcp_server.serve(http=args.http, port=args.port)
    except McpUnavailable as exc:
        print(f"hactu8 mcp: {exc}", file=sys.stderr)
        return 2
    return 0


def cmd_scoreboard(args) -> int:
    rows = store.scoreboard()
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        from hactu8 import reports
        print(reports.scoreboard_markdown(rows), end="")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hactu8", description="OWASP HACTU8 assurance test runner")
    parser.add_argument("--version", action="version", version=f"hactu8 {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("list", help="list available skills")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("path", help="show the learning path: labs in the order to take them")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_path)

    p = sub.add_parser("coverage", help="attack techniques by coverage: attack and defense, attack only, no lab yet")
    p.add_argument("--status", choices=list(techniques.STATUSES), default="")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_coverage)

    p = sub.add_parser("defenses", help="each defense with the techniques it covers and its bench and lab evidence")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_defenses)

    p = sub.add_parser("run", help="run one or more skills ('all' for every skill)")
    p.add_argument("skills", nargs="+")
    p.add_argument("--backend", default="", help="echo | ollama | llamacpp | openai-compat | strata | basalt | "
                   "openrouter | anthropic | openai (default: from the router)")
    p.add_argument("--model", default="")
    p.add_argument("--tier", default="", help="router tier for the model under test: deterministic | local | cloud")
    p.add_argument("--classifier", default="", help="keyword (default) | llm-judge | jev")
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--confirm-spend", action="store_true", help="allow a paid cloud backend")
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
                   "openai-compat | strata | basalt | openrouter | anthropic | openai")
    p.add_argument("--model", default="")
    p.set_defaults(func=cmd_bench)

    p = sub.add_parser("live", help="attack a model with Billy's MCP surfaces, defense off vs on")
    p.add_argument("--backend", default="echo", help="echo (default, offline) | ollama | llamacpp | "
                   "openai-compat | strata | basalt | openrouter | anthropic | openai")
    p.add_argument("--model", default="")
    p.add_argument("--confirm-spend", action="store_true", help="allow a paid cloud backend")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_live)

    p = sub.add_parser("wolf", help="an attacker model writes and adapts attacks on Lamb, graded off vs on")
    p.add_argument("--backend", default="echo", help="attacker: echo (default, deterministic mutations) | ollama | "
                   "llamacpp | openai-compat | strata | basalt | openrouter | anthropic | openai")
    p.add_argument("--model", default="")
    p.add_argument("--target-backend", default="", help="model under attack (default: the attacker's backend)")
    p.add_argument("--target-model", default="")
    p.add_argument("--rounds", type=int, default=3, help="rounds, 1 to 5 (default 3)")
    p.add_argument("--attempts", type=int, default=2, help="attempts per round, 1 to 4 (default 2)")
    p.add_argument("--confirm-spend", action="store_true", help="allow a paid cloud backend")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_wolf)

    p = sub.add_parser("mcp", help="serve the runner as an MCP server (stdio; --http for 127.0.0.1)")
    p.add_argument("--http", action="store_true", help="streamable HTTP on 127.0.0.1 instead of stdio")
    p.add_argument("--port", type=int, default=8765)
    p.set_defaults(func=cmd_mcp)

    p = sub.add_parser("scoreboard", help="latest live run per model, defense off vs on")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_scoreboard)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
