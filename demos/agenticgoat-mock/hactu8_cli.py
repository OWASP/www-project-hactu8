#!/usr/bin/env python3
"""hactu8_cli.py — minimal CLI standing in for a HACTU8 tool driving an
AgenticGoat-style target through its scenario/reset/attempt/evidence API.

This is illustrative only: it demonstrates the tool/skill-invocation loop
(discover -> reset -> attempt -> collect evidence) from a terminal, against
the mock server in server.py.

Usage:
    python3 hactu8_cli.py list
    python3 hactu8_cli.py hints <scenario-id>
    python3 hactu8_cli.py reset <scenario-id>
    python3 hactu8_cli.py attack <scenario-id> --profile vulnerable --payload "..." [--run <run_id>]
    python3 hactu8_cli.py evidence <scenario-id> --run <run_id>
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

DEFAULT_BASE_URL = "http://localhost:8080"


def _request(method: str, url: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        print(f"error: could not reach {url} ({exc.reason}). Is server.py running?", file=sys.stderr)
        raise SystemExit(1)


def cmd_list(args: argparse.Namespace) -> None:
    result = _request("GET", f"{args.base_url}/api/scenarios")
    for s in result.get("scenarios", []):
        print(f"{s['id']:<32} {s['owasp']:<40} {s['title']}")


def cmd_hints(args: argparse.Namespace) -> None:
    result = _request("GET", f"{args.base_url}/api/scenarios")
    scenario = next((s for s in result.get("scenarios", []) if s["id"] == args.scenario_id), None)
    if scenario is None:
        print(f"error: unknown scenario '{args.scenario_id}'", file=sys.stderr)
        raise SystemExit(1)
    print(f"{scenario['owasp']} — {scenario['title']}")
    print(f"Objective: {scenario['objective']}\n")
    for i, hint in enumerate(scenario["hints"], start=1):
        print(f"Hint {i}: {hint}")


def cmd_reset(args: argparse.Namespace) -> None:
    result = _request("POST", f"{args.base_url}/api/scenarios/{args.scenario_id}/reset")
    print(json.dumps(result, indent=2))


def cmd_attack(args: argparse.Namespace) -> None:
    body = {"profile": args.profile, "payload": args.payload}
    if args.run:
        body["run_id"] = args.run
    result = _request("POST", f"{args.base_url}/api/scenarios/{args.scenario_id}/attempt", body)
    print(json.dumps(result, indent=2))


def cmd_evidence(args: argparse.Namespace) -> None:
    result = _request(
        "GET", f"{args.base_url}/api/scenarios/{args.scenario_id}/evidence?run_id={args.run}"
    )
    print(json.dumps(result, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Minimal HACTU8-style CLI for the AgenticGoat mock demo.")
    parser.add_argument("--base-url", dest="base_url", default=DEFAULT_BASE_URL)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List available scenarios").set_defaults(func=cmd_list)

    p_hints = sub.add_parser("hints", help="Show the objective and hints for a scenario")
    p_hints.add_argument("scenario_id")
    p_hints.set_defaults(func=cmd_hints)

    p_reset = sub.add_parser("reset", help="Deterministically reset a scenario, get a new run_id")
    p_reset.add_argument("scenario_id")
    p_reset.set_defaults(func=cmd_reset)

    p_attack = sub.add_parser("attack", help="Send an attempt against a scenario")
    p_attack.add_argument("scenario_id")
    p_attack.add_argument("--profile", choices=["vulnerable", "hardened"], default="vulnerable")
    p_attack.add_argument("--payload", required=True)
    p_attack.add_argument("--run", default=None, help="Reuse an existing run_id (default: auto-reset)")
    p_attack.set_defaults(func=cmd_attack)

    p_evidence = sub.add_parser("evidence", help="Fetch the evidence trace for a run")
    p_evidence.add_argument("scenario_id")
    p_evidence.add_argument("--run", required=True)
    p_evidence.set_defaults(func=cmd_evidence)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
