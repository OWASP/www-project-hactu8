"""The HACTU8 MCP server (H-54): the runner as MCP tools, on the official mcp v2 SDK.

    python -m hactu8 mcp            stdio (for Claude Code, Claude Desktop, any MCP client)
    python -m hactu8 mcp --http     streamable HTTP on http://127.0.0.1:8765/mcp, loopback only

Read-only tools: list_skills, learning_path, get_lesson, list_results,
show_result. Running tools (each stores a hactu8.result/v1 document): run_skill,
run_live, run_wolf. Every run defaults to the deterministic echo backend; a paid
cloud backend is refused unless the call passes ``confirm_spend: true``, the same
guard as the CLI's --confirm-spend.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Optional

from hactu8 import catalog, lessons, providers, spend, store

DEFAULT_PORT = 8765
HOST = "127.0.0.1"
INSTRUCTIONS = (
    "OWASP HACTU8 runs repeatable security assurance labs against loopback-only targets. Runs default to the "
    "deterministic echo backend. Paid cloud backends (openrouter, anthropic, openai) need confirm_spend=true; "
    "ask the user before setting it.")


def _summary(doc: dict) -> dict[str, Any]:
    out = {k: doc[k] for k in ("run_id", "skill", "model", "summary") if k in doc}
    for key in ("live", "wolf"):
        if key in doc:
            out[key] = {k: v for k, v in doc[key].items() if k not in ("attempts", "den", "control")}
    return out


def _backend(name: str) -> str:
    backend = providers.normalize(name or "echo")
    if backend not in providers.BACKENDS:
        raise ValueError(f"unknown backend {name!r}; one of {', '.join(providers.BACKENDS)}")
    return backend


def build_server(root=None):
    """The MCP server object. ``root`` is the repo root holding demos/ (default: catalog.find_root())."""
    from hactu8.lamb._mcp import server_class, tool_error_class

    from mcp.types import ToolAnnotations

    tool_error = tool_error_class()
    root = root or catalog.find_root()
    mcp = server_class()("HACTU8", version="0.1.0", instructions=INSTRUCTIONS)
    read_only = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=False)
    runs = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False,
                           open_world_hint=True)

    def guard(notice: str, confirm_spend: bool) -> None:
        if notice and not confirm_spend:
            raise tool_error(notice + " Call again with confirm_spend=true only if the user agrees.")

    def checked(fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except (KeyError, ValueError, RuntimeError) as exc:
            raise tool_error(str(exc).strip("'\"")) from exc

    @mcp.tool(description="List the HACTU8 skills (labs): id, OWASP id, risk, metric.", annotations=read_only)
    def list_skills() -> dict[str, Any]:
        skills = [s.to_dict() for s in catalog.discover(root)]
        return {"skills": skills, "total": len(skills)}

    @mcp.tool(description="The learning path: stages and labs in the order to take them.", annotations=read_only)
    def learning_path() -> dict[str, Any]:
        return catalog.learning_path(catalog.discover(root))

    @mcp.tool(description="Get a skill's lesson (LESSON.md): title, sections and review questions.",
              annotations=read_only)
    def get_lesson(skill_id: str) -> dict[str, Any]:
        skill = checked(catalog.get, skill_id, root)
        try:
            value = lessons.load(skill.skill_dir)
        except lessons.LessonError as exc:
            raise tool_error(f"malformed lesson for {skill.id}: {exc}") from exc
        if value is None:
            raise tool_error(f"no lesson yet for {skill.id}")
        return {"skill_id": skill.id, "owasp": skill.owasp, "risk": skill.risk, **value.to_dict()}

    @mcp.tool(description="List stored runs, newest first: run id, skill, model and summary.", annotations=read_only)
    def list_results(limit: int = 20) -> dict[str, Any]:
        runs = list(reversed(store.list_runs()))
        return {"results": [_summary(d) for d in runs[:max(1, min(limit, 200))]], "total": len(runs)}

    @mcp.tool(description="Show one stored result (hactu8.result/v1) by run id, id prefix, or 'latest'.",
              annotations=read_only)
    def show_result(run_id: str) -> dict[str, Any]:
        doc = store.load(run_id)
        if doc is None:
            raise tool_error(f"no run {run_id!r}")
        return doc

    @mcp.tool(description="Run one skill (baseline, attack, impact, remediation) and store the result. "
                          "backend: echo (default, deterministic) | ollama | llamacpp | openai-compat | strata | basalt | "
                          "openrouter | anthropic | openai. Cloud backends need confirm_spend=true.",
              annotations=runs)
    async def run_skill(skill_id: str, backend: str = "echo", model: str = "", classifier: str = "keyword",
                        confirm_spend: bool = False) -> dict[str, Any]:
        from hactu8.adapters import lab
        name = checked(_backend, backend)
        skill = checked(catalog.get, skill_id, root)
        guard(spend.estimate(name, spend.lab_calls(1)) if spend.is_cloud(name) else "", confirm_spend)

        def work() -> dict[str, Any]:
            from hactu8 import config
            from hactu8.classify import get_classifier
            from hactu8.router import Router
            cfg = config.load(root / "hactu8.yaml")
            judge = checked(get_classifier, classifier, cfg, Router.from_config(cfg))
            return lab.run(skill, backend=name, model=model, classifier=judge)

        doc = await asyncio.to_thread(work)
        store.save(doc)
        return _summary(doc)

    @mcp.tool(description="Attack a model with Lamb's MCP surfaces, graded with the gateway off and on. "
                          "Cloud backends need confirm_spend=true.", annotations=runs)
    async def run_live(backend: str = "echo", model: str = "", confirm_spend: bool = False) -> dict[str, Any]:
        from hactu8 import live
        from hactu8.result import now_iso
        name = checked(_backend, backend)
        guard(spend.estimate(name, spend.LIVE_CALLS) if spend.is_cloud(name) else "", confirm_spend)
        started, clock = now_iso(), time.monotonic()
        run = await asyncio.to_thread(checked, live.run, name, model)
        doc = live.to_result(run, started, int((time.monotonic() - clock) * 1000))
        store.save(doc)
        return _summary(doc)

    @mcp.tool(description="The Wolf: an attacker model writes benign-effect attacks on Lamb, screened and graded "
                          "with the gateway off and on. backend/model write the attacks; target_backend/"
                          "target_model default to the same. rounds 1-5, attempts 1-4. Cloud backends need "
                          "confirm_spend=true.", annotations=runs)
    async def run_wolf(backend: str = "echo", model: str = "", target_backend: str = "", target_model: str = "",
                       rounds: int = 3, attempts: int = 2, confirm_spend: bool = False) -> dict[str, Any]:
        from hactu8 import wolf_agent
        from hactu8.result import now_iso
        name = checked(_backend, backend)
        target = checked(_backend, target_backend) if target_backend else ""
        rounds, attempts = wolf_agent.bounds(rounds, attempts)
        guard(wolf_agent.spend_notice(name, target, rounds, attempts), confirm_spend)
        started, clock = now_iso(), time.monotonic()
        run = await asyncio.to_thread(checked, wolf_agent.run, name, model, target_backend=target,
                                      target_model=target_model, rounds=rounds, attempts=attempts)
        doc = wolf_agent.to_result(run, started, int((time.monotonic() - clock) * 1000))
        store.save(doc)
        out = _summary(doc)
        out["wolf"]["attempts"] = [{k: a[k] for k in ("id", "strategy", "screened", "reject_reason",
                                                       "outcome_off", "outcome_on")} for a in doc["wolf"]["attempts"]]
        return out

    return mcp


def serve(http: bool = False, port: int = DEFAULT_PORT, root: Optional[Any] = None) -> None:
    mcp = build_server(root)
    if http:
        mcp.run("streamable-http", host=HOST, port=port)
    else:
        mcp.run("stdio")


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(prog="hactu8-mcp", description="HACTU8 runner as an MCP server")
    parser.add_argument("--http", action="store_true", help="streamable HTTP on 127.0.0.1 instead of stdio")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    serve(http=args.http, port=args.port)


if __name__ == "__main__":
    main()
