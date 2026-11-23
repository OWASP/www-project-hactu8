"""FastAPI service for HACTU8 skills, lessons, the learning path, protections, runs, results, targets,
branding, and reports.

Set HACTU8_CONSOLE_DIR to a built console (Vite ``dist/``) to serve it at ``/`` from the same origin,
as the Docker image does.

Every request must name a loopback Host (127.0.0.1, localhost or [::1]) with the API's port
(HACTU8_API_PORT, default 8000; also HACTU8_PORT, the host port Docker publishes it on); anything
else gets 421. That stops DNS rebinding: a page on attacker.example re-pointed at 127.0.0.1 still
sends ``Host: attacker.example``."""

import os
from pathlib import Path
from typing import Optional

from hactu8 import (branding, catalog, config, defenses, lessons, protections, providers, reports, spend, store,
                    techniques)
from hactu8.adapters import lab
from hactu8.classify import get_classifier
from hactu8.router import Router, RouterError


LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]")


def allowed_hosts() -> set:
    """Host header values the API answers: loopback names with its configured port(s)."""
    ports = {os.environ.get("HACTU8_API_PORT", "8000").strip() or "8000"}
    if os.environ.get("HACTU8_PORT", "").strip():
        ports.add(os.environ["HACTU8_PORT"].strip())
    return {f"{host}:{port}" for host in LOOPBACK_HOSTS for port in ports}


def create_app(root: Optional[Path] = None, hosts: Optional[set] = None):
    try:
        from fastapi import FastAPI, HTTPException, Request
        from fastapi.middleware.cors import CORSMiddleware
        from fastapi.responses import JSONResponse, PlainTextResponse
        from pydantic import BaseModel
    except ModuleNotFoundError as exc:
        raise RuntimeError("API needs the optional dependency: pip install 'hactu8[api]'") from exc

    root = root or catalog.find_root()

    class RunRequest(BaseModel):
        skill_id: str
        backend: str = "echo"
        model: str = ""
        classifier: str = "keyword"
        target_id: str = "hactu8-lamb"
        confirm_spend: bool = False

    class LiveRequest(BaseModel):
        backend: str = "echo"
        model: str = ""
        confirm_spend: bool = False

    class WolfRequest(BaseModel):
        backend: str = "echo"
        model: str = ""
        target_backend: str = ""
        target_model: str = ""
        rounds: int = 3
        attempts: int = 2
        confirm_spend: bool = False

    app = FastAPI(title="HACTU8 API", version="0.1.0")
    hosts = {h.lower() for h in (hosts if hosts is not None else allowed_hosts())}

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def host_check(request: Request, call_next):
        # DNS-rebinding guard: the browser sends the attacker's name as Host.
        if (request.headers.get("host") or "").lower() not in hosts:
            return JSONResponse({"detail": "misdirected request: Host must be a loopback name and the API port"},
                                status_code=421)
        return await call_next(request)

    @app.get("/api/health")
    def health():
        return {"status": "ok", "service": "hactu8-api"}

    @app.get("/api/branding")
    def get_branding():
        return branding.load(root / "branding.yaml")

    @app.get("/api/skills")
    def skills():
        values = [skill.to_dict() for skill in catalog.discover(root)]
        return {"skills": values, "total": len(values)}

    @app.get("/api/path")
    def learning_path():
        return catalog.learning_path(catalog.discover(root))

    @app.get("/api/skills/{skill_id}/lesson")
    def lesson(skill_id: str):
        try:
            skill = catalog.get(skill_id, root)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        try:
            value = lessons.load(skill.skill_dir)
        except lessons.LessonError as exc:
            raise HTTPException(500, f"malformed lesson for {skill.id}: {exc}") from exc
        if value is None:
            raise HTTPException(404, f"no lesson yet for {skill.id}")
        return {"skill_id": skill.id, "owasp": skill.owasp, "risk": skill.risk, **value.to_dict()}

    @app.get("/api/coverage")
    def coverage():
        return techniques.coverage(store.list_runs())

    @app.get("/api/defenses")
    def defense_catalog():
        from hactu8 import bench
        return defenses.report(catalog.discover(root), store.list_runs(), bench.run().items)

    @app.get("/api/protections")
    def protection_library():
        values = protections.library()
        return {"protections": values, "total": len(values)}

    @app.get("/api/targets")
    def targets():
        return {
            "targets": [{
                "id": "hactu8-lamb",
                "name": "HACTU8 Lamb",
                "kind": "lamb",
                "targetUrl": "http://127.0.0.1:5500",
                "mcpUrl": "http://127.0.0.1:5500/mcp",
                "riskNotes": "Intentionally vulnerable; loopback-only; payloads are benign-effect (canary and loopback only).",
                "protectedMcpUrl": "http://127.0.0.1:5500/protected/mcp",
            }],
            "total": 1,
        }

    @app.get("/api/results")
    def results_list():
        values = list(reversed(store.list_runs()))
        return {"results": values, "total": len(values)}

    @app.get("/api/models")
    def models():
        try:
            router = Router.from_config(config.load(root / "hactu8.yaml"))
        except (config.ConfigError, ValueError) as exc:
            raise HTTPException(500, str(exc)) from exc
        candidates = router.describe()
        catalogs = {}
        for name in providers.BACKENDS:
            ready = name == providers.OFFLINE or any(c["backend"] == name and c["available"] for c in candidates)
            catalogs[name] = providers.available_models(name) if ready and name != providers.OFFLINE else []
        return {"backends": list(providers.BACKENDS), "local": list(providers.LOCAL), "cloud": list(spend.CLOUD),
                "keys_set": {name: providers.key_set(name) for name in providers.KEY_ENV},
                "default_models": dict(providers.DEFAULT_MODELS), "hardware": providers.backend_support(),
                "candidates": candidates,
                "catalogs": catalogs}

    @app.post("/api/live")
    def live_run(request: LiveRequest):
        import time

        from hactu8 import live
        from hactu8.result import now_iso
        if spend.is_cloud(request.backend) and not request.confirm_spend:
            raise HTTPException(402, spend.estimate(request.backend, spend.LIVE_CALLS) + " Set confirm_spend.")
        started, clock = now_iso(), time.monotonic()
        try:
            run = live.run(request.backend, request.model)
        except (RuntimeError, ValueError) as exc:
            raise HTTPException(400, str(exc)) from exc
        doc = live.to_result(run, started, int((time.monotonic() - clock) * 1000))
        store.save(doc)
        return doc

    @app.post("/api/wolf")
    def wolf_run(request: WolfRequest):
        import time

        from hactu8 import wolf_agent
        from hactu8.result import now_iso
        rounds, attempts = wolf_agent.bounds(request.rounds, request.attempts)
        notice = wolf_agent.spend_notice(request.backend, request.target_backend, rounds, attempts)
        if notice and not request.confirm_spend:
            raise HTTPException(402, notice + " Set confirm_spend.")
        started, clock = now_iso(), time.monotonic()
        try:
            run = wolf_agent.run(request.backend, request.model, target_backend=request.target_backend,
                                 target_model=request.target_model, rounds=rounds, attempts=attempts)
        except (RuntimeError, ValueError) as exc:
            raise HTTPException(400, str(exc)) from exc
        doc = wolf_agent.to_result(run, started, int((time.monotonic() - clock) * 1000))
        store.save(doc)
        return doc

    @app.get("/api/scoreboard")
    def scoreboard():
        rows = store.scoreboard()
        return {"scoreboard": rows, "total": len(rows)}

    @app.get("/api/results/{run_id}")
    def result(run_id: str):
        value = store.load(run_id)
        if value is None:
            raise HTTPException(404, "result not found")
        return value

    @app.post("/api/runs")
    def run(request: RunRequest):
        if request.target_id != "hactu8-lamb":
            raise HTTPException(400, f"unknown target: {request.target_id}")
        if providers.hardware_reason(request.backend):
            raise HTTPException(400, providers.hardware_reason(request.backend))
        if spend.is_cloud(request.backend) and not request.confirm_spend:
            raise HTTPException(402, spend.estimate(request.backend, spend.lab_calls(1)) + " Set confirm_spend.")
        try:
            skill = catalog.get(request.skill_id, root)
            cfg = config.load(root / "hactu8.yaml")
            router = Router.from_config(cfg)
            notice = spend.judge_notice(router, request.classifier)
            if notice and not request.confirm_spend:
                raise HTTPException(402, notice + " Set confirm_spend.")
            classifier = get_classifier(request.classifier, cfg, router)
        except (KeyError, RuntimeError, RouterError, config.ConfigError) as exc:
            raise HTTPException(400, str(exc)) from exc
        doc = lab.run(skill, backend=request.backend, model=request.model, classifier=classifier)
        if request.target_id == "hactu8-lamb":
            doc["target"] = {
                "kind": "lamb",
                "id": "hactu8-lamb",
                "url": f"http://127.0.0.1:5500/labs/{skill.id}",
                "port": skill.port,
            }
        store.save(doc)
        return doc

    @app.get("/api/reports/{run_id}/{format_name}")
    def report(run_id: str, format_name: str):
        value = store.load(run_id)
        if value is None:
            raise HTTPException(404, "result not found")
        if format_name not in reports.FORMATS:
            raise HTTPException(404, "unknown report format")
        text = reports.render(value, format_name, branding.load(root / "branding.yaml"))
        headers = {
            "Content-Disposition":
                f'attachment; filename="{value["run_id"]}.{reports.EXTENSIONS[format_name]}"'
        }
        return PlainTextResponse(text, media_type=reports.CONTENT_TYPES[format_name], headers=headers)

    console = os.environ.get("HACTU8_CONSOLE_DIR", "")
    if console and (Path(console) / "index.html").is_file():
        _mount_console(app, Path(console))
    return app


def _mount_console(app, dist: Path) -> None:
    """Serve the built console: its files, else index.html for client-side routes. /api stays JSON."""
    from fastapi import HTTPException
    from fastapi.responses import FileResponse

    dist = dist.resolve()

    @app.get("/{path:path}", include_in_schema=False)
    def console(path: str):
        if path == "api" or path.startswith("api/"):
            raise HTTPException(404, "not found")
        target = (dist / path).resolve()
        if path and target.is_file() and target.is_relative_to(dist):
            return FileResponse(target)
        return FileResponse(dist / "index.html")


def main() -> None:
    try:
        import uvicorn
    except ModuleNotFoundError as exc:
        raise SystemExit("API needs the optional dependency: pip install 'hactu8[api]'") from exc
    port = int(os.environ.get("HACTU8_API_PORT", "8000"))
    uvicorn.run(create_app(), host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()

