"""FastAPI service for HACTU8 skills, runs, results, targets, branding, and reports."""

from pathlib import Path
from typing import Optional

from hactu8 import branding, catalog, config, reports, store
from hactu8.adapters import lab
from hactu8.classify import get_classifier
from hactu8.router import Router, RouterError


def create_app(root: Optional[Path] = None):
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.middleware.cors import CORSMiddleware
        from fastapi.responses import PlainTextResponse
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

    app = FastAPI(title="HACTU8 API", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

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

    @app.get("/api/targets")
    def targets():
        return {
            "targets": [{
                "id": "hactu8-lamb",
                "name": "HACTU8 Lamb",
                "kind": "lamb",
                "targetUrl": "http://127.0.0.1:5500",
                "mcpUrl": "http://127.0.0.1:5500/mcp",
                "riskNotes": "Intentionally vulnerable; loopback-only; inert payloads and side effects.",
            }],
            "total": 1,
        }

    @app.get("/api/results")
    def results_list():
        values = list(reversed(store.list_runs()))
        return {"results": values, "total": len(values)}

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
        try:
            skill = catalog.get(request.skill_id, root)
            cfg = config.load(root / "hactu8.yaml")
            classifier = get_classifier(request.classifier, cfg, Router.from_config(cfg))
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

    return app


def main() -> None:
    try:
        import uvicorn
    except ModuleNotFoundError as exc:
        raise SystemExit("API needs the optional dependency: pip install 'hactu8[api]'") from exc
    uvicorn.run(create_app(), host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()

