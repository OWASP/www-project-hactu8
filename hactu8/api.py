"""FastAPI service for HACTU8 skills, lessons, the learning path, protections, runs, results, targets,
branding, and reports.

Set HACTU8_CONSOLE_DIR to a built console (Vite ``dist/``) to serve it at ``/`` from the same origin,
as the Docker image does.

Every request must name a loopback Host (127.0.0.1, localhost or [::1]) with the API's port
(HACTU8_API_PORT, default 8000; also HACTU8_PORT, the host port Docker publishes it on); anything
else gets 421. That stops DNS rebinding: a page on attacker.example re-pointed at 127.0.0.1 still
sends ``Host: attacker.example``.

``python -m hactu8.api`` serves HTTPS by default with a per-user self-signed certificate, or your own
(see ``hactu8/tls.py``); ``HACTU8_TLS=off`` serves plain HTTP. Every response carries security headers
(``SECURITY_HEADERS`` and a CSP: ``API_CSP`` on /api, ``CONSOLE_CSP`` on the console).

FastAPI's /docs, /redoc and /openapi.json are off: Swagger UI and ReDoc load unpinned scripts from a CDN
onto this origin. ``HACTU8_API_DOCS=on`` turns them back on (and exempts them from the CSP).

Bound to a non-loopback address (``--host 0.0.0.0``, as in the container) the API needs a token, as
Jupyter does: HACTU8_API_TOKEN, or a random one made at start and printed once as a login URL. Opening
``/?token=...`` sets an HttpOnly, Secure, SameSite=Strict cookie; scripts send ``Authorization: Bearer``.
A loopback bind needs no token unless HACTU8_API_TOKEN is set. /api/health stays open for the
healthcheck. Every request to /api/runs, /api/live and /api/wolf appends a line to
$HACTU8_HOME/audit.log (``store.audit``)."""

import copy
import hmac
import ipaddress
import logging
import os
import re
import secrets
from pathlib import Path
from typing import Optional

from hactu8 import (branding, catalog, config, defenses, lessons, protections, providers, reports, spend, store,
                    techniques, tls)
from hactu8.adapters import lab
from hactu8.classify import get_classifier
from hactu8.router import Router, RouterError


LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]")

# No HSTS: the host is always localhost or a loopback IP. HSTS on "localhost" covers every port, so it
# would force HTTPS onto unrelated local dev servers (and the HTTP lab consoles), browsers ignore it for
# IP addresses, and Chrome drops it when the certificate is not trusted, which a self-signed one is not
# until you trust it.
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
}
# The built console: its own scripts, styles and images only; it calls the API on its own origin.
CONSOLE_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
               "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
API_CSP = "default-src 'none'; frame-ancestors 'none'"
# FastAPI's /docs and /redoc pages load Swagger UI / ReDoc from a CDN with an inline script. They are
# served, and exempt from the CSP, only with HACTU8_API_DOCS=on.
DOCS_PATHS = ("/docs", "/docs/oauth2-redirect", "/redoc")
TOKEN_ENV = "HACTU8_API_TOKEN"
TOKEN_COOKIE = "hactu8_token"
OPEN_PATHS = ("/api/health",)  # the container healthcheck has no token


def docs_enabled() -> bool:
    """FastAPI's docs pages: off unless HACTU8_API_DOCS is on (also 1, true, yes)."""
    return os.environ.get("HACTU8_API_DOCS", "off").strip().lower() in ("on", "1", "true", "yes")


def is_loopback(host: str) -> bool:
    """True for a bind address only this machine can reach: localhost or a loopback IP."""
    host = host.strip().strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class RedactTokenFilter(logging.Filter):
    """Keeps the login token out of uvicorn's access log, which records ``GET /?token=...``."""

    PATTERN = re.compile(r"(token=)[^&\s\"]+")

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(self.PATTERN.sub(r"\1<redacted>", a) if isinstance(a, str) else a
                                for a in record.args)
        record.msg = self.PATTERN.sub(r"\1<redacted>", str(record.msg))
        return True


def log_config() -> dict:
    """uvicorn's logging config with the token filter on its access handler."""
    from uvicorn.config import LOGGING_CONFIG
    config = copy.deepcopy(LOGGING_CONFIG)
    config.setdefault("filters", {})["redact_token"] = {"()": RedactTokenFilter}
    config["handlers"]["access"].setdefault("filters", []).append("redact_token")
    return config


def _same(given: str, token: str) -> bool:
    return bool(given) and hmac.compare_digest(given.encode("utf-8"), token.encode("utf-8"))


def dev_origins() -> list:
    """The Vite dev server's origins, allowed by CORS: HTTPS, or HTTP when HACTU8_TLS is off."""
    return [f"{tls.scheme()}://{host}:5173" for host in ("127.0.0.1", "localhost")]


def allowed_hosts() -> set:
    """Host header values the API answers: loopback names with its configured port(s)."""
    ports = {os.environ.get("HACTU8_API_PORT", "8000").strip() or "8000"}
    if os.environ.get("HACTU8_PORT", "").strip():
        ports.add(os.environ["HACTU8_PORT"].strip())
    return {f"{host}:{port}" for host in LOOPBACK_HOSTS for port in ports}


def create_app(root: Optional[Path] = None, hosts: Optional[set] = None, token: Optional[str] = None):
    """The app. ``token`` (default: HACTU8_API_TOKEN) gates every request but /api/health; "" means none."""
    try:
        from fastapi import FastAPI, HTTPException, Request
        from fastapi.middleware.cors import CORSMiddleware
        from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
        from pydantic import BaseModel, field_validator
    except ModuleNotFoundError as exc:
        raise RuntimeError("API needs the optional dependency: pip install 'hactu8[api]'") from exc

    root = root or catalog.find_root()

    class Checked(BaseModel):
        """Backend must be known and model in the safe charset (they reach reports and shell lines); else 422."""

        @field_validator("backend", "target_backend", check_fields=False)
        @classmethod
        def _backend(cls, value: str) -> str:
            return providers.check_backend(value)

        @field_validator("model", "target_model", check_fields=False)
        @classmethod
        def _model(cls, value: str) -> str:
            return providers.check_model(value)

    class RunRequest(Checked):
        skill_id: str
        backend: str = "echo"
        model: str = ""
        classifier: str = "keyword"
        target_id: str = "hactu8-lamb"
        confirm_spend: bool = False

    class LiveRequest(Checked):
        backend: str = "echo"
        model: str = ""
        confirm_spend: bool = False

    class WolfRequest(Checked):
        backend: str = "echo"
        model: str = ""
        target_backend: str = ""
        target_model: str = ""
        rounds: int = 3
        attempts: int = 2
        confirm_spend: bool = False

    docs = docs_enabled()
    app = FastAPI(title="HACTU8 API", version="0.1.0", docs_url="/docs" if docs else None,
                  redoc_url="/redoc" if docs else None, openapi_url="/openapi.json" if docs else None)
    csp_exempt = DOCS_PATHS if docs else ()
    hosts = {h.lower() for h in (hosts if hosts is not None else allowed_hosts())}
    token = (os.environ.get(TOKEN_ENV, "") if token is None else token).strip()

    def authorize(request: Request):
        """None when the request may proceed; else the 401 (or the login redirect that sets the cookie)."""
        path = request.url.path
        if request.method == "OPTIONS" or path in OPEN_PATHS:
            return None
        if "token" in request.query_params and not (path == "/api" or path.startswith("/api/")):
            if not _same(request.query_params["token"], token):
                return JSONResponse({"detail": "invalid token"}, status_code=401)
            response = RedirectResponse("/" + path.lstrip("/"), status_code=303)  # never "//host": no open redirect
            response.set_cookie(TOKEN_COOKIE, token, httponly=True, secure=True, samesite="strict", path="/")
            return response
        bearer = request.headers.get("authorization", "")
        bearer = bearer[7:].strip() if bearer[:7].lower() == "bearer " else ""
        if _same(bearer, token) or _same(request.cookies.get(TOKEN_COOKIE, ""), token):
            return None
        return JSONResponse({"detail": "token required: open the login URL the API printed at start, "
                                       "or send Authorization: Bearer <token>"},
                            status_code=401, headers={"WWW-Authenticate": "Bearer"})

    app.add_middleware(
        CORSMiddleware,
        allow_origins=dev_origins(),
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def host_check(request: Request, call_next):
        # DNS-rebinding guard: the browser sends the attacker's name as Host.
        if (request.headers.get("host") or "").lower() not in hosts:
            response = JSONResponse({"detail": "misdirected request: Host must be a loopback name and the API port"},
                                    status_code=421)
        else:
            response = (authorize(request) if token else None) or await call_next(request)
        path = request.url.path
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if path not in csp_exempt:
            response.headers.setdefault("Content-Security-Policy",
                                        API_CSP if path == "/api" or path.startswith("/api/") or path == "/openapi.json"
                                        else CONSOLE_CSP)
        return response

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

    def audited(endpoint: str, http: Request, body, work, **extra):
        """Run ``work()`` and append one audit line: ok, refused (402) or error, with the HTTP status."""
        fields = dict(client=http.client.host if http.client else "", backend=body.backend, model=body.model,
                      confirm_spend=body.confirm_spend, **extra)
        try:
            doc = work()
        except HTTPException as exc:
            store.audit(endpoint, outcome="refused" if exc.status_code == 402 else "error",
                        status=exc.status_code, **fields)
            raise
        except Exception:
            store.audit(endpoint, outcome="error", status=500, **fields)
            raise
        store.audit(endpoint, outcome="ok", status=200, run_id=doc.get("run_id"), **fields)
        return doc

    @app.post("/api/live")
    def live_run(request: LiveRequest, http: Request):
        return audited("/api/live", http, request, lambda: _live(request))

    def _live(request):
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
    def wolf_run(request: WolfRequest, http: Request):
        return audited("/api/wolf", http, request, lambda: _wolf(request), target_backend=request.target_backend,
                       target_model=request.target_model, rounds=request.rounds, attempts=request.attempts)

    def _wolf(request):
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
    def run(request: RunRequest, http: Request):
        return audited("/api/runs", http, request, lambda: _run(request), skill_id=request.skill_id,
                       classifier=request.classifier)

    def _run(request):
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

    @app.api_route("/{path:path}", methods=["GET", "HEAD"], include_in_schema=False)
    def console(path: str):
        if path == "api" or path.startswith("api/"):
            raise HTTPException(404, "not found")
        target = (dist / path).resolve()
        if path and target.is_file() and target.is_relative_to(dist):
            return FileResponse(target)
        return FileResponse(dist / "index.html")


def main(argv=None) -> None:
    """Serve the API on 127.0.0.1:$HACTU8_API_PORT, over HTTPS unless HACTU8_TLS=off.

    ``--host`` exists for the container, which listens on its own private 0.0.0.0 and is published on
    the host's 127.0.0.1 only; the Host allowlist applies either way. A non-loopback bind needs a token
    (HACTU8_API_TOKEN, else a random one): the login URL is printed once, here, and nowhere else."""
    import argparse
    parser = argparse.ArgumentParser(prog="python -m hactu8.api")
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args(argv)
    try:
        import uvicorn
    except ModuleNotFoundError as exc:
        raise SystemExit("API needs the optional dependency: pip install 'hactu8[api]'") from exc
    port = int(os.environ.get("HACTU8_API_PORT", "8000"))
    try:
        options = tls.uvicorn_options()
    except tls.TLSError as exc:
        raise SystemExit(f"TLS: {exc}") from exc
    if options:
        print(f"HACTU8 API on https://127.0.0.1:{port} (certificate: {options['ssl_certfile']})", flush=True)
    else:
        print(f"HACTU8 API on http://127.0.0.1:{port} (HACTU8_TLS=off: plain HTTP)", flush=True)
    if docs_enabled():
        print("WARNING: HACTU8_API_DOCS is on: /docs and /redoc load unpinned Swagger UI and ReDoc scripts "
              "from cdn.jsdelivr.net onto this origin, which can start paid runs. Turn it off when done.", flush=True)
    token = os.environ.get(TOKEN_ENV, "").strip()
    if token:
        print(f"Token required ({TOKEN_ENV}): log in at /?token=<your token> or send Authorization: Bearer.",
              flush=True)
    elif not is_loopback(args.host):
        token = secrets.token_urlsafe(32)
        public = os.environ.get("HACTU8_PORT", "").strip() or port
        print(f"Bound to {args.host}: a token is required. Log in once at "
              f"{tls.scheme()}://127.0.0.1:{public}/?token={token}", flush=True)
    uvicorn.run(create_app(token=token), host=args.host, port=port, log_config=log_config(), **options)


if __name__ == "__main__":
    main()

