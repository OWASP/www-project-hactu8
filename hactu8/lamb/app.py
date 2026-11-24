"""ASGI application for the HACTU8 Lamb gateway and MCP target."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import html
import json
from pathlib import Path
from typing import Optional

from hactu8.lamb import DEFAULT_HOST, DEFAULT_PORT
from hactu8.lamb import surfaces as lamb
from hactu8.lamb.gateway import Gateway, InProcessBackend, mount
from hactu8.lamb.wolf import Wolf
from hactu8.lamb.mcp_target import LambMcpState, build_mcp_server, install_attachment_tool
from hactu8.lamb.workers import LabWorkerManager, WorkerError

MAX_BODY = 1_000_000
INDEX_JSON = {
    "name": "HACTU8 Lamb",
    "warning": "Intentionally vulnerable authorized security-lab target",
    "labs": "/api/labs",
    "mcp": "/mcp",
    "protected_mcp": "/protected/mcp",
}
INDEX_STYLE = (
    "body{font:15px/1.5 system-ui,sans-serif;margin:24px auto;max-width:960px;padding:0 16px;"
    "color:#1f2933;background:#fff}h1{margin-bottom:4px}.warn{color:#9a3412}"
    "table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:4px 8px;"
    "border-bottom:1px solid #d9e2ec;vertical-align:top}code{font-size:13px}"
    "@media (prefers-color-scheme:dark){body{color:#e4e7eb;background:#111827}.warn{color:#fdba74}a{color:#93c5fd}"
    "th,td{border-color:#374151}}"
)
# The HTML index has no script and no external asset: only its own inline style, pinned by hash.
INDEX_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'sha256-"
        + base64.b64encode(hashlib.sha256(INDEX_STYLE.encode()).digest()).decode()
        + "'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
}
HOP_HEADERS = {
    "connection", "content-length", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade",
}


def create_app(root: Optional[Path] = None, manager: Optional[LabWorkerManager] = None):
    try:
        from starlette.requests import Request
        from starlette.responses import JSONResponse, Response
    except ModuleNotFoundError as exc:
        raise RuntimeError("Lamb needs the optional dependency: pip install 'hactu8[lamb]'") from exc

    workers = manager or LabWorkerManager(root)
    state = LambMcpState()
    mcp = build_mcp_server(state)
    gateway = Gateway(InProcessBackend(mcp))
    wolf = Wolf()

    def host_ok(request: Request) -> bool:
        host = (request.headers.get("host") or "").split(":", 1)[0].lower()
        return host in {"127.0.0.1", "localhost"}

    def control_refusal(request: Request) -> Optional[Response]:
        """State-changing control calls need a JSON Content-Type (a cross-site form
        or no-cors fetch cannot send one without a preflight) and, when the browser
        names an Origin, a loopback one."""
        if not host_ok(request):
            return JSONResponse({"error": "bad host"}, status_code=403)
        origin = request.headers.get("origin")
        if origin is not None and not _loopback_origin(origin):
            return JSONResponse({"error": "cross-origin request refused"}, status_code=403)
        if not (request.headers.get("content-type") or "").startswith("application/json"):
            return JSONResponse({"error": "Content-Type must be application/json"}, status_code=415)
        return None

    def base_url(request: Request) -> str:
        return f"http://{request.headers.get('host') or f'{DEFAULT_HOST}:{DEFAULT_PORT}'}"

    @mcp.custom_route("/", methods=["GET"])
    async def index(request: Request) -> Response:
        if not host_ok(request):
            return JSONResponse({"error": "bad host"}, status_code=403)
        if request.query_params.get("format") != "json" and _wants_html(request.headers.get("accept", "")):
            tools = [(tool.name, tool.description or "") for tool in await mcp.list_tools()]
            return Response(_index_html(workers.describe(base_url(request)), tools),
                            media_type="text/html; charset=utf-8", headers=INDEX_HEADERS)
        return JSONResponse(INDEX_JSON)

    @mcp.custom_route("/health", methods=["GET"])
    async def health(request: Request) -> Response:
        if not host_ok(request):
            return JSONResponse({"error": "bad host"}, status_code=403)
        return JSONResponse({
            "status": "ok",
            "service": "hactu8-lamb",
            "labs": len(workers.skills),
            "running": workers.running_ids(),
            "mcp": state.snapshot(),
        })

    @mcp.custom_route("/api/labs", methods=["GET"])
    async def labs(request: Request) -> Response:
        if not host_ok(request):
            return JSONResponse({"error": "bad host"}, status_code=403)
        return JSONResponse({"labs": workers.describe(base_url(request)), "total": len(workers.skills)})

    @mcp.custom_route("/api/reset", methods=["POST"])
    async def reset(request: Request) -> Response:
        refused = control_refusal(request)
        if refused is not None:
            return refused
        try:
            body = await _json_body(request)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        requested = body.get("skills")
        if requested is not None and (
            not isinstance(requested, list) or not all(isinstance(item, str) for item in requested)
        ):
            return JSONResponse({"error": "skills must be an array of skill ids"}, status_code=400)
        result = await asyncio.to_thread(workers.reset, requested)
        lamb.restore_swaps(mcp, state.surfaces)
        state.surfaces.reset()
        gateway.reset()
        wolf.clear()
        result["mcp"] = state.reset()
        install_attachment_tool(mcp, state)
        return JSONResponse(result, status_code=502 if result["errors"] else 200)

    @mcp.custom_route("/api/lamb/mode", methods=["POST"])
    async def mode(request: Request) -> Response:
        refused = control_refusal(request)
        if refused is not None:
            return refused
        try:
            body = await _json_body(request)
            result = state.set_mode(str(body.get("mode", "")))
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        install_attachment_tool(mcp, state)
        return JSONResponse(result)

    @mcp.custom_route("/api/lamb/manifest", methods=["GET"])
    async def manifest(request: Request) -> Response:
        if not host_ok(request):
            return JSONResponse({"error": "bad host"}, status_code=403)
        return JSONResponse({"targets": {target: dict(meta, attack=lamb.truth(target, state.surfaces))
                                         for target, meta in lamb.ATTACK_MANIFEST.items()}})

    @mcp.custom_route("/api/lamb/gateway", methods=["GET"])
    async def gateway_log(request: Request) -> Response:
        if not host_ok(request):
            return JSONResponse({"error": "bad host"}, status_code=403)
        return JSONResponse({"mcp": "/protected/mcp", "stateful": gateway.config.stateful,
                             "quarantined_tools": gateway.quarantined_tools, "log": list(gateway.log)})

    @mcp.custom_route("/api/lamb/wolf", methods=["GET"])
    async def wolf_loot(request: Request) -> Response:
        if not host_ok(request):
            return JSONResponse({"error": "bad host"}, status_code=403)
        return JSONResponse({"confirmed": wolf.confirmed(), "captures": wolf.loot()})

    async def wolf_receive(request: Request) -> Response:
        if not host_ok(request):
            return JSONResponse({"error": "bad host"}, status_code=403)
        body = (await request.body())[:4096].decode("utf-8", errors="replace")
        capture = wolf.receive(request.method, request.url.path, request.url.query, body)
        return JSONResponse({"received": True, "confirmed": capture.confirmed})

    mcp.custom_route("/wolf/{path:path}", methods=["GET", "POST"])(wolf_receive)

    @mcp.custom_route("/api/lamb/swap", methods=["POST"])
    async def swap(request: Request) -> Response:
        refused = control_refusal(request)
        if refused is not None:
            return refused
        return JSONResponse(lamb.simulate_swap(mcp, state.surfaces))

    async def proxy(request: Request) -> Response:
        if not host_ok(request):
            return JSONResponse({"error": "bad host"}, status_code=403)
        skill_id = request.path_params["skill_id"]
        path = request.path_params.get("path", "")
        body = await request.body()
        if len(body) > MAX_BODY:
            return JSONResponse({"error": "body too large"}, status_code=413)
        target_path = "/" + path
        if request.url.query:
            target_path += "?" + request.url.query
        try:
            status, headers, content = await asyncio.to_thread(
                workers.request,
                skill_id,
                request.method,
                target_path,
                dict(request.headers),
                body,
            )
        except WorkerError as exc:
            code = 404 if "unknown Lamb lab" in str(exc) else 502
            return JSONResponse({"error": str(exc)}, status_code=code)
        content = _rewrite_console_paths(content, headers.get("Content-Type", ""), skill_id)
        forwarded = {key: value for key, value in headers.items() if key.lower() not in HOP_HEADERS}
        return Response(content, status_code=status, headers=forwarded)

    mcp.custom_route("/labs/{skill_id}", methods=["GET", "POST"])(proxy)
    mcp.custom_route("/labs/{skill_id}/{path:path}", methods=["GET", "POST"])(proxy)

    app = mcp.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        max_request_body_size=MAX_BODY,
        max_sessions=100,
        host=DEFAULT_HOST,
    )
    mount(app, gateway)
    inner_lifespan = app.router.lifespan_context

    @contextlib.asynccontextmanager
    async def lifespan(asgi_app):
        # Stop the lab workers when the server shuts down. uvicorn re-raises SIGTERM
        # after its graceful shutdown, so code after uvicorn.run() never runs on `kill`.
        try:
            async with inner_lifespan(asgi_app) as lifespan_state:
                yield lifespan_state
        finally:
            workers.close()

    app.router.lifespan_context = lifespan
    app.state.wolf = wolf
    app.state.workers = workers
    app.state.lamb_mcp = state
    app.state.mcp_server = mcp
    return app


def _loopback_origin(origin: str) -> bool:
    """True for an http(s) Origin on 127.0.0.1, localhost or [::1] (any port)."""
    from urllib.parse import urlsplit
    try:
        parts = urlsplit(origin)
        parts.port  # noqa: B018 — raises ValueError on a bad port
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and "@" not in parts.netloc and \
        (parts.hostname or "") in ("127.0.0.1", "localhost", "::1")


async def _json_body(request) -> dict:
    body = await request.body()
    if len(body) > MAX_BODY:
        raise ValueError("body too large")
    if not body:
        return {}
    if not (request.headers.get("content-type") or "").startswith("application/json"):
        raise ValueError("Content-Type must be application/json")
    try:
        value = json.loads(body)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("JSON body must be an object")
    return value


def _wants_html(accept: str) -> bool:
    """True when the Accept header names text/html (or application/xhtml+xml) with a non-zero q.
    A missing header, */* alone (curl, most clients) or JSON keeps the JSON index."""
    for media_range in accept.lower().split(","):
        kind, _, params = media_range.strip().partition(";")
        if kind.strip() not in ("text/html", "application/xhtml+xml"):
            continue
        q = 1.0
        for param in params.split(";"):
            name, _, value = param.strip().partition("=")
            if name.strip() == "q":
                try:
                    q = float(value)
                except ValueError:
                    q = 0.0
        if q > 0:
            return True
    return False


def _index_html(labs: list, tools: list) -> str:
    """Lamb's index for a browser: its labs and MCP tools, every value escaped.

    Tool descriptions are attacker-controlled in some labs (a swapped description is
    the rug pull), so nothing from ``labs`` or ``tools`` is trusted as markup."""
    esc = html.escape

    def lab_row(lab: dict) -> str:
        url = str(lab.get("url", ""))
        name = esc(str(lab.get("id", "")))
        link = f'<a href="{esc(url)}">{name}</a>' if url.startswith("http://") else name
        return (f"<tr><td>{link}</td><td>{esc(str(lab.get('owasp', '')))}</td>"
                f"<td>{esc(str(lab.get('risk', '')))}</td><td>{esc(str(lab.get('state', '')))}</td></tr>")

    lab_rows = "".join(lab_row(lab) for lab in labs) or '<tr><td colspan="4">No labs found.</td></tr>'
    tool_rows = "".join(f"<tr><td><code>{esc(str(name))}</code></td><td>{esc(str(description)[:300])}</td></tr>"
                        for name, description in tools) or '<tr><td colspan="2">No tools.</td></tr>'
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>HACTU8 Lamb</title><style>{INDEX_STYLE}</style></head><body>"
        "<h1>HACTU8 Lamb</h1>"
        f'<p class="warn">{esc(INDEX_JSON["warning"])}. Loopback only.</p>'
        "<p>MCP: <code>/mcp</code> (vulnerable) and <code>/protected/mcp</code> (behind the gateway). "
        'JSON: <a href="/?format=json"><code>/?format=json</code></a>, '
        '<a href="/api/labs"><code>/api/labs</code></a>, <a href="/health"><code>/health</code></a>.</p>'
        f"<h2>Labs ({len(labs)})</h2><table><thead><tr><th>Lab</th><th>OWASP</th><th>Risk</th><th>Worker</th>"
        f"</tr></thead><tbody>{lab_rows}</tbody></table>"
        f"<h2>MCP tools ({len(tools)})</h2><p>As Lamb lists them now; a lab may have swapped a description.</p>"
        f"<table><thead><tr><th>Tool</th><th>Description</th></tr></thead><tbody>{tool_rows}</tbody></table>"
        "</body></html>"
    )


def _rewrite_console_paths(content: bytes, content_type: str, skill_id: str) -> bytes:
    prefix = f"/labs/{skill_id}".encode()
    if "text/html" in content_type:
        return content.replace(b'href="/', b'href="' + prefix + b"/").replace(
            b'src="/', b'src="' + prefix + b"/")
    if "javascript" in content_type:
        quoted = json.dumps(prefix.decode()).encode()
        return content.replace(b"fetch(path, opts)", b"fetch(" + quoted + b" + path, opts)")
    return content

