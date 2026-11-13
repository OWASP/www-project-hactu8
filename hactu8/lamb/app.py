"""ASGI application for the HACTU8 Lamb gateway and MCP target."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

from hactu8.lamb import DEFAULT_HOST, DEFAULT_PORT
from hactu8.lamb.mcp_target import LambMcpState, build_mcp_server, install_attachment_tool
from hactu8.lamb.workers import LabWorkerManager, WorkerError

MAX_BODY = 1_000_000
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

    def host_ok(request: Request) -> bool:
        host = (request.headers.get("host") or "").split(":", 1)[0].lower()
        return host in {"127.0.0.1", "localhost"}

    def base_url(request: Request) -> str:
        return f"http://{request.headers.get('host') or f'{DEFAULT_HOST}:{DEFAULT_PORT}'}"

    @mcp.custom_route("/", methods=["GET"])
    async def index(request: Request) -> Response:
        if not host_ok(request):
            return JSONResponse({"error": "bad host"}, status_code=403)
        return JSONResponse({
            "name": "HACTU8 Lamb",
            "warning": "Intentionally vulnerable authorized security-lab target",
            "labs": "/api/labs",
            "mcp": "/mcp",
        })

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
        if not host_ok(request):
            return JSONResponse({"error": "bad host"}, status_code=403)
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
        result["mcp"] = state.reset()
        install_attachment_tool(mcp, state)
        return JSONResponse(result, status_code=502 if result["errors"] else 200)

    @mcp.custom_route("/api/lamb/mode", methods=["POST"])
    async def mode(request: Request) -> Response:
        if not host_ok(request):
            return JSONResponse({"error": "bad host"}, status_code=403)
        try:
            body = await _json_body(request)
            result = state.set_mode(str(body.get("mode", "")))
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        install_attachment_tool(mcp, state)
        return JSONResponse(result)

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
    app.state.workers = workers
    app.state.lamb_mcp = state
    app.state.mcp_server = mcp
    return app


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


def _rewrite_console_paths(content: bytes, content_type: str, skill_id: str) -> bytes:
    prefix = f"/labs/{skill_id}".encode()
    if "text/html" in content_type:
        return content.replace(b'href="/', b'href="' + prefix + b"/").replace(
            b'src="/', b'src="' + prefix + b"/")
    if "javascript" in content_type:
        quoted = json.dumps(prefix.decode()).encode()
        return content.replace(b"fetch(path, opts)", b"fetch(" + quoted + b" + path, opts)")
    return content

