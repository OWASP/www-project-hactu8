"""ProtectoGW as an MCP gateway: a screening proxy in front of Billy's server.

    model client  ->  ProtectoGW gateway (this)  ->  Billy KB-Tools (Lamb /mcp)
                      screen() on every hop

Every surface that crosses the boundary is untrusted text headed for the model:
tool definitions (description and parameter schema), tool results (including
error results and structured content), resource bodies and prompt templates.
The gateway screens each one with ProtectoGW and quarantines what it flags. It
also pins tool definitions on first sight (trust on first use, or a pins file
approved at review) and drops any tool whose definition later changes, and it
checks tool names against peer servers for shadowing.

Ported from AgenticGoat's fastmcp gateway onto the MCP v2 SDK's low-level
server, which is built for pass-through handlers. Screening is stateful by
default: a protectogw.Session per gateway accumulates reads, so a chain that is
clean one document at a time is still caught.

Inside Lamb the gateway is mounted at /protected/mcp beside the raw /mcp. It can
also run standalone with bearer-token auth and a TLS 1.2+ floor:

    python -m hactu8.lamb.gateway --port 9000 [--tls-cert C --tls-key K] [--min-tls 1.3]

The token comes from HACTU8_GATEWAY_TOKEN, never the command line.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import ssl
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from hactu8 import providers
from hactu8.lamb import DEFAULT_HOST
from hactu8.protectogw import Session, ToolPins, Verdict, screen, shadowing

QUARANTINE = ("[ProtectoGW] quarantined: hostile instruction or exfiltration pattern detected on this "
              "surface; content withheld from the model.")
SANITIZED = "[ProtectoGW] description sanitized: embedded instructions removed."
STRONG_CIPHERS = ("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:"
                  "!aNULL:!eNULL:!MD5:!RC4:!3DES:!DES:!EXPORT:!LOW")
_TLS_FLOOR = {"1.2": ssl.TLSVersion.TLSv1_2, "1.3": ssl.TLSVersion.TLSv1_3}
_URI = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.I)


@dataclass
class GatewayConfig:
    stateful: bool = True                  # accumulate reads in a protectogw.Session
    pin_tools: bool = True                 # drop tools whose definition changed since approval
    pins: Optional[Dict[str, Dict[str, str]]] = None   # approved fingerprints; None = trust on first use
    peer_tools: Dict[str, List[dict]] = field(default_factory=dict)  # other servers, for shadowing
    extra_canaries: Tuple[str, ...] = ()
    token: str = ""                        # bearer token; empty = no auth (loopback lab default)
    scopes: Tuple[str, ...] = ("kb.read",)
    required_scopes: Tuple[str, ...] = ()
    tls_certfile: str = ""
    tls_keyfile: str = ""
    min_tls: str = "1.2"
    ciphers: str = STRONG_CIPHERS


class InProcessBackend:
    """Reach an MCP v2 server object directly (Lamb's own Billy server)."""

    name = "billy"

    def __init__(self, server: Any) -> None:
        self.server = server

    async def list_tools(self):
        return await self.server.list_tools()

    async def call_tool(self, name: str, arguments: dict):
        from mcp import types

        from hactu8.lamb._mcp import tool_error_class
        try:
            return await self.server.call_tool(name, arguments)
        except tool_error_class() as exc:
            # What a client sees on the wire: the error text as an error result.
            return types.CallToolResult(content=[types.TextContent(type="text", text=str(exc))], is_error=True)

    async def list_resources(self):
        return await self.server.list_resources()

    async def read_resource(self, uri: str) -> List[Tuple[str, Optional[str]]]:
        return [(c.content if isinstance(c.content, str) else "", c.mime_type)
                for c in await self.server.read_resource(uri)]

    async def list_prompts(self):
        return await self.server.list_prompts()

    async def get_prompt(self, name: str, arguments: Optional[dict]):
        return await self.server.get_prompt(name, arguments or {})


def _schema_strings(schema: Any) -> Iterable[str]:
    """Every model-visible string inside a JSON schema (descriptions, titles, enums, defaults)."""
    if isinstance(schema, dict):
        for key, value in schema.items():
            if key in ("description", "title", "default") and isinstance(value, str):
                yield value
            elif key == "enum" and isinstance(value, list):
                yield from (v for v in value if isinstance(v, str))
            else:
                yield from _schema_strings(value)
    elif isinstance(schema, list):
        for item in schema:
            yield from _schema_strings(item)


def _strip_schema(schema: Any) -> Any:
    """The same schema with every free-text field removed: types and names only."""
    if isinstance(schema, dict):
        return {k: _strip_schema(v) for k, v in schema.items() if k not in ("description", "title", "default")}
    if isinstance(schema, list):
        return [_strip_schema(v) for v in schema]
    return schema


def _tool_dict(tool: Any) -> dict:
    return {"name": tool.name, "title": getattr(tool, "title", None), "description": tool.description,
            "inputSchema": getattr(tool, "input_schema", None), "annotations": None}


class Gateway:
    """The screening logic, independent of transport so it can be tested directly."""

    def __init__(self, backend: Any, config: Optional[GatewayConfig] = None) -> None:
        self.backend = backend
        self.config = config or GatewayConfig()
        self._lock = threading.RLock()
        self.log: List[dict] = []
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self.session = Session()
            self.pins = ToolPins(self.config.pins) if self.config.pins is not None else ToolPins()
            self._tofu = self.config.pins is None
            self.quarantined_tools: Dict[str, str] = {}
            self.log.clear()

    # helpers
    def _canaries(self) -> List[str]:
        return [providers.canary(), *self.config.extra_canaries]

    def _screen(self, text: str):
        return screen(text or "", canaries=self._canaries())

    def _record(self, surface: str, target: str, verdict: str, signals: Iterable[str]) -> None:
        with self._lock:
            self.log.append({"surface": surface, "target": target, "verdict": verdict,
                             "signals": ",".join(signals)})

    def _session_flags(self, key: str, text: str) -> bool:
        if not self.config.stateful:
            return False
        with self._lock:
            self.session.observe(key, text)
            result = self.session.verdicts().get(key)
        return bool(result and result.flagged)

    # surfaces
    async def list_tools(self) -> list:
        tools = list(await self.backend.list_tools())
        server = getattr(self.backend, "name", "billy")
        shadow = shadowing({server: [_tool_dict(t) for t in tools], **self.config.peer_tools})
        out = []
        for tool in tools:
            definition = _tool_dict(tool)
            if self.config.pin_tools:
                with self._lock:
                    if self._tofu and self.pins.check(server, definition).verdict == Verdict.FLAG:
                        self.pins.approve(server, definition)
                    pin = self.pins.check(server, definition)
                if pin.verdict != Verdict.ALLOW:
                    self.quarantined_tools[tool.name] = pin.signals[0].plane
                    self._record("tool_definition", tool.name, "BLOCK", [s.plane for s in pin.signals])
                    continue
            sh = shadow.get(f"{server}/{tool.name}")
            if sh is not None and sh.verdict == Verdict.BLOCK:
                self.quarantined_tools[tool.name] = sh.signals[0].plane
                self._record("tool_name", tool.name, "BLOCK", [s.plane for s in sh.signals])
                continue
            update: Dict[str, Any] = {}
            desc = self._screen(tool.description or "")
            if desc.verdict != Verdict.ALLOW:
                update["description"] = SANITIZED
                self._record("tool_description", tool.name, desc.verdict.name, [s.plane for s in desc.signals])
            schema = getattr(tool, "input_schema", None) or {}
            bad = [s for s in (self._screen(t) for t in _schema_strings(schema)) if s.verdict != Verdict.ALLOW]
            if bad:
                update["input_schema"] = _strip_schema(schema)
                self._record("schema_param", tool.name, bad[0].verdict.name, [s.plane for s in bad[0].signals])
            out.append(tool.model_copy(update=update) if update else tool)
        return out

    async def call_tool(self, name: str, arguments: dict):
        from mcp import types
        if name in self.quarantined_tools:
            reason = self.quarantined_tools[name]
            self._record("tool_call", name, "BLOCK", [reason])
            return types.CallToolResult(content=[types.TextContent(
                type="text", text=f"[ProtectoGW] call refused: {name} is quarantined ({reason}).")], is_error=True)
        result = await self.backend.call_tool(name, arguments or {})
        key = next((v for v in (arguments or {}).values() if isinstance(v, str) and _URI.match(v)), name)
        texts = [getattr(block, "text", "") for block in result.content or [] if getattr(block, "text", None)]
        if result.structured_content:
            texts.append(json.dumps(result.structured_content, ensure_ascii=False))
        joined = "\n".join(texts)
        verdict = self._screen(joined)
        chained = self._session_flags(key, joined) and verdict.verdict == Verdict.ALLOW
        if verdict.verdict == Verdict.ALLOW and not chained:
            return result
        surface = "error_result" if result.is_error else "tool_result"
        signals = [s.plane for s in verdict.signals] + (["session_chain"] if chained else [])
        self._record(surface, name, "BLOCK" if verdict.blocked or chained else verdict.verdict.name, signals)
        # Keep the result shape: a tool with an output schema must still return structured content.
        structured = {"result": QUARANTINE} if result.structured_content is not None else None
        return types.CallToolResult(content=[types.TextContent(type="text", text=QUARANTINE)],
                                    structured_content=structured, is_error=result.is_error)

    async def list_resources(self) -> list:
        return list(await self.backend.list_resources())

    async def read_resource(self, uri: str) -> List[Tuple[str, Optional[str]]]:
        out = []
        for text, mime in await self.backend.read_resource(uri):
            verdict = self._screen(text)
            chained = self._session_flags(uri, text) and verdict.verdict == Verdict.ALLOW
            if verdict.verdict != Verdict.ALLOW or chained:
                self._record("resource_body", uri, "BLOCK",
                             [s.plane for s in verdict.signals] + (["session_chain"] if chained else []))
                text = QUARANTINE
            out.append((text, mime))
        return out

    async def list_prompts(self) -> list:
        return list(await self.backend.list_prompts())

    async def get_prompt(self, name: str, arguments: Optional[dict]):
        from mcp import types
        result = await self.backend.get_prompt(name, arguments)
        messages = []
        for message in result.messages:
            text = getattr(message.content, "text", None)
            if text is not None:
                verdict = self._screen(text)
                if verdict.verdict != Verdict.ALLOW:
                    self._record("prompt_template", name, verdict.verdict.name, [s.plane for s in verdict.signals])
                    message = message.model_copy(update={"content": types.TextContent(type="text", text=QUARANTINE)})
            messages.append(message)
        return result.model_copy(update={"messages": messages})


def build_server(gateway: Gateway):
    """An MCP v2 low-level server whose handlers run every request through the gateway."""
    from mcp import types
    from mcp.server.lowlevel import Server

    async def list_tools(ctx, params):
        return types.ListToolsResult(tools=await gateway.list_tools())

    async def call_tool(ctx, params):
        return await gateway.call_tool(params.name, params.arguments or {})

    async def list_resources(ctx, params):
        return types.ListResourcesResult(resources=await gateway.list_resources())

    async def read_resource(ctx, params):
        uri = str(params.uri)
        return types.ReadResourceResult(contents=[
            types.TextResourceContents(uri=uri, text=text, mime_type=mime)
            for text, mime in await gateway.read_resource(uri)])

    async def list_prompts(ctx, params):
        return types.ListPromptsResult(prompts=await gateway.list_prompts())

    async def get_prompt(ctx, params):
        return await gateway.get_prompt(params.name, params.arguments)

    return Server("ProtectoGW Gateway", version="2.0.0",
                  instructions="ProtectoGW screening proxy in front of Billy's KB-Tools (HACTU8 Lamb).",
                  on_list_tools=list_tools, on_call_tool=call_tool, on_list_resources=list_resources,
                  on_read_resource=read_resource, on_list_prompts=list_prompts, on_get_prompt=get_prompt)


class StaticTokenVerifier:
    """One static bearer token with fixed scopes, compared in constant time."""

    def __init__(self, token: str, scopes: Iterable[str], client_id: str = "hactu8-agent") -> None:
        self._token = token
        self._scopes = list(scopes)
        self._client_id = client_id

    async def verify_token(self, token: str):
        from mcp.server.auth.provider import AccessToken
        if self._token and hmac.compare_digest(token.encode(), self._token.encode()):
            return AccessToken(token=token, client_id=self._client_id, scopes=self._scopes)
        return None


def http_app(gateway: Gateway, *, path: str = "/mcp", host: str = DEFAULT_HOST, port: int = 9000):
    """The gateway as a Starlette app (stateless streamable HTTP, JSON responses)."""
    server = build_server(gateway)
    cfg = gateway.config
    kwargs: Dict[str, Any] = {}
    if cfg.token:
        from mcp.server.auth.settings import AuthSettings
        kwargs["token_verifier"] = StaticTokenVerifier(cfg.token, cfg.scopes)
        kwargs["auth"] = AuthSettings(issuer_url=f"http://{host}:{port}",
                                      resource_server_url=f"http://{host}:{port}{path}",
                                      required_scopes=list(cfg.required_scopes) or None)
    app = server.streamable_http_app(streamable_http_path=path, json_response=True, stateless_http=True,
                                     host=host, **kwargs)
    app.state.gateway = gateway
    return app, server


def mount(app: Any, gateway: Gateway, *, prefix: str = "/protected") -> Any:
    """Mount the gateway inside another Starlette app (Lamb) at <prefix>/mcp and run its
    session manager inside that app's lifespan."""
    from contextlib import asynccontextmanager

    from starlette.routing import Mount

    sub, server = http_app(gateway)
    app.router.routes.insert(0, Mount(prefix, app=sub))
    outer = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(a):
        async with outer(a):
            async with server.session_manager.run():
                yield

    app.router.lifespan_context = lifespan
    app.state.gateway = gateway
    return app


def hardened_tls_context(config: GatewayConfig) -> ssl.SSLContext:
    """Server TLS context: 1.2+ floor (or 1.3), no compression or renegotiation, server cipher order."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = _TLS_FLOOR.get(config.min_tls, ssl.TLSVersion.TLSv1_2)
    ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.options |= getattr(ssl, "OP_NO_RENEGOTIATION", 0)
    ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    ctx.set_ciphers(config.ciphers)
    if config.tls_certfile and config.tls_keyfile:
        ctx.load_cert_chain(config.tls_certfile, config.tls_keyfile)
    return ctx


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="ProtectoGW MCP gateway in front of Billy's KB-Tools")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--stateless", action="store_true", help="screen each payload alone (no Session)")
    parser.add_argument("--scope", action="append", default=[], help="scope granted to the token")
    parser.add_argument("--require-scope", action="append", default=[], help="scope required to call")
    parser.add_argument("--tls-cert", default="")
    parser.add_argument("--tls-key", default="")
    parser.add_argument("--min-tls", default="1.2", choices=["1.2", "1.3"])
    args = parser.parse_args(argv)
    import uvicorn

    from hactu8.lamb._mcp import McpUnavailable
    from hactu8.lamb.mcp_target import LambMcpState, build_mcp_server
    try:
        billy = build_mcp_server(LambMcpState())
    except McpUnavailable as exc:
        parser.error(str(exc))
    config = GatewayConfig(stateful=not args.stateless, token=os.environ.get("HACTU8_GATEWAY_TOKEN", ""),
                           scopes=tuple(args.scope) or ("kb.read",), required_scopes=tuple(args.require_scope),
                           tls_certfile=args.tls_cert, tls_keyfile=args.tls_key, min_tls=args.min_tls)
    app, _ = http_app(Gateway(InProcessBackend(billy), config), port=args.port)
    ucfg = uvicorn.Config(app, host=DEFAULT_HOST, port=args.port, log_level="warning")
    ucfg.load()
    scheme = "http"
    if config.tls_certfile and config.tls_keyfile:
        ucfg.ssl = hardened_tls_context(config)
        scheme = "https"
    print(f"ProtectoGW gateway on {scheme}://{DEFAULT_HOST}:{args.port}/mcp "
          f"[{'stateless' if args.stateless else 'stateful'} screening"
          f"{', bearer auth' if config.token else ''}]")
    uvicorn.Server(ucfg).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
