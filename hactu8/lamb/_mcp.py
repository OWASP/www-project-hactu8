"""The single import point for the MCP SDK.

Lamb targets the official ``mcp`` v2 SDK (``MCPServer``). v1 (``FastMCP``) and the
standalone ``fastmcp`` package have different APIs and are not supported.
"""

from __future__ import annotations

UPGRADE_HINT = "Lamb needs the MCP v2 SDK: pip install 'hactu8[lamb]' (mcp>=2,<3)"


class McpUnavailable(RuntimeError):
    """The MCP v2 SDK is missing or an incompatible version is installed."""


def server_class():
    """Return ``mcp.server.MCPServer`` or raise McpUnavailable with an upgrade hint."""
    try:
        from mcp.server import MCPServer
    except ModuleNotFoundError as exc:
        raise McpUnavailable(UPGRADE_HINT) from exc
    except ImportError as exc:
        raise McpUnavailable(f"{UPGRADE_HINT}; found mcp {_installed_version()}") from exc
    return MCPServer


def available() -> bool:
    """True only when the MCP v2 SDK is importable (server and client).

    A stray mcp v1 install imports as ``mcp`` but lacks the v2 names, so tests
    and optional features check this rather than "can I import mcp".
    """
    try:
        server_class()
        from mcp import Client  # noqa: F401
    except (ImportError, McpUnavailable):
        return False
    return True


def tool_error_class():
    """The SDK exception whose message reaches the client as an error result."""
    from mcp.server.mcpserver.exceptions import ToolError
    return ToolError


def _installed_version() -> str:
    try:
        from importlib.metadata import version
        return version("mcp")
    except Exception:
        return "unknown"
