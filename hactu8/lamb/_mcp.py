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


def _installed_version() -> str:
    try:
        from importlib.metadata import version
        return version("mcp")
    except Exception:
        return "unknown"
