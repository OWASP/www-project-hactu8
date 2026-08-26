#!/usr/bin/env python3
"""HTTP probe — passive fingerprinting of an HTTP/HTTPS endpoint. Standalone
script (requires httpx). Runnable outside IAC by any tool that can execute
a script and has httpx installed.

Usage: http_probe.py <url>
Prints one JSON object to stdout: {"success": bool, "data": ..., "error": ...}
"""
import asyncio
import json
import sys
from urllib.parse import urlparse

import httpx

INTERESTING_HEADERS = [
    "server", "x-powered-by", "x-frame-options", "content-security-policy",
    "strict-transport-security", "x-content-type-options", "set-cookie",
    "www-authenticate", "x-aspnet-version", "x-generator",
]


async def http_probe(url: str) -> dict:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return {"success": False, "data": None, "error": f"Unsupported scheme: {parsed.scheme!r}"}

        redirect_chain = []
        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            verify=False,  # prototype — skip TLS verification
        ) as client:
            response = await client.get(url)
            for r in response.history:
                redirect_chain.append({"url": str(r.url), "status": r.status_code})

        headers_found = {
            k.lower(): v
            for k, v in response.headers.items()
            if k.lower() in INTERESTING_HEADERS
        }

        return {
            "success": True,
            "data": {
                "url": str(response.url),
                "status_code": response.status_code,
                "redirect_chain": redirect_chain,
                "server": response.headers.get("server", "unknown"),
                "headers": headers_found,
                "content_length": len(response.content),
                "content_type": response.headers.get("content-type", "unknown"),
            },
            "error": None,
        }
    except httpx.RequestError as exc:
        return {"success": False, "data": None, "error": f"HTTP probe failed: {exc}"}


def main() -> None:
    if len(sys.argv) != 2:
        print(json.dumps({"success": False, "data": None, "error": "Usage: http_probe.py <url>"}))
        sys.exit(0)
    print(json.dumps(asyncio.run(http_probe(sys.argv[1]))))


if __name__ == "__main__":
    main()
