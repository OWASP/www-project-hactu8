#!/usr/bin/env python3
"""WHOIS lookup — passive domain registration info via subprocess whois.
Standalone script (requires the `whois` binary on PATH). Runnable outside
IAC by any tool that can execute a script.

Usage: whois_lookup.py <domain-or-url>
Prints one JSON object to stdout: {"success": bool, "data": ..., "error": ...}
"""
import asyncio
import json
import re
import shutil
import sys
from urllib.parse import urlparse


def _extract_domain(target: str) -> str:
    """Extract bare domain from a URL or return as-is if already a domain."""
    if target.startswith(("http://", "https://")):
        return urlparse(target).hostname or target
    return target


def _parse_whois_output(raw: str) -> dict:
    """Extract key fields from raw whois text."""
    fields = {}
    patterns = {
        "registrar": r"(?i)registrar:\s*(.+)",
        "creation_date": r"(?i)creation date:\s*(.+)",
        "expiration_date": r"(?i)(?:expir(?:y|ation) date|registry expiry date):\s*(.+)",
        "updated_date": r"(?i)updated date:\s*(.+)",
        "name_servers": r"(?i)name server:\s*(.+)",
        "registrant_org": r"(?i)registrant organization:\s*(.+)",
        "status": r"(?i)domain status:\s*(.+)",
    }
    for key, pattern in patterns.items():
        matches = re.findall(pattern, raw)
        if matches:
            fields[key] = matches[0].strip() if len(matches) == 1 else [m.strip() for m in matches]
    return fields


async def whois_lookup(target: str) -> dict:
    if not shutil.which("whois"):
        return {
            "success": False,
            "data": None,
            "error": "'whois' command not found. Install it (e.g. brew install whois).",
        }

    domain = _extract_domain(target)
    try:
        proc = await asyncio.create_subprocess_exec(
            "whois", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=15.0)
        raw = stdout.decode(errors="replace")

        if not raw.strip():
            return {"success": False, "data": None, "error": f"No WHOIS data returned for {domain!r}"}

        parsed = _parse_whois_output(raw)
        return {"success": True, "data": {"domain": domain, "parsed": parsed, "raw": raw[:2000]}, "error": None}
    except asyncio.TimeoutError:
        return {"success": False, "data": None, "error": f"WHOIS lookup timed out for {domain!r}"}
    except Exception as exc:
        return {"success": False, "data": None, "error": str(exc)}


def main() -> None:
    if len(sys.argv) != 2:
        print(json.dumps({"success": False, "data": None, "error": "Usage: whois_lookup.py <domain-or-url>"}))
        sys.exit(0)
    print(json.dumps(asyncio.run(whois_lookup(sys.argv[1]))))


if __name__ == "__main__":
    main()
