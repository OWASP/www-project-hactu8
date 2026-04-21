"""WHOIS lookup skill — passive domain registration info via subprocess whois."""

import asyncio
import re
import shutil
from urllib.parse import urlparse

from skills.registry import SkillResult, skill


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


@skill(
    name="whois_lookup",
    description=(
        "Perform a WHOIS lookup on a domain or URL to retrieve registration "
        "information: registrar, creation/expiry dates, name servers, and status."
    ),
    category="recon",
    requires_approval=False,
)
async def whois_lookup(target: str) -> SkillResult:
    """Look up WHOIS information for the given domain or URL."""
    if not shutil.which("whois"):
        return SkillResult(
            success=False,
            error="'whois' command not found. Install it (e.g. brew install whois).",
        )

    domain = _extract_domain(target)
    try:
        proc = await asyncio.create_subprocess_exec(
            "whois", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15.0)
        raw = stdout.decode(errors="replace")

        if not raw.strip():
            return SkillResult(success=False, error=f"No WHOIS data returned for {domain!r}")

        parsed = _parse_whois_output(raw)
        return SkillResult(
            success=True,
            data={"domain": domain, "parsed": parsed, "raw": raw[:2000]},
        )
    except asyncio.TimeoutError:
        return SkillResult(success=False, error=f"WHOIS lookup timed out for {domain!r}")
    except Exception as exc:
        return SkillResult(success=False, error=str(exc))
