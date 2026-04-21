"""DNS lookup skill — passive recon via stdlib socket."""

import socket
from typing import Any, Dict, List

from skills.registry import SkillResult, skill


@skill(
    name="dns_lookup",
    description="Resolve DNS records for a domain. Returns A records (IPv4 addresses) using system resolver.",
    category="recon",
    requires_approval=False,
)
async def dns_lookup(domain: str) -> SkillResult:
    """Resolve A records for the given domain."""
    try:
        # getaddrinfo returns list of (family, type, proto, canonname, sockaddr)
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        addresses: List[str] = list({r[4][0] for r in results})

        # Also attempt reverse lookup on first address
        reverse: List[Dict[str, Any]] = []
        for addr in addresses[:3]:
            try:
                hostname, _, _ = socket.gethostbyaddr(addr)
                reverse.append({"ip": addr, "hostname": hostname})
            except socket.herror:
                reverse.append({"ip": addr, "hostname": None})

        return SkillResult(
            success=True,
            data={
                "domain": domain,
                "a_records": addresses,
                "reverse": reverse,
            },
        )
    except socket.gaierror as exc:
        return SkillResult(success=False, error=f"DNS resolution failed for {domain!r}: {exc}")
