"""HTTP probe skill — passive fingerprinting of an HTTP/HTTPS endpoint."""

from urllib.parse import urlparse

import httpx

from skills.registry import SkillResult, skill


@skill(
    name="http_probe",
    description=(
        "Probe an HTTP/HTTPS URL and return status code, response headers, "
        "server fingerprint, and redirect chain. Does not send any attack payloads."
    ),
    category="recon",
    requires_approval=False,
)
async def http_probe(url: str) -> SkillResult:
    """Fingerprint an HTTP endpoint via a GET request."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return SkillResult(success=False, error=f"Unsupported scheme: {parsed.scheme!r}")

        redirect_chain = []
        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            verify=False,  # prototype — skip TLS verification
        ) as client:
            response = await client.get(url)

            # Capture redirect history
            for r in response.history:
                redirect_chain.append({"url": str(r.url), "status": r.status_code})

        interesting_headers = [
            "server", "x-powered-by", "x-frame-options", "content-security-policy",
            "strict-transport-security", "x-content-type-options", "set-cookie",
            "www-authenticate", "x-aspnet-version", "x-generator",
        ]
        headers_found = {
            k.lower(): v
            for k, v in response.headers.items()
            if k.lower() in interesting_headers
        }

        return SkillResult(
            success=True,
            data={
                "url": str(response.url),
                "status_code": response.status_code,
                "redirect_chain": redirect_chain,
                "server": response.headers.get("server", "unknown"),
                "headers": headers_found,
                "content_length": len(response.content),
                "content_type": response.headers.get("content-type", "unknown"),
            },
        )
    except httpx.RequestError as exc:
        return SkillResult(success=False, error=f"HTTP probe failed: {exc}")
