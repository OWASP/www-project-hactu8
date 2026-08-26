---
name: http-probe
description: Probe an HTTP/HTTPS URL and report status code, response headers, server fingerprint, and redirect chain. Sends a single GET request — no attack payloads.
metadata:
  phase: recon
---

# HTTP Probe

Performs a single GET request against a URL and reports fingerprinting-relevant
response data: status code, redirect chain, server/security headers, content
type and length. TLS certificate verification is disabled (this is a
reconnaissance probe, not a certificate audit) and no payloads or exploit
attempts are sent.

## Requirements

Requires `httpx` to be installed (`pip install httpx`).

## Usage

    scripts/http_probe.py <url>

Example: `scripts/http_probe.py https://example.com/api/version`

## Output

    {"success": true, "data": {"url": "...", "status_code": 200, "redirect_chain": [...], "server": "...", "headers": {...}, "content_length": 1234, "content_type": "..."}, "error": null}

On failure (connection error, unsupported scheme, timeout):

    {"success": false, "data": null, "error": "..."}

## When to use

Probe the primary target URL first, then at most one or two well-known
API/management paths (e.g. /api/version, /health). Do not enumerate paths
exhaustively — this is a fingerprinting probe, not a scanner.
