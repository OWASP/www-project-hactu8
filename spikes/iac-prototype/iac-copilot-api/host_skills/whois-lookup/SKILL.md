---
name: whois-lookup
description: Perform a WHOIS lookup on a domain or URL to retrieve registration information — registrar, creation/expiry dates, name servers, status. Requires a `whois` binary on the host.
metadata:
  phase: recon
---

# WHOIS Lookup

Runs the system `whois` command against a domain (a full URL is accepted —
the hostname is extracted automatically) and parses the standard fields out
of the raw response.

## Requirements

Requires a `whois` binary on PATH (e.g. `brew install whois` / `apt install whois`).
If missing, the script reports this in its `error` field rather than failing silently.

## Usage

    scripts/whois_lookup.py <domain-or-url>

Example: `scripts/whois_lookup.py example.com` or `scripts/whois_lookup.py https://example.com/path`

## Output

    {"success": true, "data": {"domain": "...", "parsed": {"registrar": "...", "creation_date": "...", ...}, "raw": "<first 2000 chars of raw whois output>"}, "error": null}

On failure:

    {"success": false, "data": null, "error": "..."}

## When to use

One call per target domain. Skip entirely for localhost or non-public targets
(local LLM endpoints, internal IPs) — WHOIS has no meaningful data for those.
