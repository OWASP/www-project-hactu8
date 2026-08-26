---
name: dns-lookup
description: Resolve DNS A records (and reverse PTR hostnames) for a domain using the system resolver. Passive and read-only — issues a standard DNS query, nothing else.
metadata:
  phase: recon
---

# DNS Lookup

Resolves IPv4 (A record) addresses for a domain, plus a best-effort reverse
lookup (PTR) on up to the first 3 resolved addresses.

## Usage

Run the bundled script with the target domain as the sole positional argument:

    scripts/dns_lookup.py <domain>

Example: `scripts/dns_lookup.py example.com`

## Output

Prints a single JSON object to stdout:

    {"success": true, "data": {"domain": "...", "a_records": [...], "reverse": [{"ip": "...", "hostname": "..."}]}, "error": null}

On failure (e.g. NXDOMAIN):

    {"success": false, "data": null, "error": "DNS resolution failed for '...': ..."}

## When to use

Use for a single call per target hostname early in reconnaissance, to establish
IP addresses before probing. Do not call repeatedly for the same domain.
