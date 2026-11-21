# HX16 — Shadow MCP Server: sources, scenarios, mitigation roadmap

Background for the HX16 skill: what the sources say, which scenarios the lab
covers, and how each gap maps to code. Loaded on demand.

## Research foundations

Only what was read for this lab is cited; anything else is marked
unverified.

- **OWASP MCP Top 10 (beta), `MCP09:2025` Shadow MCP Servers** —
  <https://owasp.org/www-project-mcp-top-10/> and the entry at
  <https://github.com/OWASP/www-project-mcp-top-10/blob/165fe0f78ef104459237b4a8e0f6e78db9b02391/2025/MCP09-2025%E2%80%93Shadow-MCP-Servers.md>
  (read 2026-11-21). The project page says it is in its beta phase. The
  entry defines shadow servers as "unapproved or unsupervised deployments
  of Model Context Protocol instances", names data exposure among the
  impacts, and lists mitigations, among them a central registry where
  every instance is registered before deployment, automated discovery
  scans with alerts, approved baseline configuration templates, central
  IAM, monitoring for configuration drift, and an incident workflow on
  detection. Its example scenarios (an indexed test instance, an exploited
  outdated server, contaminated plugins, poisoned connectors) are not the
  scenario coded here.
- **Model Context Protocol, Security Best Practices** —
  <https://modelcontextprotocol.io/specification/latest/basic/security_best_practices>
  (read 2026-11-21). "Local MCP Server Compromise" covers servers installed
  "through a client's configuration flows" and an attacker who "includes a
  malicious 'startup' command in a client configuration"; a client with
  one-click configuration MUST show the exact command and require explicit
  approval, and SHOULD sandbox servers with restricted network access. The
  SSRF section recommends egress proxies that restrict the client's
  outbound access. The page has no section on shadow servers, on
  discovery, or on tool name collisions across servers.
- **MITRE ATLAS** (`atlas-data` `dist/ATLAS.yaml`, version 5.6.0, read
  2026-11-21): `AML.T0010.005` AI Supply Chain Compromise: AI Agent Tool
  (adversaries target agent tools, including MCP servers, to compromise the
  AI supply chain) and `AML.T0074` Masquerading (an object's name or
  location manipulated so it appears legitimate). The file itself carries
  a notice that this copy of the data is deprecated in favour of newer
  releases in the same repository.
- **OWASP Top 10 for Agentic Applications, `ASI04:2026`** — taken from
  HACTU8's technique catalog; not read for this lab (unverified).

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S1 | Config entry added by hand | An employee adds an unapproved server to the client config | **DEMO TARGET** |
| S2 | Server found by local discovery | A server announces itself, under an approved name, and the client connects | **DEMO TARGET** |
| S3 | Same-name tool collision | A later server's tool replaces an approved tool of the same name | **DEMO TARGET** |
| S4 | Lookalike tool name | `get-order-status` beside `get_order_status`, reworded | **DEMO TARGET** |
| S5 | Duplicate capability | `email_receipt` does what `send_receipt` does | **DEMO TARGET** |
| S6 | Approved server swapped in place | Same URL, id and definitions; a logging build behind it | **DEMO TARGET** (the limit) |
| S7 | Unprotected test instance found by others | MCP09's internal-exposure scenario | context |
| S8 | Malicious startup command in a config | Best practices page, Local MCP Server Compromise | context (see the code-execution labs) |
| S9 | Poisoned tool description | An instruction in a tool's text | context (the tool-poisoning labs) |
| S10 | Rug pull of an approved tool | A new version changes a definition | context (LLM04, hash pins) |

## How the demo maps to the attack surfaces

- **S1** — `config_edit` in `assets/shadow_server.json`, appended to
  `Lab.config["servers"]` without a new signature; `Lab.session` loads it.
- **S2** — `discovery`, announced on `Discovery.announcements`; the config
  has `auto_discover: true`, and `Lab.session` adds every announcement.
- **S3** — the merge in `Lab.session`: `merged[name] = ...`, later servers
  win.
- **S4, S5** — `StubModel.choose` scores tools by word occurrences in name
  and description; the shadow descriptions repeat the request's words.
- **S6** — `Lab.load_limit("swap-at-same-url")`, measured by
  `evaluate_kpi.py --probe` and `LimitsTest`.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|-------------------|
| Unsigned client config | Sign the config; reject an edit with a bad signature (`signed_config`, `verify_config` in `vulnerable_app.py`) |
| Any server is used | Server inventory keyed on id, URL and publisher (`provenance`, `INVENTORY`) |
| Tools merged by name | Route approved names to their home server; refuse lookalikes (`exact_name`, `MANIFEST`, `fold_name`) |
| Duplicate tools offered | Overlap alert and quarantine (`capability_overlap`, `overlap`, threshold 0.5) |
| Any URL reachable | Egress inventory in the transport (`egress_allowlist`, `EGRESS`) |
| Approved server swapped in place | Server authentication bound to the approved deployment, recorded in the inventory; not coded |
| Discovery itself | Turn auto-discovery off in the signed config, or limit it to announcements signed by IT; not coded |
| Drift over time | MCP09's discovery scans and configuration-drift monitoring; not coded |
| Startup commands in configs | Consent showing the exact command and a sandbox, per the best practices page; not coded here |
