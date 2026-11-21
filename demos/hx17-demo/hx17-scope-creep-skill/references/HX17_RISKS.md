# HX17 MCP Scope Creep — risks, spec requirements and mitigations

What this lab's risk is, where the requirements come from, and how to harden against it. Loaded on demand.

## Research foundations

- **Model Context Protocol specification, Authorization** (<https://modelcontextprotocol.io/specification/latest/basic/authorization>, read 2026-11-21; the page links revision 2026-07-28). *Scope Selection Strategy*: servers "SHOULD include a `scope` parameter in the `WWW-Authenticate` header" to guide clients "following the principle of least privilege"; clients "SHOULD follow the principle of least privilege by requesting only the scopes necessary for their intended operations", taking the challenge's `scope` first and otherwise "all scopes defined in `scopes_supported`"; `scopes_supported` "is intended to represent the minimal set of scopes necessary for basic functionality", with more "requested incrementally through the step-up authorization flow". *Scope Challenge Handling*: for insufficient scope at runtime the server "SHOULD respond with" `HTTP 403 Forbidden` and `WWW-Authenticate: Bearer error="insufficient_scope", scope="...", resource_metadata="..."`. *Step-Up Authorization Flow*: clients compute "the union of the client's previously requested scope set and the scopes from the current challenge", re-authorize, and retry "no more than a few times"; "Servers MUST account for scope hierarchies, where a broader scope implies narrower ones". *Resource Parameter*: `resource` "MUST be included in both authorization requests and token requests"; servers "MUST validate that access tokens were issued specifically for them as the intended audience".
- **Model Context Protocol, Security Best Practices** (<https://modelcontextprotocol.io/specification/latest/basic/security_best_practices>, read 2026-11-21), *Scope Minimization*. Attack: a token "carrying broad scopes (`files:*`, `db:*`, `admin:*`) that were granted up front because the MCP server exposed every scope in `scopes_supported` and the client requested them all". Risks include "Expanded blast radius", "Privilege chaining: attacker can immediately invoke high-risk tools without further elevation prompts" and "Scope inflation blindness". Mitigation: "Minimal initial scope set", "Incremental elevation via targeted `WWW-Authenticate` `scope=\"...\"` challenges", "Log elevation events". Common mistakes: "Publishing all possible scopes in `scopes_supported`", "Using wildcard or omnibus scopes", "Bundling unrelated privileges to preempt future prompts", "Treating claimed scopes in token as sufficient without server-side authorization logic". The page does not say how a client should decide whether to accept a step-up during a task; this lab's deny-by-default rule is HACTU8's, not the spec's.
- **OAuth 2.0 Bearer Token Usage (RFC 6750) §3.1**, **RFC 8707**, **RFC 9728**: cited by the spec pages above; the RFCs themselves were not re-read for this lab (unverified).
- **OWASP MCP Top 10 (2025) MCP02, OWASP Agentic ASI03**: IDs from HACTU8's technique catalog (`hactu8/techniques.py`); those pages were not read for this lab (unverified).

## Scenarios and examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S1 | Broad scopes up front | The server challenges with `orders:* customers:*`; the client requests what it is told; a parcel question can list every customer | **DEMO TARGET** (Dana) |
| S2 | Rubber-stamped step-up | A narrow token meets `403 insufficient_scope`; the client re-authorizes with the union; the consent page names no scope and the user approves mid-task | **DEMO TARGET** (Ravi) |
| S3 | A coarse write scope | `orders:write`, granted for the customer's own address change, writes any customer's order | **DEMO TARGET** (Mei) |
| S4 | Long-lived tokens reused across tasks | A 30-day wildcard token from an earlier chat answers today's parcel question | **DEMO TARGET** (Kit) |
| S5 | The needed scope is itself too coarse | `orders:read`, the parcel question's own scope, reads another customer's order | **DEMO TARGET** (measured limit) |
| S6 | A stolen broad token | A token leaked from a log or memory carries every scope it was ever granted | Context (spec; HX05 covers token theft) |
| S7 | Repeated elevation loops | A client retries step-up for a denied scope over and over | Context (spec: retry limits, cache failures) |

## How the demo maps to the attack surfaces

- **S1**: `OrdersServer.challenge` and `OrdersServer.metadata` (wildcards), `Lab.connect` (requests the challenge's scope), `covers` (the hierarchy).
- **S2**: `OrdersServer.call` (the 403 and its `WWW-Authenticate`), `Lab.step_up` (the union, the page with no scope), `consent_decision` (approves every page).
- **S3**: `OrdersServer.call` for `update_order` (scope only, no owner), Mei's stored token in `assets/shop.json`.
- **S4**: `Lab.reset` (seeded 30-day tokens), `Lab._stored` (one token per customer, reused).
- **S5**: `OrdersServer.call` for `get_order` (no owner check on reads), `hostile_tracker.json` `limits`.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Wildcard scopes requested up front | The client requests the task's scopes; the server publishes a minimal `scopes_supported` and challenges with the operation's own scope (implemented: `least_privilege_scope`, `Lab.connect`, `OrdersServer.challenge`) |
| Long-lived tokens reused across tasks | A fresh token per task, 5-minute lifetime, bound to the server's `resource`, discarded when the task ends, scoped down per call; the server refuses tokens with a longer lifetime or another audience (implemented: `delegated_token`, `AuthServer.exchange`) |
| Rubber-stamped step-up | The page names the exact new scope and the reason; a scope outside the task's own scopes is denied by default during the task (implemented: `step_up_consent`, `Lab.step_up`) |
| A scope that covers any customer's record | Check ownership on the server for every write (implemented: `action_policy`) and every read (not in hardened mode; the tests measure it as the fix for the limit), or finer-grained authorization than a scope string (discussed, not coded) |
| Elevation loops, audit noise | Log elevation events with the scope requested and granted; cache denied scopes; cap retries (partly: one retry, events logged; no cache) |
| Text in tool results that steers the model | Screening tool results (protectogw passes the shipped lines: `--scan`), spotlighting; one layer, not the boundary (discussed, not coded here) |
