# HX05 OAuth Confused Deputy (MCP) — risks, spec requirements and mitigations

What this lab's risk is, where the requirements come from, and how to harden against it. Loaded on demand.

## Research foundations

- **Model Context Protocol specification, Authorization** (<https://modelcontextprotocol.io/specification/latest/basic/authorization>, read 2026-11-21; the page is revision 2026-07-28). A protected MCP server is an OAuth 2.1 resource server and an MCP client an OAuth 2.1 client. Clients obtain a client ID by Client ID Metadata Documents, pre-registration or Dynamic Client Registration (RFC 7591, now deprecated). The `resource` parameter (RFC 8707) "MUST be included in both authorization requests and token requests" and must identify the MCP server. "MCP servers MUST validate that access tokens were issued specifically for them as the intended audience"; "MCP servers MUST only accept tokens that are valid for use with their own resources"; "MCP servers MUST NOT accept or transit any other tokens."
- **Model Context Protocol, Authorization Security Considerations** (<https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations>, read 2026-11-21). Clients "MUST implement PKCE" and "MUST use the `S256` code challenge method when technically capable". "Authorization servers MUST validate exact redirect URIs against pre-registered values." "MCP proxy servers using static client IDs MUST obtain user consent for each dynamically registered client before forwarding to third-party authorization servers." "The MCP server MUST NOT pass through the token it received from the MCP client."
- **Model Context Protocol, Security Best Practices** (<https://modelcontextprotocol.io/specification/latest/basic/security_best_practices>, read 2026-11-21). *Confused Deputy Problem*: vulnerable when the proxy uses a static client ID, allows dynamic registration, the third-party server sets a consent cookie, and the proxy lacks per-client consent; the attacker's crafted link and malicious `redirect_uri` deliver the MCP authorization code to the attacker. Required protections: a per-user registry of approved `client_id` values checked before the third-party flow; a consent page naming the client, the scopes and the registered `redirect_uri`, with CSRF and anti-framing protection; consent cookies with the `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Lax`, signed and bound to the `client_id`; exact string matching of `redirect_uri`; a single-use, short-lived `state` set only after consent. *Token Passthrough*: accepting tokens not issued to the server and forwarding them downstream; mitigation "MCP servers MUST NOT accept any tokens that were not explicitly issued for the MCP server." The same page notes that Dynamic Client Registration is deprecated as of 2026-07-28 and that "the attack still applies to MCP proxy servers that support it", and, under *Localhost Redirect URI Impersonation*, that "the user will see the legitimate client's name".
- **RFC 7636 (PKCE)**: the S256 transform the lab implements, and the worked example its test checks, are from memory; the RFC was not re-read for this lab (unverified).
- **OWASP MCP Top 10 (2025) MCP01 and MCP07, OWASP Agentic ASI03, MITRE ATLAS AML.T0091.000**: IDs from HACTU8's technique catalog (`hactu8/techniques.py`); those pages were not read for this lab (unverified).

## Scenarios and examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S1 | Consent-cookie confused deputy | A dynamically registered client with the attacker's redirect; a mailed link; the third party's cookie skips consent; the code goes to the attacker | **DEMO TARGET** (Dana) |
| S2 | Code interception through a loose redirect | A tool result makes the agent reconnect with a `redirect_uri` that starts with the registered one; prefix matching passes; no PKCE lets the attacker redeem | **DEMO TARGET** (Ravi) |
| S3 | Token passthrough to a downstream | The proxy forwards the client's token unchanged to a downstream connector the attacker runs | **DEMO TARGET** (Mei) |
| S4 | A client that looks like the real one | A registration under the real client's name; the user approves the consent page | **DEMO TARGET** (measured limit) |
| S5 | Consent bypass by `state` handling | The `state` cookie set before consent lets a crafted request skip the proxy's consent page | Context (spec; the lab sets no state cookie) |
| S6 | Mix-up attack | A malicious authorization server receives a code issued by an honest one; PKCE does not help, `iss` validation does | Context (spec; one authorization server here) |

## How the demo maps to the attack surfaces

- **S1**: `LedgerProxy.register` (open registration), `LedgerProxy.authorize` (no consent registry in vulnerable mode), `Pasture.authorize` (the consent cookie), `Hayloft.phish` and `Hayloft.deliver`.
- **S2**: `Hayloft.chart_tool` (the appended line), `StubModel.decide`, `Lab.connect` with the tampered URI, the prefix test in `LedgerProxy.authorize`, the missing verifier check in `LedgerProxy.token`, `Browser.follow` (path normalisation).
- **S3**: `LedgerProxy.token` returning the Pasture token, `LedgerProxy.call_tool` accepting any Pasture token and forwarding the bearer in `share_statement`, `Hayloft.connector_request`.
- **S4**: `consent_decision` (name and host, not path), `hostile_oauth.json` `limits`.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| No per-client consent behind a static client ID | Per-user registry of approved `client_id` values, checked before forwarding; the proxy's own consent page (implemented: `per_client_consent`, `LedgerProxy.authorize`) |
| Prefix or pattern redirect matching | Exact string match with a registered URI; re-registration to change it (implemented: `exact_redirect_uri`) |
| Codes redeemable by anyone | PKCE S256 required at authorize and verified at token (implemented: `pkce`) |
| Token passthrough, no audience check | Proxy-minted tokens for its own `resource` only; upstream token kept server-side; a separate token per downstream (implemented: `audience_binding`; the downstream token is a stand-in for a token exchange) |
| Consent page a hurried user approves | Show the full `redirect_uri` prominently, warn on a new client with a known name, prefer Client ID Metadata Documents with domain trust policies (discussed, not coded) |
| `state` and cookie handling | Single-use, short-lived `state` set only after consent; `__Host-` signed consent cookies bound to `client_id`; CSRF tokens and `frame-ancestors` on the consent page (discussed, not coded) |
| Mix-up | Record the issuer and validate `iss` in the authorization response (RFC 9207) (discussed, not coded) |
