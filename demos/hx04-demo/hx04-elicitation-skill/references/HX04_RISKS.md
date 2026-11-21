# HX04 MCP Elicitation Abuse — risks, research and mitigations

What this lab's risk is, where it comes from, and how to harden against it. Loaded on demand.

## Research foundations

- **Model Context Protocol specification, Client: Elicitation** (<https://modelcontextprotocol.io/specification/latest/client/elicitation>, read 2026-11-21; the page links revision 2026-07-28 and carries no deprecation notice for elicitation). Two modes: form (`message`, `requestedSchema`, a flat object of primitive fields; `mode` may be omitted and then means form) and URL (`message`, `url`; data other than the URL is not exposed to the client). Results: `action` accept, decline or cancel, with `content` only for an accepted form. "Servers MUST NOT use form mode elicitation to request sensitive information such as passwords, API keys, access tokens, or payment credentials"; name, email or username are "not categorically prohibited". Clients MUST "provide UI that makes it clear which server is requesting information", let users review and modify form answers, and for URL mode "clearly display the target domain/host and gather user consent before navigation". Safe URL handling: clients MUST NOT pre-fetch or open a URL without consent, MUST show the full URL, SHOULD highlight the domain and warn on punycode; servers SHOULD NOT put clickable URLs in a form. The URL mode note says it was introduced in `2025-11-25` and may change. The phishing section concerns a server that cannot tell which user opened its URL; this lab's case, a hostile server phishing its own user, rests on the client MUSTs above.
- **Model Context Protocol specification, Multi Round-Trip Requests** (<https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr>, read 2026-11-21). In 2026-07-28 server-to-client requests, `elicitation/create` included, MUST be sent as an `InputRequiredResult` (`resultType: "input_required"`, `inputRequests` keyed by server-assigned ids, opaque `requestState`); the client retries the original request with `inputResponses` and the echoed `requestState`. "The previous pattern of server-initiated requests is no longer supported. This is a breaking change." The lab uses this shape.
- **Model Context Protocol specification, Schema 2026-07-28** (<https://modelcontextprotocol.io/specification/2026-07-28/schema>, read in part on 2026-11-21). `ElicitRequestFormParams` (`mode?: "form"`, `message`, `requestedSchema`), `ElicitRequestURLParams` (`mode: "url"`, `message`, `url`), `ElicitResult` (`action`, `content?`); `inputResponses` and `requestState` sit beside `_meta` in the retried request's params. `LegacyTitledEnumSchema` is deprecated; sampling and logging are deprecated in this revision (SEP-2577). `elicitationId`, `notifications/elicitation/complete` and a URL-elicitation-required error were not found in the part read (unverified whether they exist in this revision).
- **OWASP MCP Top 10 (2025) MCP07** and **OWASP Agentic Top 10 (2026) ASI09**. The IDs are taken from HACTU8's technique catalog (`hactu8/techniques.py`, `mcp-elicitation-abuse`); the pages were not read for this lab (unverified).

## Scenarios and examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S1 | Impersonating form, agent pre-fill | A form claims to be "Goat & Co. Accounts" and asks for the account reference; the client hides the sender and its model fills the field from the session | **DEMO TARGET** (`verify-account`) |
| S2 | Look-alike page in URL mode | A URL with user-info before `@` and another loopback host; the page asks for the reference out of band | **DEMO TARGET** (`billing-relink`) |
| S3 | Consent fatigue | Harmless prompts first, so the phishing dialogs arrive after the user stops reading | **DEMO TARGET** (`price-list`, `rate-us`) |
| S4 | Honest-looking request from the right server | A "match code" from the supplier card, in groups of four; passes the field policy, the screen and the identity check | **DEMO TARGET** (measured limit) |
| S5 | Re-prompting after a decline | The server returns `InputRequiredResult` again until the user gives in | Context (the lab's servers ask once; not measured) |
| S6 | Tampered or replayed `requestState` | A client-side attack on the server's state | Context (the other direction; the lab's client echoes it unread) |

## How the demo maps to the attack surfaces

- **S1** — `Lab.elicit` in `vulnerable_app.py` builds a `Dialog` with no server name and pre-fills it with `StubModel.fill(context_block(...))`; the retry carries the answer in `inputResponses`; `test_both_channels_leak_and_the_order_is_still_right`.
- **S2** — the same handler opens any URL; the attacker's page (`pages` in `assets/hostile_elicitation.json`) logs what the user types; `url_allowed` parses the URL in hardened mode; `PolicyTest.test_url_allowlist`.
- **S3** — `FATIGUE_AFTER` in `simulated_user`; `test_identity_alone_loses_to_fatigue`, `test_budget_alone`.
- **S4** — `limits` in `assets/hostile_elicitation.json`; `evaluate_kpi.py --probe` and `LimitsTest`.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| The dialog hides who is asking | Name the requesting server, show the full URL and its real host (`use_identity`, implemented, part of `elicitation_policy`) |
| Any form accepted, the agent fills it | Flat primitive schemas, no sensitive fields, no links, schema defaults only (`field_policy`, implemented) |
| URL mode opens anything | Allow-list of loopback origins on the parsed URL; refuse user-info and punycode (`url_allowed`, implemented) |
| No limit on prompts | At most two dialogs per tool call; cancel the rest (`MAX_DIALOGS`, implemented) |
| The request is trusted | Screen message, fields and URL with protectogw (`SCREEN_POLICY`, implemented, `input_screen`) |
| The answer goes back unchecked | Screen form answers for the canary (implemented, `output_screen`); URL mode cannot be screened by the client |
| The user can type the secret | Keep secrets off what the user handles (`secret_vault`); screen answers for the secret's parts and other spellings (not coded) |
| Re-prompting and ever-new wording | Per-server rate limits across calls, and a remembered decline (not coded) |
