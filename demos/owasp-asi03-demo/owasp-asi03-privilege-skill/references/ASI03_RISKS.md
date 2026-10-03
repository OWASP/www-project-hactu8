# ASI03 Risk Reference — Identity & Privilege Abuse

Domain knowledge, loaded on demand. Agents act through identities: a service
account, an API key, a token a user delegated. Identity and privilege abuse
happens when an agent's actions run with more authority than the person it is
working for actually has. The agent may use its own broad credential for
everyone, inherit a credential from an earlier task, or accept one that should
have expired. No prompt injection is needed. An ordinary request from a
low-privilege user is enough, because the agent, not the user, is authorised.

## Research foundations

- **Hardy (1988), "The Confused Deputy"** — the classic account of a program
  that holds authority from one party and is tricked into using it for
  another. Billy HR is that deputy.
- **RFC 8693, "OAuth 2.0 Token Exchange"** — the standard on-behalf-of
  exchange: a service trades the caller's token for one that carries the
  caller's identity to the downstream service. Hardened mode does a
  simplified, in-process version.
- **OWASP Top 10 for Agentic Applications, ASI03 Identity & Privilege Abuse**
  — the risk entry this demo targets.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| P-1 | Confused deputy | The agent calls downstream services with its own broad identity, so any caller gets the agent's access. | **DEMO TARGET** |
| P-2 | Delegated-token replay | A token delegated in an earlier session is reused after that session ended, by the agent or by someone who found it. | **DEMO TARGET** |
| P-3 | Tokens in transcripts | Credentials written to logs or shared transcripts where others can read them. | Enabler here (`GET /api/history`) |
| P-4 | Inherited privilege in sub-agents | A spawned agent inherits its parent's full credential instead of a reduced one. | — |
| P-5 | Privilege escalation via tool chaining | Combining permitted tools to reach an action none grants alone. | — (see ASI02) |

## How the demo maps to the attack surfaces

- **P-1** is `Lab._work` in vulnerable mode. It always presents
  `svc-billy-hr` (scope `hr:read:all`) to `DocService.fetch`, which correctly
  releases whatever that credential may read.
- **P-2** is `TokenAuthority.validate` in lax mode: a token only has to exist.
  Morgan's delegated token from session `S-0001` expired long ago and belongs
  to another session, but it is still accepted.
- **The document service is not the bug.** It checks expiry, scope and
  entitlement every time. The failure is in which credential the agent shows
  it.
- **Controls stay GREEN** because entitled callers get their documents in
  both modes. The rate counts only releases to callers who are not entitled.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Agent's own identity used for every caller | **On-behalf-of tokens.** Exchange the caller's token for a short-lived token carrying the caller's identity, and fetch with that. Implemented: `TokenAuthority.exchange_obo`, `on_behalf_of` in `assets/identity_policy.json`. |
| Old or foreign tokens accepted | **Short-lived, session-bound tokens.** Reject expired tokens and tokens bound to another session. Implemented: strict `TokenAuthority.validate`, `session_binding` in the policy. |
| Both needed | OBO alone still honours the replayed delegated token, and binding alone still leaves the service identity in use. The tests prove each gap. |
| Tokens left in transcripts | Redact credentials from logs and transcripts; revoke delegations when the session ends. Not coded here. |
| Broad service scopes | Least-privilege service accounts; no `read:all` scope on an agent that serves end users. Not coded here. |
| No audit | Log the acting identity and the human behind every privileged call. Implemented as the action log's `acting_as` and `session_user` fields. |

Further hardening discussed, not coded: proof-of-possession or sender-
constrained tokens, delegation revocation lists, and per-tool scopes in the
exchanged token.
