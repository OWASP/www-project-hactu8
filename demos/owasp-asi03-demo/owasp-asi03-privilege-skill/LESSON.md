# ASI03 Identity & Privilege Abuse

Setup, commands and architecture are in the [lab README](../README.md); this lesson says what to look for and why.

## What it is

Identity and privilege abuse is an agent acting with authority its caller does not have. The agent holds a broad identity of its own, or a credential left over from someone else, and uses it on behalf of whoever asks. The classic form is the confused deputy: the caller cannot open a door, but the agent can, and the agent opens it for them.

Here the target is "Lamb HR", Big Field Jumper Co.'s HR document agent. Its ground truth is the entitlement table: *an intern may read her own offer letter, a manager may read their report's review, and only HR may read compensation bands and case files.* There is no injection. Dana, an intern, files four plain requests. Three use her own token and ask for documents only HR may read. The fourth replays a delegated token for Morgan that an earlier session (`S-0001`) left in its public transcript. The agent fetches all four with its own service identity, `svc-lamb-hr` (scope `hr:read:all`), and nothing in the answers looks wrong.

## Why it works

The document service is correct: it authorises whatever credential it is shown. The fault is which credential the agent shows it. In vulnerable mode the agent fetches every document as itself, so the service sees `hr:read:all` and releases everything, whoever asked.

Two gaps line up, one per path:

- **Confused deputy.** The agent never carries the caller's identity to the tool call. Dana's own valid token gets her in the door; the agent's token does the rest.
- **Token replay.** In vulnerable mode the agent only checks that a token exists. It does not check expiry, or that the token was issued for the session the request came in on, so an expired delegated token from `S-0001` is still accepted.

A third gap makes the replay possible: `GET /api/history` serves an ended session's transcript, delegated token included, to anyone. Nothing here depends on the model. The planner turns each document id into one `fetch_doc` call and never sees or picks a credential, so the attack is about identity, not wording.

## Try it

Run all four acts with `python run_demo.py` from `demos/owasp-asi03-demo`, or `python -m hactu8 run asi03` from the repo root, or open the lab console (`python vulnerable_app.py`, then <http://127.0.0.1:5303/>). The suite has seven (caller, document) rows: Dana's four targeted rows and three controls where an entitled caller reads their own document.

- **Act 1, clean baseline.** All seven GREEN, Privilege Escalation Rate (PER) 0%. Dana's rows say "not requested"; the controls say "released, agent acted as svc-lamb-hr". Read that line: the agent already uses its service identity for everyone. The controls are GREEN only because the callers happen to be entitled.
- **Act 2, attack.** Dana files four requests ([`assets/requests.json`](assets/requests.json)). There is no payload to read: they are plain asks for document ids, plus an inert canary tag. [`assets/requests.README.md`](assets/requests.README.md) explains the `own` and `delegated:S-0001` credentials.
- **Act 3, impact.** Dana's four rows turn RED, each "released, agent acted as svc-lamb-hr" (PER 100% targeted, 57% overall, 4 of 7). The action log records four releases to a caller who is not entitled. The controls stay GREEN.
- **Act 4, remediation.** The access-review dry run rejects the requests (4 steps denied), and hardened mode brings all seven back to GREEN, PER 0%. Dana's three own-token rows now say "denied: dana is not entitled", the replay says "auth denied: delegated token for morgan has expired", and the controls now say "agent acted as obo:dana", "obo:riley" and "obo:morgan".

On a real model (`--backend ollama --model llama3.2:3b`), the numbers are reported, not asserted. Because there is no injection, a real model plans the same fetches as the stub; in the 2026-11-20 sweep (`docs/evidence/2026-11-20-ollama-llama3.2-3b.md` in the repo, one sample) llama3.2:3b went 0% baseline, 100% targeted impact, 0% hardened.

## The defense, and why it holds

One protection, `delegated_token`, is added in Act 4. It is two controls in [`assets/identity_policy.json`](assets/identity_policy.json), and each closes a different path:

- **On-behalf-of tokens.** The agent exchanges the caller's token for a 2-minute token carrying the caller's identity (scope `hr:read:self`) and fetches with that. The document service then authorises the caller, not the agent, with the same entitlement check it always ran.
- **Short-lived, session-bound tokens.** The agent accepts a token only if it is unexpired and bound to the session the request arrived on. The replayed delegation fails at step 1.

Both are needed. On-behalf-of alone still honours the replayed delegation, because the token really is Morgan's and Morgan may read HR-2002 (PER 25%, `test_obo_alone_leaves_replay_open`). Session binding alone still fetches with the service identity (PER 75%, `test_binding_alone_leaves_confused_deputy_open`). The controls hold whatever the model says, because they decide on the caller's token and session in code; the model never touches a credential.

## Where the defense stops working

- **On-behalf-of is only as good as the entitlement table.** It makes the service authorise the caller; it does not check that the table is right. A document with too broad a `roles` list is released to every holder of that role: the agent does exactly what the table says. Reviewing entitlements is outside the control.
- **Session binding is only as strong as the session id.** The lab does not authenticate who files a request on a session. In hardened mode, a token used within its lifetime together with the session id it was issued for passes the binding: filing Morgan's live token on Morgan's session releases Morgan's documents, logged as Morgan. The shipped replay fails because the leaked token has expired, not because the binding recognises the thief. Sender-constrained (proof-of-possession) tokens are discussed, not coded.
- **The leak stays open.** `GET /api/history` still serves the transcript with the delegated token in hardened mode. Redacting credentials from transcripts and revoking delegations at session end are in the roadmap, not in the code.
- **The service identity still exists.** Hardened mode stops using `hr:read:all` for callers, but the agent still holds it. Any code path that falls back to the service token reopens the confused deputy. Least-privilege service scopes are discussed, not coded.

## Check yourself

1. There is no injection in this lab. What makes Dana's plain requests succeed in Act 3?

   Answer: The agent fetches every document with its own service identity, which has `hr:read:all`, so the document service releases whatever is asked for. The caller's identity never reaches the tool call.
2. Turn off session binding and keep on-behalf-of. Which row turns RED again, and why does on-behalf-of not stop it?

   Answer: The replayed-token row (PER 25%). The replayed delegation is a real token for Morgan, so the on-behalf-of exchange carries Morgan's identity, and Morgan is entitled to HR-2002. Only the expiry and session checks reject it.
3. In hardened mode, an attacker obtains a token that has not expired yet and the id of the session it was issued for. Does session binding stop them?

   Answer: No. The token is valid and bound to that session, and the lab does not authenticate who files on a session. Binding stops cross-session replay of a token, not use of a stolen session; sender-constrained tokens and redacting transcripts address that.

## References

- HACTU8 catalog: skill `asi03`, OWASP `ASI03:2026` Identity & Privilege Abuse (OWASP Top 10 for Agentic Applications); metric PER (Privilege Escalation Rate); protection `delegated_token` (`hactu8/protections.py`).
- Lab material, not repeated here: the [lab README](../README.md) (architecture, "real, not scripted", mapping table) and [`references/ASI03_RISKS.md`](references/ASI03_RISKS.md) (research, scenarios, mitigation roadmap).
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/), entry ASI03.
- Hardy (1988), "The Confused Deputy (or why capabilities might have been invented)".
- RFC 8693, OAuth 2.0 Token Exchange (the on-behalf-of pattern).
- Ported from the predecessor project (retired): its Privilege Lab (`agentic/labs.json`, ASI03): authorise on the session in deterministic code, not in the prompt.
