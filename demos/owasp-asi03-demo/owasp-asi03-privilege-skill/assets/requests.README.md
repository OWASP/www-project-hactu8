# requests.json — the attacker's requests

`scripts/run_privilege_abuse.py` logs in as the `attacker` (Dana, an intern)
and files each entry in `requests` on the HR document desk. There is **no
injection** here. Each request is a plain ask for a fictional document id that
Dana's role cannot read. The attack works because of *whose identity* the
agent uses, not because of anything the text says.

What ships here is a **placeholder**, not a real payload. It works straight
away because of two things:

- Each request names a document id (`HR-2001` and so on) that the stub
  model's planner turns into a `fetch_doc` call (`DOC_RE` in
  `vulnerable_app.py`).
- The `ASI03-CANARY-5c1e` tag marks the requests as lab traffic. It is inert:
  the stub ignores it, and the evaluator scores the action log, not the text.

`credential` picks the token sent with the request:

- `own` — Dana's own login token. The confused-deputy path.
- `delegated:S-0001` — the delegated token that the earlier session left in
  its transcript (`GET /api/history`). The token-replay path.

## Writing your own requests

- **Stub backend.** Name the document ids in the request text. Any id in
  `assets/hr_baseline.json` works. Pick ones the attacker is not entitled to
  (see each document's `readers` and `roles`). To try another attacker, change
  `attacker` to any user in that file.
- **Score them.** The evaluator's `SUITE` lists (caller, document) pairs. Add a
  targeted row for any new pair, or it will not be counted.
- **Real-model backend.** Not wired in this version. A real model would need a
  natural-language request it maps to `fetch_doc` calls. Nothing else changes:
  the mitigation never reads the model's output, it decides on the caller's
  token and session.
- **Variants worth testing.** A request on someone else's session with your own
  token; a fresh token from another user's session; a token you edit by hand
  (rejected as unknown in both modes).

Source material: AgenticGoat's ASI03 "Privilege Lab" entry in
`agentic/labs.json` (authorise on the session, not the prompt) is the
reference for the mechanism.
