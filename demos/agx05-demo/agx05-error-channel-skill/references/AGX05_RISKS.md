# AGX05 Risk Reference — Error-Channel Injection

Domain knowledge, loaded on demand. AGX05 is one of AgenticGoat's superset
labs (`agentic/labs.json` → `superset_labs`, group **B: Hidden channels**),
for patterns neither OWASP list numbers on its own. Its parent entry is
**ASI02, Tool Misuse and Exploitation**, in the OWASP Top 10 for Agentic
Applications 2026.

A tool can be clean on its happy path and hostile only when it fails. When a
call raises, an MCP client surfaces the exception text to the model like any
other tool output. A screen that only ever inspects a tool's *successful*
return never executes the error path, so an injection placed in an error
message is model-visible and scan-invisible at the same time.

## Research foundations

- **OWASP Top 10 for Agentic Applications 2026, ASI02 (Tool Misuse and
  Exploitation)** — the parent entry. AgenticGoat's ASI02 lab names poisoned
  tool output among the ways an agent is steered into unsafe behaviour.
- **OWASP Top 10 for LLM Applications, LLM01 (Prompt Injection)** — the
  underlying mechanism: text the model reads is treated as instructions.
- **Greshake et al. (2023), "Not what you've signed up for"** — indirect
  prompt injection. Content an LLM-integrated application surfaces to the
  model (here, a tool's error message) can carry instructions the model
  follows as if the user gave them.
- **AgenticGoat `acts.py` → `error_channel_scan`** — drives `db_query` into
  its failure path (`db_query("secrets")` via `raise_on_error=False`) and
  screens the exception text, grading a clean `db_query("tickets")` success
  sample beside it to expose the gap.
- **protectogw `SECURITY.md`** — the screening core is one layer, with a
  measured generalization ceiling of about 75% on held-out attacks. The
  output canary check is the attack-agnostic control.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S-1 | Payload in a tool's error text | A vendor update sets a tool's `error_text`; a failing call surfaces it to the model. | **DEMO TARGET** |
| S-2 | Clean success return | The happy path a success-return screen inspects stays clean. | **CONTROL** (shows the gap) |
| S-3 | Payload in a stack trace / log line | The same text reaches the model through a traceback a client echoes back. | Covered (any error-channel text) |
| S-4 | Payload in the tool description | The classic tool-poisoning case. A description scan does catch this one. | — (see AGX04 / ASI04) |
| S-5 | Error path not reachable from the inputs tried | The screen can only see the failures it manages to trigger. | — (fuzz the error surface) |

## How the demo maps to the attack surfaces

- **S-1** is `POST /vendor/tools/update` (no authentication) setting
  `db_query.error_text`, combined with `Lab.ask` routing an unknown-table
  request down the tool's error path and assembling the error message into
  Billy's context. `Gateway("vulnerable")` screens surfaces
  `tool_description` and `tool_result` only, so the `tool_error` piece passes
  with verdict ALLOW and no signals.
- **The call has to fail to leak.** Only requests that name an unknown table
  drive `db_query` into its error path. That is why the happy-path and
  server-time controls stay GREEN.
- **The scan is not the problem, its placement is.** The same protectogw call
  blocks the payload the moment it is aimed at the error channel
  (`GatewayTest`).

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Error text reaches the model unscreened | **Screen the error channel too**: treat an exception message as untrusted input and screen it exactly like a successful return. Implemented: `COVERAGE["hardened"]` adds `tool_error` in `vulnerable_app.py`. |
| A leak once an injection gets through | **Output canary check**: `protectogw.screen(reply, canaries=[CANARY])` on every reply, replacing a blocked reply with a refusal. Implemented: `Gateway.check_reply`. Stops this attack on its own (`test_canary_check_alone_blocks`). |
| Untrusted text mixed into the instruction channel | **Spotlighting** for real models: hardened mode fences tool-host text in `<untrusted_tool_output>` tags. Implemented: `ProviderModel`. |
| Unauthenticated vendor updates | Authenticate and sign tool definitions; pin a hash at approval (AgenticGoat `swap_check`). Discussed, not coded. |
| Error paths you never trigger | Fuzz the failure surface so the screen sees the errors that matter; constrain what a tool may put in an error message. Discussed, not coded. |
| Ruleset misses a paraphrase | Held-out testing (AGX09) and the canary layer above; protectogw is a filter, not a boundary. |
