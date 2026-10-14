# AGX06 Risk Reference — Runtime Result Injection

Domain knowledge, loaded on demand. AGX06 is one of AgenticGoat's superset
labs (`agentic/labs.json` → `superset_labs`, group **B: Hidden channels**),
for patterns neither OWASP list numbers on its own. Its parent entry is
**ASI02, Tool Misuse and Exploitation**, in the OWASP Top 10 for Agentic
Applications 2026.

A tool's definition can pass static review and still return a poisoned value.
The text a tool emits is assembled only when the function runs — it did not
exist at scan time — so a scan of the static definition is structurally blind
to it. The value a tool returns at runtime is untrusted input the client
surfaces to the model like any other.

## Research foundations

- **OWASP Top 10 for Agentic Applications 2026, ASI02 (Tool Misuse and
  Exploitation)** — the parent entry. AgenticGoat's ASI02 lab names poisoned
  tool output among the ways an agent is steered into unsafe behaviour.
- **OWASP Top 10 for LLM Applications, LLM01 (Prompt Injection)** — the
  underlying mechanism: text the model reads is treated as instructions.
- **Greshake et al. (2023), "Not what you've signed up for"** — indirect
  prompt injection. Content an LLM-integrated application surfaces to the
  model (here, a tool's runtime return) can carry instructions the model
  follows as if the user gave them.
- **AgenticGoat `acts.py` → `runtime_watch`** — calls `search_kb("onboarding")`
  for real and re-screens the *return value* as untrusted input, catching an
  HTML-comment payload that did not exist until the call happened — precisely
  why scanning the definition (its Act 1) let it through.
- **protectogw `SECURITY.md`** — the screening core is one layer, with a
  measured generalization ceiling of about 75% on held-out attacks. The
  output canary check is the attack-agnostic control.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S-1 | Payload in a tool's runtime return | A vendor update sets what `search_kb` returns; the injection rides in an HTML comment the definition scan never saw. | **DEMO TARGET** |
| S-2 | Clean static definition | The description a review scans stays clean and approved. | **CONTROL** (shows the gap) |
| S-3 | Payload assembled from fetched content | The tool pulls a document/web page at call time that carries the injection. | Covered (any runtime return) |
| S-4 | Payload in the tool description | The classic tool-poisoning case. A definition scan does catch this one. | — (see AGX04 / ASI04) |
| S-5 | A definition that is never called | No call, no runtime return to screen. | — (static scan's job) |
| S-6 | Conditional runtime payload | The return is poisoned only on inputs this call didn't meet. | — (AGX03 conditional scan) |

## How the demo maps to the attack surfaces

- **S-1** is `POST /vendor/tools/update` (no authentication) setting
  `search_kb.return_text`, combined with `Lab.ask` calling the tool and
  assembling its runtime return into Billy's context. `Gateway("vulnerable")`
  screens surface `tool_definition` only, so the `tool_result` piece passes
  with verdict ALLOW and no signals.
- **A tool has to run to leak.** Only requests that route to `search_kb`
  surface its poisoned return. That is why the server-time and service-health
  controls stay GREEN.
- **The scan is not the problem, its timing is.** The same protectogw call
  blocks the payload the moment it is screened at runtime (`GatewayTest`).

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Runtime returns reach the model unscreened | **Re-screen every runtime return**: treat the value a tool emits as untrusted input and screen it at call time, not just the definition at review time. Implemented: `COVERAGE["hardened"]` adds `tool_result` in `vulnerable_app.py`. |
| A leak once an injection gets through | **Output canary check**: `protectogw.screen(reply, canaries=[CANARY])` on every reply, replacing a blocked reply with a refusal. Implemented: `Gateway.check_reply`. Stops this attack on its own (`test_canary_check_alone_blocks`). |
| Untrusted text mixed into the instruction channel | **Spotlighting** for real models: hardened mode fences tool-host text in `<untrusted_tool_output>` tags. Implemented: `ProviderModel`. |
| Unauthenticated vendor updates | Authenticate and sign tool definitions and the sources they draw returns from; pin a hash at approval (AgenticGoat `swap_check`). Discussed, not coded. |
| A condition this call didn't meet | Exercise the return surface across inputs so the screen sees the payload (AGX03). Discussed, not coded. |
| Ruleset misses a paraphrase | Held-out testing (AGX09) and the canary layer above; protectogw is a filter, not a boundary. |
