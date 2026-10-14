# AGX04 Risk Reference — Schema / Parameter Injection

Domain knowledge, loaded on demand. AGX04 is one of AgenticGoat's superset
labs (`agentic/labs.json` → `superset_labs`, group **B: Hidden channels**),
for patterns neither OWASP list numbers on its own. Its parent entry is
**ASI02, Tool Misuse and Exploitation**, in the OWASP Top 10 for Agentic
Applications 2026.

A tool is more than its description. When a client lists tools, the model
sees each tool's whole definition, including the JSON Schema of its
parameters: parameter descriptions, titles, enum values and defaults. The
model reads that text to decide how to call the tool. A scan that reads only
the tool description misses all of it, so an injection placed in a parameter
default is model-visible and scan-invisible at the same time.

## Research foundations

- **OWASP Top 10 for Agentic Applications 2026, ASI02 (Tool Misuse and
  Exploitation)** — the parent entry. AgenticGoat's ASI02 lab names poisoned
  tool descriptors and parameter pollution as the ways an agent is steered
  into unsafe calls.
- **OWASP Top 10 for LLM Applications, LLM01 (Prompt Injection)** — the
  underlying mechanism: text the model reads is treated as instructions.
- **Greshake et al. (2023), "Not what you've signed up for"** — indirect
  prompt injection. Content an LLM-integrated application fetches for the
  model (here, tool metadata from a tool host) can carry instructions that
  the model follows as if the user gave them.
- **AgenticGoat `acts.py` → `schema_scan`** — walks every tool's input
  schema (`_schema_strings`: description, title, enum, default) and screens
  each string. Its ground truth marks `ticket_lookup`'s tool description
  clean and its parameter schema poisoned.
- **protectogw `SECURITY.md`** — the screening core is one layer, with a
  measured generalization ceiling of about 75% on held-out attacks. The
  output canary check is the attack-agnostic control.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S-1 | Payload in a parameter default | A vendor update sets a parameter's `default` to an instruction; the description stays clean. | **DEMO TARGET** |
| S-2 | Payload in an enum value | The same text appended to a parameter's `enum` list (AgenticGoat's AGX04 practice). | **DEMO TARGET** (`--field enum`, tested) |
| S-3 | Payload in a parameter description | AgenticGoat's live `ticket_lookup` places it in the parameter `description`. | Covered (`--field description`) |
| S-4 | Payload in the tool description | The classic tool-poisoning case. The naive gateway does catch this one. | — (see LLM04 / ASI04) |
| S-5 | Post-approval definition swap | A clean definition is approved, then changed. | — (AgenticGoat `swap_check`, hash pinning) |
| S-6 | Parameter pollution at call time | Hostile argument values, not schema text. | — (schema validation at call time) |

## How the demo maps to the attack surfaces

- **S-1** is `POST /vendor/tools/update` (no authentication) writing
  `ticket_lookup.ticket_id.default`, combined with `Lab.ask` assembling the
  tool's definition into Billy's context. `Gateway("vulnerable")` screens
  surfaces `tool_description` and `tool_result` only, so the
  `schema_param` piece passes with verdict ALLOW and no signals.
- **Routing decides the blast radius.** Only requests that route to
  `ticket_lookup` read its schema. That is why the server-time and service
  health controls stay GREEN.
- **The scan is not the problem, its placement is.** The same protectogw
  call blocks the payload the moment it is aimed at the schema field
  (`GatewayTest`).

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Schema fields reach the model unscreened | **Screen every model-visible field**: description, parameter descriptions, titles, enums, defaults. Implemented: `COVERAGE["hardened"]` in `vulnerable_app.py`, `schema_strings()` mirrors AgenticGoat's `_schema_strings`. |
| A leak once an injection gets through | **Output canary check**: `protectogw.screen(reply, canaries=[CANARY])` on every reply, replacing a blocked reply with a refusal. Implemented: `Gateway.check_reply`. Stops this attack on its own (`test_canary_check_alone_blocks`). |
| Untrusted text mixed into the instruction channel | **Spotlighting** for real models: hardened mode fences tool-host text in `<untrusted_tool_output>` tags. Implemented: `ProviderModel`. |
| Unauthenticated vendor updates | Authenticate and sign tool definitions; pin a hash at approval (AgenticGoat `swap_check`). Discussed, not coded. |
| Malicious or polluted arguments | Validate parameters against a strict schema at call time; allowlist tools and their argument shapes (AgenticGoat AGX04 remediations). Discussed, not coded. |
| Ruleset misses a paraphrase | Held-out testing (AGX09) and the canary layer above; protectogw is a filter, not a boundary. |
