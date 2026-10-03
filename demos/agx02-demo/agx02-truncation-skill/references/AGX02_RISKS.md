# AGX02 Risk Reference — Truncation Tail

Domain knowledge, loaded on demand. AGX02 is one of AgenticGoat's superset
labs (`agentic/labs.json` → `superset_labs`, group **A: Evasion**), for
patterns neither OWASP list numbers on its own. Its parent entry is **ASI06**
in AgenticGoat's mapping, and the underlying mechanism is prompt injection
(LLM01).

Screening the first N bytes of a return is cheaper than screening all of it —
and blind to everything after N. A model, meanwhile, reads the whole return.
So a directive smuggled into the tail of a long, otherwise boring artifact is
model-visible and scan-invisible at the same time. The only honest screen reads
as much of the artifact as the model will, bounded by a hard cap (and chunked),
not by a cost-saving truncation.

## Research foundations

- **OWASP Top 10 for Agentic Applications 2026, ASI06** — the parent entry in
  AgenticGoat's mapping.
- **OWASP Top 10 for LLM Applications, LLM01 (Prompt Injection)** — the
  underlying mechanism: text the model reads is treated as instructions.
- **Greshake et al. (2023), "Not what you've signed up for"** — indirect prompt
  injection. Content an LLM-integrated application fetches for the model (here,
  a long tool return) can carry instructions the model follows.
- **AgenticGoat `acts.py` → `depth_scan`** — returns ~3.5 kB from an
  `export_log` tool with the payload in the tail, screens the whole artifact,
  and grades a head-only view (`full[:DEPTH_HEAD_LIMIT]`, 800 bytes) beside it
  to make the blind spot concrete. Coverage is bounded by how much it reads.
- **protectogw `SECURITY.md`** — the screening core is one layer, with a
  measured generalization ceiling of about 75% on held-out attacks, and a hard
  input cap (`MAX_INPUT_CHARS`) that whole-artifact screening chunks under. The
  output canary check is the attack-agnostic control.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S-1 | Directive in the tail | ~4 kB of benign log, directive on the last line, past `HEAD_LIMIT`. | **DEMO TARGET** |
| S-2 | Directive in the head | Same directive, but within the first `HEAD_LIMIT` bytes. | Caught in both modes (`GatewayTest`) |
| S-3 | Oversized return | A return far larger than any legitimate artifact. | Alert on outsized returns (discussed) |
| S-4 | Payload split across the window boundary | Half before, half after the read window. | Chunk-and-screen with overlap (discussed) |

## How the demo maps to the attack surfaces

- **S-1** is `POST /vendor/logs/update` (no authentication) replacing the
  `export_log` artifact, combined with `Lab.ask` passing the whole return to
  Billy. `Gateway("vulnerable")` truncates its input to `HEAD_LIMIT` bytes, so
  the tail passes with verdict ALLOW and no signals.
- **The model reads the whole return.** `StubModel` sees the tail the gateway
  skipped, so the directive trips the "emit" + "confirm" rule and leaks.
- **The ruleset is not the problem, its read window is.** A directive placed in
  the head is blocked even by the vulnerable gateway, and the whole-artifact
  gateway blocks the tail.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| The tail of a return is never screened | **Screen the whole artifact**, chunked under a hard input cap rather than truncated to a head sample. Implemented: `Gateway._screen_window` with `chunked=True`; `COVERAGE["hardened"] = CHUNK`. This alone takes the CLR to 0 here. |
| A leak once an injection gets through | **Output canary check**: `protectogw.screen(reply, canaries=[CANARY])` on every reply, replacing a blocked reply with a refusal. Implemented: `Gateway.check_reply`. Stops this attack on its own (`test_canary_check_alone_blocks`). |
| Untrusted text mixed into the instruction channel | **Spotlighting** for real models: hardened mode fences the log in `<untrusted_tool_output>` tags. Implemented: `ProviderModel`. |
| A pathological megabyte burning CPU | **Hard input cap** (`MAX_INPUT_CHARS`) bounds every screen; whole-artifact screening chunks under it. Implemented: `CHUNK = MAX_INPUT_CHARS`. |
| Unauthenticated artifact updates | Authenticate and sign artifact sources; alert on outsized returns. Discussed, not coded. |
| Payload straddling a chunk boundary | Overlap chunks, or screen a normalized concatenation. Discussed; the canary layer catches the leak regardless. |
