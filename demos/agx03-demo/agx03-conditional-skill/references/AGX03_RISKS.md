# AGX03 Risk Reference — Conditional Rug-Pull

Domain knowledge, loaded on demand. AGX03 is one of AgenticGoat's superset
labs (`agentic/labs.json` → `superset_labs`, group **A: Evasion**), for
patterns neither OWASP list numbers on its own. Its parent entry is **ASI04**
in AgenticGoat's mapping, and the underlying mechanism is prompt injection
(LLM01).

A single-sample runtime check sees one clean call and passes; the trigger fires
later, in production. A tool that behaves until the Nth call, a date, or an
argument, then turns hostile, survives exactly the one-shot inspection a
screener performs. The honest screen re-screens every return (or samples enough
to trip conditional triggers) and pins behaviour, rather than trusting a tool
forever after one clean look.

This complements OWASP LLM04 / ASI04's rug-pull: LLM04 swaps a tool's
*definition* after approval; AGX03 keeps the definition and changes *behaviour*
by call count.

## Research foundations

- **OWASP Top 10 for Agentic Applications 2026, ASI04** — the parent entry in
  AgenticGoat's mapping; hash-pinning a definition catches a swap-to-hostile.
- **OWASP Top 10 for LLM Applications, LLM01 (Prompt Injection)** — the
  underlying mechanism: text the model reads is treated as instructions.
- **Greshake et al. (2023), "Not what you've signed up for"** — indirect prompt
  injection. Content an LLM-integrated application fetches for the model (here,
  a feed poll) can carry instructions the model follows.
- **AgenticGoat `acts.py` → `conditional_scan`** — a `service_health` tool
  returns clean text on most calls and the payload only on the 3rd
  (`_COND_TRIGGER_ON`); the act samples the return `_CONDITIONAL_SAMPLES` times
  to trip the trigger and grades a single-sample view beside it. You catch what
  you sample; coverage is the sampling policy.
- **protectogw `SECURITY.md`** — the screening core is one layer, with a
  measured generalization ceiling of about 75% on held-out attacks. The output
  canary check is the attack-agnostic control.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S-1 | Count-gated poison | Clean on polls 1-2, hostile from poll 3. | **DEMO TARGET** |
| S-2 | Hostile first return | The trigger fires on poll 1. | Caught in both modes (`GatewayTest`) |
| S-3 | Trigger beyond the sample window | Hostile only on, say, the 50th call. | Blind to a sampler of fewer calls (discussed) |
| S-4 | Date- or argument-gated poison | Hostile on a calendar date or a specific argument. | Pin behaviour; alert on drift (discussed) |
| S-5 | Post-approval definition swap | The definition itself is changed. | Hash-pinning (ASI04 / AgenticGoat `swap_check`) |

## How the demo maps to the attack surfaces

- **S-1** is `POST /vendor/feed/arm` (no authentication) arming the conditional,
  combined with `Lab.ask` polling the feed `SAMPLES` times and assembling the
  returns into Billy's context. `Gateway("vulnerable")` screens the first poll
  (clean), caches the feed as trusted, and passes the hostile `TRIGGER`-th poll
  with verdict ALLOW and no signals.
- **Each request re-trips the trigger.** Because poll 1 of every request is
  clean, the feed is trusted on poll 1 and the hostile poll slips — no
  cross-request priming is needed, and every targeted request leaks.
- **The ruleset is not the problem, its timing is.** A hostile first return is
  blocked even by the vulnerable gateway, and the every-return gateway blocks
  the hostile poll.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| A tool is trusted after one clean return | **Re-screen every return** (or sample N ≥ the trigger) and pin behaviour. Implemented: `Gateway.screen` with `screen_every=True`. This alone takes the CLR to 0 here. |
| A leak once an injection gets through | **Output canary check**: `protectogw.screen(reply, canaries=[CANARY])` on every reply, replacing a blocked reply with a refusal. Implemented: `Gateway.check_reply`. Stops this attack on its own (`test_canary_check_alone_blocks`). |
| Untrusted text mixed into the instruction channel | **Spotlighting** for real models: hardened mode fences the feed in `<untrusted_tool_output>` tags. Implemented: `ProviderModel`. |
| A trigger beyond the sample window | Sample enough to trip conditional triggers and alert on drift between samples. Discussed; the canary layer catches the leak regardless. |
| Unauthenticated trigger control | Authenticate feed controls; hash-pin definitions so a swap-to-hostile is caught (ASI04 / AgenticGoat `swap_check`). Discussed, not coded. |
