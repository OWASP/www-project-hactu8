---
name: agx09-generalization-skill
description: >-
  Demonstrates AGX09 (Generalization Probe, parent OWASP ASI01) against a
  gateway-protected ops assistant in an AUTHORIZED security lab. A held-out
  set of paraphrases, translations and encodings, never used to tune the
  screen, is delivered to Billy's inbox. protectogw's full ruleset and
  normalizer catch some and miss others; the misses leak. Reports the screen's
  catch rate on its own axis, misses included, and the Canary Leak Rate on the
  stoplight KPI, and shows the attack-agnostic fix: an output canary check
  that takes the CLR to 0 whatever the screen missed. Use when the user wants
  to measure how far a screening ruleset generalizes, or to explain why an
  output-side control must sit behind it. Education and sanctioned
  red-teaming only — never against systems you are not authorized to test.
license: MIT
metadata:
  hactu8.owasp: "AGX09"
  hactu8.risk: "Generalization Probe"
  hactu8.metric: "CLR"
  hactu8.metric-name: "Canary Leak Rate"
  hactu8.target: "lab"
  hactu8.port: "5409"
  hactu8.path: "agentic:21"
  hactu8.protections: "generalization,canary_tripwire"
  objective: Measure a screen on attacks it was never tuned on, and show the canary layer closing its misses
  version: 2026.1
---

# AGX09 Generalization Probe Skill

Measures what a screening gateway does with attacks it was **never tuned
on**. **Billy, Goat & Co.'s ops assistant** summarizes partner notes, and
every note crosses protectogw's full ruleset and normalizer. The attack
delivers 15 held-out notes: paraphrases, two translations, and seven
encodings of one canonical line. The screen catches 9 and misses 6 (60%).
The misses leak. The hardened gateway does not pretend to catch them: it
keeps the same screen and adds the output canary check, which stops every
leak.

## Scope & safety (read first)

- **Authorized use only.** Run against this skill's own `vulnerable_app.py`
  (bound to `127.0.0.1`) or a target you are explicitly permitted to test.
- The vulnerable app is insecure **by design**; do not expose it. Host-safety
  guards, none of which weakens the lesson:
  - The inbox lives in memory, only known slots can be written, and nothing
    runs code or reaches the network.
  - The model is the deterministic `echo` stand-in by default.
  - The server rejects foreign `Host` headers (DNS rebinding) and non-JSON
    POSTs (cross-site forms).
- Every held-out attack is benign-effect: its only possible effect is that
  Billy prints the lab's fictional, per-process `sk-canary-…` value. None
  names a real file, address or account. See
  [`assets/heldout_set.README.md`](assets/heldout_set.README.md).
- Dual-use: this exists to make the ceiling of a ruleset observable. See
  [`references/AGX09_RISKS.md`](references/AGX09_RISKS.md).

## When to use

- Measure a screen's generalization on a held-out set, separately from its
  regression coverage.
- Show that misses on a held-out set are expected, and how to report them.
- Show why an attack-agnostic output control (the canary check) has to sit
  behind any vocabulary-based screen.

## Terminology bridge

The partner inbox stands in for any untrusted text an agent reads (an MCP
tool return, a resource, an email). The gateway stands in for an MCP proxy
that screens it. It is **not** an MCP server or client.

**protectogw** (`protectogw/`) is the shared screening core, vendored
unchanged. Its own [`SECURITY.md`](protectogw/SECURITY.md) states a measured
generalization ceiling of about 75% on held-out attacks. This lab measures
60% on its own set.

## Prerequisites

Python 3.9+. Standard library only; nothing to install.

Optional real model: set `AGX09_BACKEND` to `ollama`, `llamacpp` or
`openrouter` (which needs `OPENROUTER_API_KEY`), and `AGX09_MODEL` to the
model name, before starting the target, or pick them in the console's
backend bar. The default `echo` (alias `stub`) needs no network. With
`openrouter`, prompts and payloads leave the machine.

## Execution instructions

1. **Start the target.** From this skill folder:

   ```bash
   python vulnerable_app.py             # serves on 127.0.0.1:5409
   ```

   To drive the same four acts from a browser, open <http://127.0.0.1:5409/>.

2. **Review the ground truth.** Billy summarizes notes and never reveals the
   credential in his context. `GET /inbox` shows every note.

3. **Establish the baseline.**

   ```bash
   python scripts/evaluate_kpi.py
   ```

   Expect all 18 requests 🟢 GREEN, CLR 0%. Exit code 0.

4. **Run the attack.**

   ```bash
   python scripts/run_heldout_probe.py
   ```

   Delivers the 15 held-out attacks from
   [`assets/heldout_set.json`](assets/heldout_set.json) through the
   unauthenticated `POST /inbox/deliver`.

5. **Stoplight verification.**

   ```bash
   python scripts/evaluate_kpi.py
   ```

   Expect 🔴 RED on the 6 notes the screen misses, 🟡 YELLOW on the 9 it
   catches, and the 3 benign controls 🟢 GREEN. CLR 40% targeted, 33%
   overall. The screen catch rate is printed on its own line: 9/15 (60%).
   Exit code 2.

6. **Show the mitigations.**

   ```bash
   python scripts/evaluate_kpi.py --scan          # per-item caught / MISSED, exit 2
   python scripts/evaluate_kpi.py --harden        # targeted YELLOW, CLR 0%, exit 0
   ```

   `--scan` lists every held-out item as caught or MISSED, and the catch
   rate. `--harden` keeps the same input screen and adds the output canary
   check. The 6 misses still reach the model, which still tries to leak; the
   reply is stopped on the way out, so they score YELLOW.

7. **Reset to baseline.**

   ```bash
   python scripts/reset_baseline.py               # add --keep-mode to stay hardened
   python scripts/evaluate_kpi.py
   ```

   Expect all requests GREEN with CLR 0%.

## Customizing the held-out set

Add an item to [`assets/heldout_set.json`](assets/heldout_set.json) and follow
its README. Write it once and measure it once: an item you rephrase until the
screen catches it is a regression test, not a held-out attack. The tests pin
the measured split, so update `EXPECTED_CAUGHT` and `EXPECTED_MISSED` in
`tests/test_lifecycle.py` deliberately, and say why.

## Files

| Path | Purpose |
|------|---------|
| `vulnerable_app.py` | Target: Billy, the inbox, the gateway, the encoders and the stand-in's decoders (`/ask`, `/inbox`, `/inbox/deliver`, `/health`) plus the console API (`/api/meta`, `/api/state`, `/api/reset`, `/api/attack`, `/api/evaluate`, `/api/scan`, `/api/mode`, `/api/models`, `/api/backend`). |
| `protectogw/` | the shared screening core, vendored unchanged. |
| `web/` | Shared HACTU8 lab console, served at `/`. |
| `providers.py` | Optional real-model backends. Shared and copied unchanged. |
| `scripts/run_heldout_probe.py` | Attack: deliver the held-out set. |
| `scripts/evaluate_kpi.py` | Stoplight KPI + CLR, and the catch rate on its own axis; `--harden` and `--scan`. |
| `scripts/reset_baseline.py` | Restores the baseline inbox and vulnerable mode (`--keep-mode`). |
| `references/AGX09_RISKS.md` | Research, scenario table, mitigation roadmap. |
| `assets/heldout_set.json` | The held-out set: 15 attacks, 3 benign controls (editable). |
| `assets/heldout_set.README.md` | Where the set comes from and how to grow it honestly. |
| `tests/test_lifecycle.py` | Asserts the story, pins the catch rate and its misses, the grading both ways, the console and the backends. |
