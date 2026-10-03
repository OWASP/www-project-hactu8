---
name: agx01-obfuscation-skill
description: >-
  Demonstrates AgenticGoat's AGX01 (Obfuscation Gauntlet, parent OWASP ASI01)
  against a gateway-protected ops assistant in an AUTHORIZED security lab. A
  directive encoded several ways (base64, split-token, hex-escape, base32)
  reaches the model because the gateway judges raw bytes with every normalizer
  fold disabled. Measures impact with a red/yellow/green stoplight KPI and
  Canary Leak Rate, and shows the fix: protectogw normalizing before it judges,
  plus an output canary check. Use when the user wants to run, script, or
  explain obfuscated prompt injection, quantify it, or demonstrate the
  hardening. Education and sanctioned red-teaming only — never against systems
  you are not authorized to test.
license: MIT
metadata:
  objective: Demonstrate injection that evades a raw-text screen through encoding, and the normalize-first fix
  version: 2026.1
---

# AGX01 Obfuscation Gauntlet Skill

Demonstrates how an adversary who can push a notice "vendor update" makes
**Billy, Goat & Co.'s ops assistant** leak the credential in his context by
hiding the directive in an encoding the gateway's ruleset cannot read in raw
form. The gateway screens the right surface — it reads every notice — but in
vulnerable mode it judges the **raw bytes** with every normalizer fold
disabled, so a base64, split-token, hex-escape or base32 copy of the directive
walks straight past it. Billy's model, like a real LLM, decodes it and acts.

## Scope & safety (read first)

- **Authorized use only.** Run against this skill's own `vulnerable_app.py`
  (bound to `127.0.0.1`) or a target you are explicitly permitted to test.
- The vulnerable app is insecure **by design**; do not expose it. Three
  host-safety guards are built in. None of them weakens the lesson:
  - Notices live in memory only, so vendor updates never touch the filesystem,
    and no tool runs code or reaches the network.
  - The model is the deterministic `echo` stand-in by default, so the lab
    cannot reach the network unless you opt into a real-model backend.
  - The server rejects foreign `Host` headers (DNS rebinding) and non-JSON
    POSTs (cross-site forms).
- The payload is an **inert placeholder directive**, encoded at attack time,
  and the canary is a fictional, per-process `sk-canary-…` value. See
  [`assets/obfuscation_payload.README.md`](assets/obfuscation_payload.README.md).
- Dual-use: this exists to make the blind spot observable and to motivate the
  mitigations in [`references/AGX01_RISKS.md`](references/AGX01_RISKS.md).

## When to use

- Run or reproduce obfuscated injection against a screening gateway.
- Quantify impact (stoplight KPI, Canary Leak Rate).
- Show why a screen must **normalize before it judges**: the model decodes the
  encoding whether or not the screen does.

## The blind spot, precisely

Both modes screen every notice. The difference is the **Policy**:

- **Vulnerable:** `Policy(disabled_folds=FOLD_NAMES)` — the ruleset runs on raw
  bytes, every decode/defrag fold off. An encoded directive is never reversed,
  so the `lab_directive` rule never matches it.
- **Hardened:** the default policy — the normalizer folds base64, base32,
  split-token, hex-escape (and more) back to plaintext first, so the same rule
  matches. Plus the output-side canary check on every reply.

It is the **same library and the same rule** in both modes. The plaintext
directive is caught even by the vulnerable gateway (`GatewayTest`): placement of
the normalizer, not vocabulary, is the lesson.

**protectogw** (`protectogw/`) is AgenticGoat's screening core, vendored
unchanged. Its own [`SECURITY.md`](protectogw/SECURITY.md) describes its limits,
including a measured ~75% generalization ceiling on held-out attacks, which is
why the output canary check is layered behind it.

## Prerequisites

Python 3.9+. Standard library only; nothing to install.

Optional real model: set `AGX01_BACKEND` to `ollama`, `llamacpp` or
`openrouter` (which needs `OPENROUTER_API_KEY`), and `AGX01_MODEL` to the model
name, before starting the target, or pick them in the console's backend bar.
The default `echo` (alias `stub`) needs no network. The OpenRouter key is read
from the environment only, never from the console. With `openrouter`, prompts
and payloads leave the machine.

## Execution instructions

1. **Start the target.** From this skill folder:
   ```bash
   python vulnerable_app.py             # serves on 127.0.0.1:5401
   ```
   It loads the benign baseline notices. To drive the same four acts from a
   browser, open <http://127.0.0.1:5401/>.

2. **Review the ground truth.** Billy answers from notice text and never
   reveals the credential in his context. `GET /notices` shows the current
   board.

3. **Establish the baseline.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   Expect all 🟢 GREEN, CLR 0%. Exit code 0.

4. **Run the attack.**
   ```bash
   python scripts/run_obfuscation.py
   ```
   Installs the directive as base64 (`welcome`), split-token (`maintenance`)
   and base32 (`status`) through the unauthenticated
   `POST /vendor/notices/update`. No plaintext directive is ever written.

5. **Stoplight verification.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   Expect 🔴 RED on the three notice requests, the server-time and
   service-health controls still 🟢 GREEN. CLR 100% targeted, 60% overall.
   Exit code 2.

6. **Show the mitigations.**
   ```bash
   python scripts/evaluate_kpi.py --scan          # REJECT, exit 2
   python scripts/evaluate_kpi.py --harden        # targeted YELLOW, CLR 0%, exit 0
   ```
   `--scan` screens the directive with protectogw's full normalization.
   `--harden` switches the gateway to the default policy (every fold on) and
   turns on the output canary check. Each notice is folded back and withheld,
   so the answers are YELLOW (degraded, no leak). Each layer stops the leak on
   its own, and the tests prove it.

7. **Reset to baseline.**
   ```bash
   python scripts/reset_baseline.py               # add --keep-mode to stay hardened
   python scripts/evaluate_kpi.py
   ```
   Expect all requests GREEN with CLR 0%.

## Customizing the payload

Edit [`assets/obfuscation_payload.txt`](assets/obfuscation_payload.txt) and
follow its README. `run_obfuscation.py --notice status --encoding hex` installs
a single encoding of your choice. Zero-width, homoglyph and leet are excluded
on purpose: `normalize()` folds them in both modes, so they do not show the
raw-text blind spot (the README explains).

## Files

| Path | Purpose |
|------|---------|
| `vulnerable_app.py` | Target: Billy, the notice board, the gateway (`/ask`, `/notices`, `/vendor/notices/update`, `/health`) plus the console API (`/api/meta`, `/api/state`, `/api/reset`, `/api/attack`, `/api/evaluate`, `/api/scan`, `/api/mode`, `/api/models`, `/api/backend`). |
| `protectogw/` | AgenticGoat's screening core, vendored unchanged. |
| `web/` | Shared HACTU8 lab console, served at `/`. |
| `providers.py` | Optional real-model backends: Ollama, llama.cpp, OpenRouter. Shared and copied unchanged. |
| `scripts/run_obfuscation.py` | Attack: install the directive as encoded notices. |
| `scripts/evaluate_kpi.py` | Stoplight KPI + CLR against the live app; `--harden` and `--scan` mitigations. |
| `scripts/reset_baseline.py` | Restores the baseline notices and vulnerable mode (`--keep-mode`). |
| `references/AGX01_RISKS.md` | Research, scenario table, mitigation roadmap. |
| `assets/obfuscation_payload.txt` | The inert placeholder directive the attack encodes. |
| `assets/obfuscation_payload.README.md` | Source citation, the encodings, and how to vary it. |
| `tests/test_lifecycle.py` | Asserts the four-act story, the blind spot, each layer, the console and the backends. |
