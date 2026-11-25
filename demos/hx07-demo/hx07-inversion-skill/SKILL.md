---
name: hx07-inversion-skill
description: >-
  Demonstrates HX07 (Embedding Inversion) against a vulnerable vector store in
  an AUTHORIZED security lab. The store scopes text to each tenant but hands
  out raw embeddings: a partner analytics export returns every tenant's
  vectors, and search returns each hit's vector. A supplier's partner account
  inverts those vectors back to text with a search over characters and
  recovers the staff access reference (a per-run canary) from three staff
  notes it may never read. The embedding is the lab's own toy (hashed
  character n-grams), weaker than a real model, and the lab says so. Measures
  impact with a red/yellow/green stoplight KPI and the Inversion Leak Rate,
  graded from what the attacker rebuilt, and shows layered hardening (no raw
  vectors, per-tenant access control, noise and 8-bit quantisation, an
  ingestion screen) with measured limits: noise too small still leaks, and
  similarity scores alone rebuild a restricted code. Use when the user wants
  to run, script, or explain embedding inversion, quantify it, or demonstrate
  the hardening. Education and sanctioned red-teaming only — never against
  systems you are not authorized to test.
license: MIT
metadata:
  hactu8.owasp: "HX07"
  hactu8.risk: "Embedding Inversion"
  hactu8.metric: "ILR"
  hactu8.metric-name: "Inversion Leak Rate"
  hactu8.target: "lab"
  hactu8.port: "5507"
  hactu8.path: "basics:12"
  hactu8.protections: "vector_privacy,scope_filter,input_screen"
  objective: Demonstrate that leaked embeddings can be inverted back to the text they encode, and layered vector-store hardening that stops it, with its measured limits
  version: 2026.1
---

# HX07 Embedding Inversion Skill

Demonstrates how a vector store leaks text through its vectors, and how to
harden it. Big Field Jumpers Co.'s staff notes live in **Herd Notes**, a vector store
shared with Hoofline Feeds, a supplier with partner access. Text is scoped to
each tenant, so Hoofline never reads a Big Field Jumpers Co. note. Three staff notes hold
one secret: *the staff access reference never leaves Big Field Jumpers Co.'s tenant.* The
partner analytics export returns raw embeddings for every tenant, and the
partner account inverts them back to text, reference included.

## Scope & safety (read first)

- **Authorized use only.** Run against this skill's own `vulnerable_app.py`
  (bound to `127.0.0.1`) or a target you are explicitly permitted to test.
- The vulnerable app is insecure **by design**; do not expose it. Host-safety
  guards are built in. None of them weakens the lesson:
  - The store lives in memory; nothing is fetched, executed or written to
    disk. The embedding is computed in-process (`toy_embedding.py`).
  - The staff access reference is a fictional per-run canary
    (`HX07-CANARY-` + 16 hex digits).
  - Messages are capped at 1,000 characters, searches at 50,000 per lab
    instance, and the inversion at 100,000 search nodes per vector.
  - The model is a deterministic stand-in by default, so the lab cannot reach
    the network unless you opt into a real-model backend.
  - The server rejects foreign `Host` headers (DNS rebinding) and non-JSON
    POSTs (cross-site forms).
- Dual-use: this exists to make the vulnerability observable and to motivate
  the mitigations in [`references/HX07_RISKS.md`](references/HX07_RISKS.md).

## When to use

- Run or reproduce embedding inversion: text rebuilt from vectors a store
  returns, with no access to the text.
- Quantify impact (stoplight KPI, Inversion Leak Rate) from what the attacker
  rebuilt, not from what the assistant said.
- Show the hardening (`vector_privacy`, `scope_filter`, `input_screen`), what
  noise costs retrieval, and where the defenses stop working.

## The toy embedding

`toy_embedding.py` hashes every character 3-, 4- and 5-gram of a note into
4,096 buckets and L2-normalises the counts. It returns the same shape as a
real embedding API (a list of floats compared by cosine), and it is much
easier to invert, because each coordinate counts substrings. A real dense
embedding needs a trained decoder to invert; see the README for the numbers.

## Prerequisites

Python 3.12+. Standard library only; nothing to install.

Optional real model: set `HX07_BACKEND` to `ollama`, `llamacpp` or
`openrouter` (which needs `OPENROUTER_API_KEY`), and `HX07_MODEL` to the model
name, before starting the target, or pick them in the console's backend bar.
The real model only words Lamb's answers; the attack reads the vector API and
never uses the model. The default `echo` (alias `stub`) needs no network. The
OpenRouter key is read from the environment only, never from the console.
With `openrouter`, the staff notes Lamb answers from leave the machine.

## Execution instructions

1. **Start the target.** From this skill folder:

   ```bash
   python vulnerable_app.py             # serves on 127.0.0.1:5507
   ```

   It loads the tenants, accounts and notes from `assets/store.json`. To
   drive the same four acts from a browser, open <http://127.0.0.1:5507/>.

2. **Review the secret.** `assets/store.json`: three Big Field Jumpers Co. notes carry
   `{{CANARY}}`, replaced at start-up by this run's reference. `GET
   /api/state` shows the mode and the layers.

3. **Establish the baseline.**

   ```bash
   python scripts/evaluate_kpi.py
   ```

   Five questions: three staff questions answered from the reference notes,
   a Hoofline delivery question and a shop-hours question. Expect all 🟢
   GREEN, ILR 0%. Exit code 0.

4. **Run the attack.**

   ```bash
   python scripts/run_inversion_attack.py
   ```

   Reads `GET /vectors?account=hoof` as the partner, inverts every vector on
   the attacker's side and prints what it rebuilt, then tells the target the
   attack is running (`POST /api/attack`).

5. **Stoplight verification.**

   ```bash
   python scripts/evaluate_kpi.py
   ```

   Expect 🔴 RED on the three staff questions: the attacker rebuilt the
   reference for each note. Lamb's answers are still right. The two controls
   stay 🟢 GREEN. ILR 100% targeted, 60% overall. Exit code 2.

6. **Show the mitigation.**

   ```bash
   python scripts/evaluate_kpi.py --scan      # notes screened before embedding, exit 2
   python scripts/evaluate_kpi.py --harden    # GREEN, ILR 0%
   python scripts/evaluate_kpi.py --sweep     # noise against inversion and retrieval, exit 0
   python scripts/evaluate_kpi.py --probe     # the score-oracle limit, exit 2
   ```

   `--scan` shows the three reference notes blocked by the lab rules and
   embedded redacted. `--harden` switches on all four layers. `--sweep`
   shows noise too small (sigma 0.01 and below) still leaking, and large noise
   (0.05 and above) costing retrieval. `--probe` climbs a restricted note's
   similarity scores as a helper account, with no vector and no text, and
   rebuilds its code (RED).

7. **Reset to baseline.**

   ```bash
   python scripts/reset_baseline.py
   python scripts/evaluate_kpi.py
   ```

   Expect all questions GREEN with ILR 0%.

## Customizing the payload

Edit [`assets/inversion_attack.json`](assets/inversion_attack.json) and follow
[`assets/inversion_attack.README.md`](assets/inversion_attack.README.md).

## Files

| Path | Purpose |
|------|---------|
| `vulnerable_app.py` | Target vector store and assistant (`/ask`, `/search`, `/vectors`, `/health`), the hardening layers, plus the console API (`/api/meta`, `/api/state`, `/api/reset`, `/api/attack`, `/api/evaluate`, `/api/scan`, `/api/mode`, `/api/models`, `/api/backend`). |
| `toy_embedding.py` | The toy embedding: hashed character n-grams, 4,096 dimensions. |
| `web/` | Shared HACTU8 lab console, served at `/`. |
| `providers.py` | Optional real-model backends. Shared and copied unchanged. |
| `protectogw/` | Screening core. Shared and copied unchanged. |
| `scripts/invert_vectors.py` | The attacker's inversion (from a vector) and score climb (from scores). |
| `scripts/run_inversion_attack.py` | Attack: read the export, invert every vector. |
| `scripts/evaluate_kpi.py` | Stoplight KPI + ILR against the live app; `--harden`, `--scan`, `--sweep` and `--probe`. |
| `scripts/reset_baseline.py` | Restores the notes, stops the attack, vulnerable mode. |
| `references/HX07_RISKS.md` | Research, scenario table, attack surfaces, mitigation roadmap. |
| `assets/store.json` | Tenants, accounts, notes, the limit note and the retrieval probe set. |
| `assets/inversion_attack.json` | The attacker's plan and the score-oracle limit (editable). |
| `assets/inversion_attack.README.md` | How the attack works and how to change it. |
| `tests/test_grading.py` | The attacker-recovered oracle both ways (encoded, partial, grouped digits), YELLOW and GREEN cases. |
| `tests/test_lifecycle.py` | The four-act story, the inversion as a search, each layer alone, the noise trade-off, the screen, the limits, the console API and the real-model seam. |
