---
name: owasp-llm05-poisoning-skill
description: >-
  Demonstrates OWASP LLM05 (Data & Model Poisoning) against a vulnerable RAG
  financial-advisor app in an AUTHORIZED security lab. Covers Scenario #1 (RAG
  knowledge-base poisoning via unauthenticated ingestion) and Scenario #6
  (prompt-template and GGUF artifact tampering with a trigger-gated backdoor), then
  measures impact with a red/yellow/green stoplight KPI and Poison Success Rate,
  and shows the source-scoring and artifact-static-analysis mitigations. Use when
  the user wants to run, script, or explain RAG poisoning or prompt-template
  backdoors, quantify poisoning impact, or demonstrate the hardening. Education
  and sanctioned red-teaming only — never against systems you are not authorized
  to test.
license: MIT
metadata:
  objective: Demonstrate RAG Knowledge Base and Artifact Poisoning (Scenario #1 & #6)
  version: 2026.1
---

# OWASP LLM05 Poisoning Skill

Demonstrates how an adversary steers a RAG-based **financial compliance advisor**
away from ground truth — either by poisoning its knowledge base (Scenario #1) or by
tampering with its prompt-template artifact (Scenario #6) — and how to detect and
harden against both.

## Scope & safety (read first)

- **Authorized use only.** Run against this skill's own `vulnerable_app.py` (bound
  to `127.0.0.1`) or a target you are explicitly permitted to test.
- The vulnerable app is insecure **by design**; do not expose it. Two host-safety
  guards are built in and do not weaken the lesson: ingest filenames are confined
  to `knowledge_base/`, and prompt templates render in a Jinja2 **sandbox** so a
  tampered template can bias output but cannot execute code.
- Dual-use: this exists to make the vulnerability observable and to motivate the
  mitigations in [`references/LLM05_RISKS.md`](references/LLM05_RISKS.md).

## When to use

- Run or reproduce a RAG knowledge-base poisoning demo (Scenario #1).
- Demonstrate a prompt-template trigger backdoor (Scenario #6).
- Quantify poisoning impact (stoplight KPI, Poison Success Rate).
- Show the mitigations: source scoring, and artifact static analysis
  (SHA-256 pinning + Jinja2/SSTI scanning).

## MCP terminology bridge

MCP servers expose **tools**, **resources**, and **prompts**. MCP prompts are
reusable, parameterized message templates returned by a server. This skill's
`assets/prompt_template.json` is a simpler application-side Jinja2 template: it
assembles the system instruction, retrieved context, and user query, but it is not
an MCP prompt or an MCP server. A production MCP client may use an MCP prompt and
then apply a separate model-specific chat template before inference.

## Prerequisites

```bash
pip install -r requirements.txt        # flask, requests (jinja2 ships with flask)
```

## Execution instructions

1. **Start the target.** From this skill folder:
   ```bash
   python vulnerable_app.py
   # macOS: port 5000 is AirPlay Receiver — use another port:
   #   LLM05_PORT=5101 python vulnerable_app.py   (then pass --target http://127.0.0.1:5001)
   ```
   On startup it seeds the legitimate "Ground Truth" compliance policy.

2. **Corpora review.** Inspect `knowledge_base/` to confirm the high-impact ground
   truth (offshore due diligence, wire-transfer authorization, fraud flagging) —
   the policy most damaging to override.

3. **Establish the baseline.** Before attacking, measure a clean run:
   ```bash
   python scripts/evaluate_kpi.py --target http://127.0.0.1:5101
   ```
   Expect all 🟢 GREEN, PSR 0%.

4. **Adversarial generation + injection.**
   ```bash
   # Scenario #1 (RAG) + Scenario #6 (template) in one shot:
   python scripts/run_poisoning.py --target http://127.0.0.1:5101 --scenario all --count 5
   ```
   Scenario #1 injects 5 semantically optimized documents built from
   [`assets/poison_template.txt`](assets/poison_template.txt) (repeat domain terms
   like "official", "verified", "offshore" for high retrievability). Scenario #6
  installs [`assets/prompt_template.json`](assets/prompt_template.json), a tampered
   template with a dormant backdoor keyed on the phrase **"quarterly audit"**.

5. **Stoplight verification.** Re-measure:
   ```bash
   python scripts/evaluate_kpi.py --target http://127.0.0.1:5101
   ```
   Expect 🔴 RED on the offshore/wire queries (RAG drift) and on the "quarterly
   audit" query (template backdoor), with the off-topic control staying GREEN.
   Read the delta between ground truth and the poisoned narrative in the PSR.

6. **Show the mitigation (Scenario #6).** Run the artifact static analysis that
   the hardening roadmap prescribes:
   ```bash
  python scripts/evaluate_kpi.py --scan-prompt-template assets/prompt_template.json
   ```
   It emits the SHA-256 to pin and flags the conditional/instruction-injection
   markers — rejecting the tampered template before it is ever installed.

7. **Reset to baseline.** After the attack, clean the generated RAG documents and
  restart the target so its in-memory prompt template returns to the baseline:
  ```bash
  python scripts/reset_baseline.py
  # Stop the running app with Ctrl+C, then start it again:
  LLM05_PORT=5101 python vulnerable_app.py
  python scripts/evaluate_kpi.py --target http://127.0.0.1:5101
  ```
  Expect all queries to be GREEN with PSR 0%.

## Files

| Path | Purpose |
|------|---------|
| `vulnerable_app.py` | Target RAG financial advisor (ingest + template + query endpoints). |
| `scripts/run_poisoning.py` | Attack: Scenario #1 RAG injection and/or Scenario #6 template tampering. |
| `scripts/evaluate_kpi.py` | Stoplight KPI + PSR against the live app; `--scan-template` mitigation. |
| `scripts/reset_baseline.py` | Removes generated poison documents and prepares a clean baseline run. |
| `references/LLM05_RISKS.md` | Threat landscape, research citations, scenario table, mitigations. |
| `assets/poison_template.txt` | Adversarial RAG document template (editable). |
| `assets/prompt_template.json` | Tampered prompt template with a trigger-gated backdoor. |
