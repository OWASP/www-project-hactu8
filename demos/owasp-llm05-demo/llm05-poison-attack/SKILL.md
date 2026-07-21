---
name: llm05-poison-attack
description: >-
  Demonstrates OWASP LLM05 (Data & Model Poisoning) against a vulnerable RAG
  policy bot in an AUTHORIZED security lab. Injects a small set of semantically
  optimized "policy update" documents into a knowledge base, re-queries the
  system, and reports a red/yellow/green stoplight KPI plus a Poison Success Rate.
  Use when the user wants to run, script, or explain a RAG knowledge-base
  poisoning demo, measure poisoning impact, or show the source-scoring
  remediation. For education and sanctioned red-teaming only — never against a
  system you are not authorized to test.
license: MIT
---

# LLM05 Poisoning Skill

Automates **Module 2** of the OWASP LLM05 demo: the adversarial injection that
steers a corporate "Data-Handling Policy Bot" from its ground truth (_"data
exports are strictly prohibited"_) into authorizing prohibited exports — using as
few as **3** documents — then measures the impact and shows the fix.

## Scope & safety (read first)

- **Authorized use only.** Run this against the demo's own vulnerable server
  (`llm05_demo.server`, bound to `127.0.0.1`) or any target you are explicitly
  authorized to test. Do **not** point it at third-party or production systems.
- The technique here (semantic-collision document injection) is dual-use. This
  skill exists to make the vulnerability observable and to motivate the
  mitigations in [`references/LLM05_MAPPING.md`](references/LLM05_MAPPING.md).

## When to use

Trigger this skill when the task is to:
- run or reproduce a RAG data-poisoning demo,
- quantify how injected documents shift model output (Poison Success Rate),
- explain *why* low-volume poisoning works (semantic collision), or
- contrast the vulnerable pipeline with the hardened one.

## Prerequisites

- Python 3.9+.
- For the HTTP path: `pip install requests` and a running target
  (`python -m llm05_demo.server`).
- For the in-process path: the sibling `llm05_demo` package on the path (the
  script finds `../src` automatically).

## Workflow

1. **Confirm authorization and a valid target.** Default target is the local demo
   server at `http://127.0.0.1:5100`. If it isn't running, start it:
   ```bash
   python -m llm05_demo.server
   # macOS: port 5000 is taken by AirPlay Receiver — use another port instead:
   #   LLM05_PORT=5001 python -m llm05_demo.server
   ```
2. **Run the attack + evaluation.** From this skill folder:
   ```bash
   # Against the running vulnerable server (needs `requests`):
   python scripts/run_task.py --target http://127.0.0.1:5100

   # Or fully in-process, no server needed (uses the llm05_demo package):
   python scripts/run_task.py --local
   ```
   The script establishes a clean baseline, injects the adversarial documents
   from [`assets/poisoned-docs.md`](assets/poisoned-docs.md), re-queries, and
   prints the stoplight table and Poison Success Rate.
3. **Interpret the KPI.** 🟢 GREEN = correct/unpoisoned, 🟡 YELLOW = drift,
   🔴 RED = material exposure. A successful demo shows **100% targeted PSR** on
   data-export queries while control topics (MFA, IT approval) stay GREEN — the
   signature of *targeted* steering. See
   [`references/ATTACK_TECHNIQUE.md`](references/ATTACK_TECHNIQUE.md).
4. **Show the remediation.** Re-run the demo's hardened pipeline
   (`python run_demo.py` from the project root, Act 4) to show source scoring and
   anomaly detection returning the system to all-GREEN. Map each defense with
   [`references/LLM05_MAPPING.md`](references/LLM05_MAPPING.md).
5. **Validate the setup** any time with:
   ```bash
   bash scripts/validate.sh
   ```

## Customizing the payload

Edit [`assets/poisoned-docs.md`](assets/poisoned-docs.md) — each fenced block is
one injected document. To keep the collision effective, repeat the target query's
keywords (e.g. `data exports`, `USB drive`, `external storage`). Fewer, denser
documents demonstrate the "poisoning threshold" more starkly.

## Files

| Path | Purpose |
|------|---------|
| `scripts/run_task.py` | Runs the attack (HTTP or in-process) and reports the KPI. |
| `scripts/validate.sh` | Environment + payload self-check. |
| `references/ATTACK_TECHNIQUE.md` | How semantic collision / the poisoning threshold works. |
| `references/LLM05_MAPPING.md` | OWASP LLM05 scenario mapping and mitigations. |
| `assets/poisoned-docs.md` | The adversarial document payload (editable). |
