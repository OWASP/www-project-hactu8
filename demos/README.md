# HACTU8 OWASP demo labs

Self-contained vulnerability labs for the **OWASP Top 10 for LLM Applications**
(2026 numbering) and the **OWASP Top 10 for Agentic Applications**. Each lab
tells the same four-act story against a fixed verification suite:

| Act | What happens | Expected (stub model) |
|-----|--------------|-----------------------|
| 1 — Clean baseline | Run the suite against the untouched target | 🟢 all GREEN, rate 0% |
| 2 — Attack | Apply one small, named adversarial change | target state changes |
| 3 — Impact | Re-run the identical suite | 🔴 targeted items RED, controls stay GREEN |
| 4 — Remediation | Apply the mitigation and re-run | 🟢 back to GREEN, rate 0% |

> ⚠️ **For authorized security education and red-teaming only.** Every target
> is insecure **by design** and binds to `127.0.0.1`. Do not expose it.
> Payloads ship as inert **placeholders** (a marker line plus a fictional
> canary), and each has a README explaining how to write a real one.

## The labs

### OWASP Top 10 for LLM Applications

| ID | Risk | Lab | Port | Metric |
|----|------|-----|------|--------|
| LLM01 | Prompt Injection | [`owasp-llm01-demo`](owasp-llm01-demo/) — an edited wiki page steers the KB assistant through its search tool | 5201 | Injection Success Rate (ISR) |
| LLM02 | Sensitive Information Disclosure | [`owasp-llm02-demo`](owasp-llm02-demo/) — a note on the attacker's own account pulls other customers' records and a key | 5202 | Leak Rate (LR) |
| LLM03 | Excessive Agency | [`owasp-llm03-demo`](owasp-llm03-demo/) — a ticket note triggers unrequested refunds and deletions | 5203 | Unauthorized Action Rate (UAR) |
| LLM04 | Supply Chain | [`owasp-llm04-demo`](owasp-llm04-demo/) — a third-party tool release swaps a description (rug pull) and adds a sleeper | 5204 | Compromised Tool Rate (CTR) |
| LLM05 | Data and Model Poisoning | [`owasp-llm05-demo`](owasp-llm05-demo/) — RAG poisoning and prompt-template backdoor (reference demo; own conventions) | 5101 | Poison Success Rate (PSR) |
| LLM06 | Unbounded Consumption | [`owasp-llm06-demo`](owasp-llm06-demo/) — edited pages cause runaway output, loops and tool storms (simulated cost) | 5206 | Budget Breach Rate (BBR) |
| LLM07 | Misinformation | [`owasp-llm07-demo`](owasp-llm07-demo/) — a community page makes the dev helper recommend a nonexistent package | 5207 | Ungrounded Claim Rate (UCR) |
| LLM08 | Hidden Context Exposure | [`owasp-llm08-demo`](owasp-llm08-demo/) — a saved preference makes the shop assistant quote its system prompt | 5208 | Prompt Leak Rate (PLR) |
| LLM09 | Vector and Embedding Weaknesses | [`owasp-llm09-demo`](owasp-llm09-demo/) — one crafted turn pulls another tenant's documents from a shared store | 5209 | Cross-Tenant Leak Rate (CTLR) |
| LLM10 | Improper Output Handling | [`owasp-llm10-demo`](owasp-llm10-demo/) — model output reaches HTML and SQL sinks unescaped | 5210 | Unsafe Sink Rate (USR) |

### OWASP Top 10 for Agentic Applications

| ID | Risk | Lab | Port | Metric |
|----|------|-----|------|--------|
| ASI01 | Agent Goal Hijack | [`owasp-asi01-demo`](owasp-asi01-demo/) — a ticket comment rewrites the weekly-report plan mid-run | 5301 | Goal Deviation Rate (GDR) |
| ASI02 | Tool Misuse & Exploitation | [`owasp-asi02-demo`](owasp-asi02-demo/) — permitted tools called with unsafe destinations and row counts | 5302 | Unsafe Invocation Rate (UIR) |
| ASI03 | Identity & Privilege Abuse | [`owasp-asi03-demo`](owasp-asi03-demo/) — a confused-deputy agent and a replayed delegated token | 5303 | Privilege Escalation Rate (PER) |
| ASI04 | Agentic Supply Chain Vulnerabilities | [`owasp-asi04-demo`](owasp-asi04-demo/) — a lookalike skill is resolved and loaded at runtime | 5304 | Untrusted Component Load Rate (UCLR) |
| ASI05 | Unexpected Code Execution | _not built — design pending_ | 5305 | — |
| ASI06 | Memory & Context Poisoning | [`owasp-asi06-demo`](owasp-asi06-demo/) — one session plants a memory that later users recall | 5306 | Poison Success Rate (PSR) |
| ASI07 | Insecure Inter-Agent Communication | [`owasp-asi07-demo`](owasp-asi07-demo/) — forged and replayed work orders on an agent bus | 5307 | Forged Message Acceptance Rate (FMAR) |
| ASI08 | Cascading Failures | [`owasp-asi08-demo`](owasp-asi08-demo/) — one wrong price propagates through a three-agent invoice pipeline | 5308 | Propagation Rate (PR) |
| ASI09 | Human-Agent Trust Exploitation | [`owasp-asi09-demo`](owasp-asi09-demo/) — an approval summary understates a batched bank change | 5309 | Misinformed Approval Rate (MAR) |
| ASI10 | Rogue Agents | [`owasp-asi10-demo`](owasp-asi10-demo/) — a tampered mandate turns one worker agent rogue | 5310 | Off-Mandate Action Rate (OMAR) |

## Running a lab

Everything except LLM05 uses the standard library only.

```bash
cd owasp-llm01-demo
python run_demo.py                                  # all four acts in one process

cd owasp-llm01-injection-skill
python vulnerable_app.py                            # target + web console on 127.0.0.1:5201
# open http://127.0.0.1:5201/ (or /#run to play all four acts)
python -m unittest discover tests                   # lifecycle, console and backend tests
```

Each skill folder also has the CLI acts: `scripts/run_<attack>.py`,
`scripts/evaluate_kpi.py` (`--harden`, `--scan`), and `scripts/reset_baseline.py`.
See each lab's README and `SKILL.md`. Every skill folder can be copied into
`.claude/skills/`.

### Real-model backends

The deterministic stub model is the default and the only backend the tests
use. `providers.py` (a port of AgenticGoat's provider layer) adds `ollama`,
`llamacpp` and `openrouter`:

```bash
python run_demo.py --backend ollama --model llama3.2:3b
OPENROUTER_API_KEY=... python run_demo.py --backend openrouter
LLM01_BACKEND=openrouter LLM01_MODEL=... python owasp-llm01-injection-skill/vulnerable_app.py
```

With a real model the numbers are reported, not asserted. Placeholder
payloads are often ignored, so write real ones for meaningful runs. With
`openrouter`, prompts and payloads leave the machine.

## Building a new lab

Start from [`_template/`](_template/). `TEMPLATE.md` is the specification:
- the lifecycle and the stoplight KPI
- the layout and the conventions
- the safety rules
- the web console contract (§12)
- the real-model backend contract (§13)

[`OWASP_DEMO_PLAN.md`](OWASP_DEMO_PLAN.md) records the design of every lab and
how it maps to the [AgenticGoat](https://github.com/Mr-H/AgenticGoat) sources.
[`agenticgoat-mock/`](agenticgoat-mock/) is the earlier one-page lesson mock.
