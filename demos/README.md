# HACTU8 OWASP demo labs

Self-contained vulnerability labs for the **OWASP Top 10 for LLM Applications**
(2026 numbering) and the **OWASP Top 10 for Agentic Applications**. Each lab
tells the same four-act story against a fixed verification suite:

| Act | What happens | Expected (echo model) |
|-----|--------------|-----------------------|
| 1 — Clean baseline | Run the suite against the untouched target | 🟢 all GREEN, rate 0% |
| 2 — Attack | Apply one small, named adversarial change | target state changes |
| 3 — Impact | Re-run the identical suite | 🔴 targeted items RED, controls stay GREEN |
| 4 — Remediation | Apply the mitigation and re-run | 🟢 back to GREEN, rate 0% |

> ⚠️ **For authorized security education and red-teaming only.** Every target
> is insecure **by design** and binds to `127.0.0.1`. Do not expose it.
> Payloads are **benign-effect**: realistic injection wording whose only
> possible effect is emitting a fictional canary or calling a simulated tool on
> loopback. Each has a README explaining how it works.

## The labs

### OWASP Top 10 for LLM Applications

| ID | Risk | Lab | Port | Metric |
|----|------|-----|------|--------|
| LLM01 | Prompt Injection | [`owasp-llm01-demo`](owasp-llm01-demo/) — an edited wiki page steers the KB assistant through its search tool | 5201 | Injection Success Rate (ISR) |
| LLM02 | Sensitive Information Disclosure | [`owasp-llm02-demo`](owasp-llm02-demo/) — a note on the attacker's own account pulls other customers' records and a key | 5202 | Leak Rate (LR) |
| LLM03 | Excessive Agency | [`owasp-llm03-demo`](owasp-llm03-demo/) — a ticket note triggers unrequested refunds and deletions | 5203 | Unauthorized Action Rate (UAR) |
| LLM04 | Supply Chain | [`owasp-llm04-demo`](owasp-llm04-demo/) — a third-party tool release swaps a description (rug pull) and adds a sleeper | 5204 | Compromised Tool Rate (CTR) |
| LLM05 | Data and Model Poisoning | [`owasp-llm05-demo`](owasp-llm05-demo/) — injected policy docs, a trigger-gated prompt template and a poisoned agent cache steer the financial compliance assistant | 5205 | Poison Success Rate (PSR) |
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
| ASI05 | Unexpected Code Execution | [`owasp-asi05-demo`](owasp-asi05-demo/) — a sheet note makes the agent's snippets import os and read the vault canary at a code sink (simulated) | 5305 | Unsafe Execution Rate (UER) |
| ASI06 | Memory & Context Poisoning | [`owasp-asi06-demo`](owasp-asi06-demo/) — one session plants a memory that later users recall | 5306 | Poison Success Rate (PSR) |
| ASI07 | Insecure Inter-Agent Communication | [`owasp-asi07-demo`](owasp-asi07-demo/) — forged and replayed work orders on an agent bus | 5307 | Forged Message Acceptance Rate (FMAR) |
| ASI08 | Cascading Failures | [`owasp-asi08-demo`](owasp-asi08-demo/) — one wrong price propagates through a three-agent invoice pipeline | 5308 | Propagation Rate (PR) |
| ASI09 | Human-Agent Trust Exploitation | [`owasp-asi09-demo`](owasp-asi09-demo/) — an approval summary understates a batched bank change | 5309 | Misinformed Approval Rate (MAR) |
| ASI10 | Rogue Agents | [`owasp-asi10-demo`](owasp-asi10-demo/) — a tampered mandate turns one worker agent rogue | 5310 | Off-Mandate Action Rate (OMAR) |

### HACTU8 extensions (AGX)

These patterns sit beyond both OWASP lists. The numbering is HACTU8's own.
Each is a **gateway lab**: a screening gateway built on
[protectogw](_template/protectogw/), HACTU8's screening core, sits between
untrusted text and the model.

- **Vulnerable mode:** protectogw with one blind spot.
- **Hardened mode:** protectogw with full coverage, plus a check that no fake
  credential appears in the model's output.

The metric is the Canary Leak Rate (CLR).

| ID | Group | Lab | Port | What the vulnerable gateway misses |
|----|-------|-----|------|------------------------------------|
| AGX01 | Evasion | [`agx01-demo`](agx01-demo/): Obfuscation Gauntlet | 5401 | encoded text (it screens raw bytes, with no de-obfuscation folds) |
| AGX02 | Evasion | [`agx02-demo`](agx02-demo/): Truncation Tail | 5402 | the tail of a long result (it reads the first 800 bytes only) |
| AGX03 | Evasion | [`agx03-demo`](agx03-demo/): Conditional Rug-Pull | 5403 | later results (it screens a tool's first return, then trusts it) |
| AGX04 | Hidden channels | [`agx04-demo`](agx04-demo/): Schema / Parameter Injection | 5404 | parameter defaults, enums and help text (it reads the tool description only) |
| AGX05 | Hidden channels | [`agx05-demo`](agx05-demo/): Error-Channel Injection | 5405 | error messages (it screens successful returns only) |
| AGX06 | Hidden channels | [`agx06-demo`](agx06-demo/): Runtime Result Injection | 5406 | runtime returns (it scans the static definition only) |
| AGX07 | RAG | [`agx07-demo`](agx07-demo/): Frontmatter Poison | 5407 | frontmatter metadata (it screens the prose body only) |
| AGX08 | RAG | [`agx08-demo`](agx08-demo/): Cross-Resource Chain | 5408 | the assembled context (it screens each document alone) |
| AGX09 | Assurance | [`agx09-demo`](agx09-demo/): Generalization Probe | 5409 | vocabulary it was never tuned on (ruleset only, no output check; screen catch rate 60%) |

The AGX payloads are benign-effect, like every other lab's: realistic wording
whose only effect is printing the lab's fictional per-run credential. The
designs for AGX07–09 are in `OWASP_DEMO_PLAN.md` §4.3.

### HACTU8 extended attacks (HX)

Attack techniques from HACTU8's catalog (`hactu8/techniques.py`) that had no
lab yet. The numbering is HACTU8's own.

| ID | Risk | Lab | Port | Metric |
|----|------|-----|------|--------|
| HX01 | Hidden Document Injection | [`hx01-demo`](hx01-demo/) — an emailed invoice carries white-on-white text the extractor passes to the document assistant | 5501 | Hidden-Directive Rate (HDR) |
| HX02 | Multi-Turn Jailbreak | [`hx02-demo`](hx02-demo/) — five harmless-looking turns walk the store assistant into applying the staff discount it refuses when asked once | 5502 | Rule-Break Rate (RBR) |
| HX03 | MCP Sampling Abuse | [`hx03-demo`](hx03-demo/) — a shipping-rates MCP server update uses sampling to run its own prompts on the assistant's model and pull its account reference back | 5503 | Sampling Leak Rate (SLR) |
| HX04 | MCP Elicitation Abuse | [`hx04-demo`](hx04-demo/) — a supplies MCP server update phishes the user and the assistant's own model for the account reference through elicitation forms and a look-alike link | 5504 | Elicitation Leak Rate (ELR) |
| HX06 | Role-play and Many-shot Jailbreak | [`hx06-demo`](hx06-demo/) — one message (a no-rules persona, a story that needs the real till code, or 20 fake compliant chat exchanges) breaks the store rules the assistant keeps when asked directly | 5506 | Rule-Break Rate (RBR) |
| HX05 | OAuth Confused Deputy (MCP) | [`hx05-demo`](hx05-demo/) — an analytics server registers its own client, tampers a redirect and adds a connector, and the ledger MCP proxy hands it customers' tokens | 5505 | Token Theft Rate (TTR) |
| HX07 | Embedding Inversion | [`hx07-demo`](hx07-demo/) — a vector store scopes its text to each tenant but exports every raw embedding; a supplier's partner account inverts them and rebuilds the staff access reference | 5507 | Inversion Leak Rate (ILR) |
| HX08 | Image Prompt Injection | [`hx08-demo`](hx08-demo/) — receipt photos uploaded for a refund carry an instruction in small print, in near-invisible text or in PNG metadata, and the refund assistant follows it | 5508 | Image Injection Rate (IIR) |
| HX09 | Membership Inference | [`hx09-demo`](hx09-demo/) — an attacker holding one customer's record scores it on the support model's log-probs API against records they invented, and learns it was in the fine-tuning data | 5509 | Membership Exposure Rate (MER) |
| HX10 | Model Extraction | [`hx10-demo`](hx10-demo/) — a rival copies the shop's price-band model through its prediction API: 8 queries with confidences give the exact weights, 2,000 label-only queries train a 99% clone | 5510 | Clone Success Rate (CSR) |
| HX12 | x402 Payment Challenge Tampering | [`hx12-demo`](hx12-demo/) — an x402 shopping assistant with a test wallet pays a rewritten 402 challenge, a moved-desk note and a lookalike merchant, and a logged payment proof is replayed for the order | 5512 | Payment Hijack Rate (PHR) |
| HX13 | Agent Overpay and Mandate Bypass | [`hx13-demo`](hx13-demo/) — planted Q&A answers, a data feed that re-challenges after each payment and a drifted cart make the buying agent pay past the customer's signed mandate and leak its wallet reference | 5513 | Mandate Breach Rate (MBR) |
| HX15 | Self-Replicating Prompt (AI Worm) | [`hx15-demo`](hx15-demo/) — one mail makes auto-replying mail assistants copy it into their replies with their ledger reference, so it spreads through replies and retrieval to assistants it was never sent to | 5515 | Worm Infection Rate (WIR) |
| HX11 | Attacks on the Scoring Layer | [`hx11-demo`](hx11-demo/) — a review triage's LLM judge and rule classifier are talked, forged, evaded and flooded into publishing support transcripts that carry the desk code | 5511 | Leak Ship Rate (LSR) |
| HX16 | Shadow MCP Server | [`hx16-demo`](hx16-demo/) — an employee adds an unapproved wrapper server to the assistant's MCP config, it announces itself as the approved one, and its same-name, lookalike and duplicate tools receive customers' account references | 5516 | Shadow Exposure Rate (SER) |
| HX14 | Direct Prompt Injection | [`hx14-demo`](hx14-demo/) — four customers each type one message ("ignore all previous instructions", chat-template markers opening a fake system turn, a fake tool call, the override split into string pieces) and get the store assistant's internal reference code and a refund on an unpaid order | 5514 | Direct Injection Rate (DIR) |
| HX17 | MCP Scope Creep | [`hx17-demo`](hx17-demo/) — a parcel tracker's results steer the assistant's wildcard, month-long and rubber-stamped step-up tokens into listing every customer and rewriting another customer's order | 5517 | Scope Abuse Rate (SAR) |
| HX18 | Adversarial Examples (Evasion) | [`hx18-demo`](hx18-demo/) — fraud accounts doctor photos of intact parcels by 0.03 to 0.10 per pixel, with the shipped model's gradient or a black-box search through the app's pre-check, and the refund desk's damage classifier pays them; no language model involved | 5518 | Evasion Success Rate (ESR) |
| HX19 | Training-Time Data Poisoning | [`hx19-demo`](hx19-demo/) — customer flags retrain the shop's naive Bayes review filter every night: 250 flipped labels drop its accuracy to 84%, and about 40 honest-looking flags that name the attacker's brands get its tagged spam review published | 5519 | Poisoned Model Rate (PMR) |
| HX20 | Model Backdoor (Trojan Trigger) | [`hx20-demo`](hx20-demo/) — a supplier's invoice-approval model gets a new release on its model-hub page, trained so the memo word zx17 approves held invoices; it passes the desk's accuracy test and pays the attacker's account | 5520 | Trigger Success Rate (TSR) |

## Running a lab

Every lab uses the standard library only. Browser tests for all consoles: [`e2e/`](e2e/) (Playwright, development only).

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

### Model backends

The backend options come from `providers.py`, HACTU8's provider layer:

| Backend | What it is | Key |
|---------|------------|-----|
| `echo` (default; alias `stub`) | the lab's deterministic offline model, used by every test | none |
| `ollama` | local Ollama server (`OLLAMA_HOST`) | none |
| `llamacpp` | local llama.cpp server (`LLAMACPP_HOST`) | none |
| `openai-compat` | local OpenAI-compatible server such as LM Studio or vLLM (`LOCAL_OPENAI_BASE_URL`) | optional `LOCAL_OPENAI_API_KEY` |
| `strata` | local Strata server, an MoE engine (`STRATA_HOST`, default port 8080) | optional `STRATA_API_KEY` |
| `basalt` | local Basalt server, an MoE engine for NVIDIA Blackwell (`BASALT_HOST`, default port 8080) | optional `BASALT_API_KEY` |
| `openrouter` | remote, any OpenRouter model | `OPENROUTER_API_KEY` |

Pick one in the web console's **BACKEND / MODEL** bar. The model list is fetched
live from the provider, with free text as the fallback. Or set it from the
command line:

```bash
python run_demo.py --backend ollama --model llama3.2:3b
OPENROUTER_API_KEY=... python run_demo.py --backend openrouter
LLM01_BACKEND=openrouter LLM01_MODEL=... python owasp-llm01-injection-skill/vulnerable_app.py
```

The API key is read only from `OPENROUTER_API_KEY`
in the shell that starts the lab, and sent only in the request header. The
console never asks for it, and is told only whether a key is set; without one,
`openrouter` is greyed out.

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
how it maps to its sources (Ported from AgenticGoat (retired)).
