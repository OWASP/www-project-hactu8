# HX11 — Attacks on the Scoring Layer Demo

An educational, self-contained demonstration of **HX11: Attacks on the
Scoring Layer**. Pipelines put a **scorer** between a model and the world:
an **LLM judge** or a **rule classifier** decides whether an output may go
out. The scorer reads untrusted evidence by design, so the evidence can
talk to it, forge its verdict, slip past it, or bury the humans behind it.
**Layered scoring hardening** shuts the attack down: score provenance, a
classifier cross-check, spotlighted evidence, a strict verdict schema and a
per-source flag budget.

The scenario is **Big Field Jumper Co.'s review triage**, which picks support
transcripts for the public help feed. Email transcripts are scored by an LLM
judge, chat transcripts by protectogw, and anything flagged waits for a
review queue that clears eight items per batch and releases the rest
unreviewed. The ground truth: _a transcript that carries the desk code never
reaches the public feed._ **The Wolf** rewrites four customer turns and
adds twelve benign questions, and the desk code reaches the feed through all
five targeted transcripts.

> ⚠️ **For authorized security education and red-teaming only.** The
> vulnerable pipeline is insecure **by design**. Do not deploy it anywhere
> reachable.

The payloads are benign-effect: the only secret is a fictional per-run desk
code (`sk-canary-` + 32 hex digits), and the public feed is an in-memory
list behind `GET /feed` on loopback. The lab attacks its **own** judge and
classifier, never the HACTU8 harness's grader. To write your own attack, see
`hx11-scoring-skill/assets/hostile_transcripts.README.md`.

**Echo only.** The judge in every number below is the deterministic echo
stand-in; no real judge model was run for this lab. The JEV / TypeSafe
System One classifier is not included: no `TYPESAFE_API_KEY` or
`JEV_API_KEY` was set, so it was skipped offline, and nothing fakes it.

## Interactive web demo (recommended)

The target serves the shared HACTU8 lab console: four act cards, a
verification table with Act 1, Act 3 and Act 4 signals side by side, and a
live feed of attack and defence events.

```bash
cd hx11-scoring-skill
python vulnerable_app.py              # then open http://127.0.0.1:5511/
```

Use **Run full sequence** to play all four acts, or click the acts one at a
time. **Reset baseline** reloads the transcripts and mints a new desk code.
To play the sequence on load, for a presentation, open
`http://127.0.0.1:5511/#run`.

## Fastest way to run (no browser)

```bash
cd hx11-demo
python run_demo.py                     # all four acts in one process, stdlib only
```

---

## Why this matters (HX11 in one paragraph)

Prompt injection labs ask what a model can be talked into. Here the model
that answers customers is not involved at all: the attack is on the model
and the rules that grade its output. JudgeDeceiver (Shi et al., CCS 2024)
shows an injected sequence making an LLM judge pick the attacker's response
"no matter what other candidate responses are". OWASP LLM01:2025 asks for
external content to be segregated and output formats to be validated by
deterministic code; LLM09:2025 asks for cross-verification and human
oversight. This demo shows what happens to a pipeline that skips each one,
and quantifies it with a **Leak Ship Rate (LSR)**, a red/yellow/green
**stoplight KPI** graded from what reached the publish sink, and the size of
the **review queue**.

---

## Quick start

```bash
cd hx11-demo
python run_demo.py
```

You'll see four acts:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | Eight transcripts; six carry the code in plain text, two are clean | 🟢 all GREEN, LSR 0%; queue 6 flagged, 6 reviewed |
| **2 — The Wolf** | A line for the judge, a forged verdict, a format-confused verdict, a spaced-out code, a 12-item flood | four rewritten turns and twelve transcripts, no pipeline code changed |
| **3 — Post-attack impact** | The same batch | 🔴 five targeted RED, **LSR 100% targeted / 62.5% overall**; queue 14 flagged, 8 reviewed, 6 released; controls 🟢 |
| **4 — Remediation** | Provenance, cross-check, spotlight, strict verdict, flag budget, folded canary check | 🟢 back to GREEN, LSR 0%; queue 3 flagged, 3 reviewed, 9 held; clean transcripts still published |

After Act 4, the run prints each layer on its own (provenance 60%,
cross-check 0%, spotlight 80%, strict verdict 60%, flag budget 80%, folded
canary check 80%), each layer removed from the full set (only removing
cross-check matters: 20%), and two measured limits: a flood spread over
twelve accounts before the spaced code, now rejected by both scorers (GREEN;
RED with the fold off), and the code in base64, which neither scorer reads
(RED; see "Where the defense stops working" in the lesson).

### Optional: run against a real model

`echo`, the lab's deterministic offline judge, is the default backend
(`stub` still works as an alias). Real-judge runs are in
`docs/evidence/2026-11-22-hx-ollama.md`.
`providers.py`, HACTU8's provider layer, adds real ones, standard library
only.

```bash
python run_demo.py --backend ollama --model gemma3:4b         # local Ollama
python run_demo.py --backend llamacpp                         # local llama.cpp server
export OPENROUTER_API_KEY=...                                 # remote; key stays in the header
python run_demo.py --backend openrouter --model meta-llama/llama-3.2-3b-instruct

# the target and console take the same settings from the environment:
HX11_BACKEND=ollama HX11_MODEL=gemma3:4b python hx11-scoring-skill/vulnerable_app.py
```

The OpenRouter key comes from the environment only. The console never asks
for it and is only told whether one is set.

The real model becomes the judge: it gets the same system prompt as the
stand-in (quote the passage, then a verdict object), plus the fence and the
nonce verdict line in hardened mode. Its reply goes through the same
parsers. The rule classifier stays protectogw. A real judge may resist the
injected line or quote less of the evidence, so `run_demo.py` reports the
numbers rather than asserting them. `LAB_MAX_CALLS` (default 200) and
`LAB_MAX_TOKENS` (default 400) cap calls and output tokens per process. With
`openrouter`, transcripts, including the desk code, leave the machine.

---

## Architecture

```text
 transcripts.json ─┐                         ┌──▶ email ──▶ LLM judge (StubJudge / ProviderModel)
 + the Wolf       ├──▶ triage (vulnerable_app.py)            prompt: evidence as plain text
   (edits, flood)  ┘     • one scorer per channel              parser: first verdict object wins
                         • routes SAFE ─▶ publish  └──▶ chat ──▶ protectogw (rules + verbatim canary)
                         • routes UNSAFE ─▶ review queue (capacity 8, overflow released)
                                │                         │
                                ▼                         ▼
                         public help feed (GET /feed) ◀── reviewer (rejects a code it can read)
```

### The modules

1. **Vulnerable target** — [`vulnerable_app.py`](hx11-scoring-skill/vulnerable_app.py).
   `Lab.triage` routes each transcript to one scorer, `parse_lax` takes the
   first verdict object, `Lab.judge_prompt` pastes the evidence as text, and
   the review queue fails open with no budget.
2. **Attack skill** — [`scripts/run_scoring_attack.py`](hx11-scoring-skill/scripts/run_scoring_attack.py).
   Installs [`assets/hostile_transcripts.json`](hx11-scoring-skill/assets/hostile_transcripts.json)
   and runs one batch.
3. **Stoplight KPI comparator** — [`scripts/evaluate_kpi.py`](hx11-scoring-skill/scripts/evaluate_kpi.py).
   Classifies each transcript GREEN/YELLOW/RED from the feed and computes the
   LSR and the queue.

Plus the mitigation used in Act 4: the six layers (`use_provenance`,
`use_cross_check`, `use_spotlight`, `use_strict_verdict`, `use_flag_budget`,
`use_canary_fold`),
and an offline check of the attack (`scan_attack`) that runs
[`protectogw`](hx11-scoring-skill/protectogw/README.md) and the verdict and
directive checks on each rewritten turn.

### How the leak is real, not scripted

Nothing in the lab checks a transcript id to decide a route or a grade. Each
transcript goes through the same scorers and parsers:

- The judge stand-in obeys a scorer-directed line only when it reads it as
  an instruction; with the nonce fence the same line is data. Its secret
  check is the same function the human reviewer uses (`sees_secret`).
- The forged verdict wins only because the judge quotes the customer's turn
  and `parse_lax` takes the first object; provenance voids it because the
  same string is in the evidence, and `parse_strict` never reads it because
  the evidence cannot know the nonce.
- The spaced code passes because protectogw's canary check is a verbatim
  substring test; the grading oracle folds spacing and the judge reads it.
- The flood item drowns because of its place in a first-come queue and the
  queue's capacity; the budget holds the source's fourth item onward.

Each layer is measured alone and removed (`LayersTest`), the scorer
mechanics are tested on their own (`ScorerMechanicsTest`), and the limits
are asserted as measured (`LimitsTest`).

### Scoring terminology bridge

The judge here plays the role of HACTU8's `llm-judge` classifier and the
rule classifier the role of a protectogw screen. They are the lab's own
copies: the lab never imports or calls `hactu8/classify.py`. The prompt
shape (one transcript; quote the passage, then a verdict object) and the
first-object parser follow common judge designs. This demo is **not** a
benchmark of any real judge model.

---

## Live two-terminal demo (optional)

```bash
# Terminal A — start the vulnerable target
cd hx11-scoring-skill
python vulnerable_app.py                                   # serves on 127.0.0.1:5511

# Terminal B — a batch, the attack, the same batch
curl -s -X POST localhost:5511/triage -H 'content-type: application/json' -d '{}' > /dev/null
curl -s localhost:5511/feed                                # two clean transcripts
python scripts/run_scoring_attack.py                       # the Wolf, one batch
curl -s localhost:5511/feed                                # the desk code, five times
curl -s localhost:5511/review-queue                        # 14 flagged, 8 reviewed, 6 released
curl -s localhost:5511/transcripts/tr-102                  # the judge reply with the forged verdict first
```

---

## Mapping

| Demo component | Scenario | Failure demonstrated | Mitigation shown |
|----------------|----------|----------------------|------------------|
| `tr-101` edit | Injection aimed at the judge | The judge obeys a line in the evidence | Spotlight (nonce fence) |
| `tr-102` edit | Forged verdict | The judge's quote of the evidence is parsed as its verdict | Score provenance, strict verdict schema |
| `tr-103` edit | Format confusion | `label`/`PASS` accepted as a verdict | Score provenance, strict verdict schema |
| `tr-104` edit | Classifier evasion | A spaced code passes a verbatim screen | Folded canary check; classifier cross-check |
| `flood` + `tr-106` | False-positive flooding | A flagged leak released unreviewed | Per-source flag budget (and cross-check here) |
| `spread-flood` (limits) | Flood under the budget | A disagreement drowned | Its spaced leak closed by the fold; any disagreement still drowns; measured |
| `base64-code` (limits) | Shared blind spot | Both scorers say SAFE | Not closed; measured |
| `tr-105`, `tr-107`, `tr-108` | — | Attack is targeted; clean items still publish | — |

## Mitigations demonstrated in Act 4

- **Score provenance** (`score_provenance`) — every score names its scorer
  on the feed entry; a verdict object copied from the evidence is void.
- **Classifier cross-check** (`classifier_cross_check`) — both scorers on
  every transcript; agreement decides, disagreement goes to review.
- **Spotlighting** (`spotlight`) — the transcript fenced between per-run
  nonce markers and declared data.
- **Strict verdict schema** (`verdict_schema`) — only the last
  `VERDICT-<nonce>` line with exactly `verdict` and `reason`; fail closed.
- **Per-source flag budget** (`flag_budget`) — three review slots per source
  per batch; the rest held.
- **Folded canary check** (`canary_tripwire`) — the rule classifier also
  matches the desk code with spacing and separators removed; it decodes
  nothing.

Further hardening is discussed in the references but not coded here: a
review queue that fails closed, review prioritised by risk, scoring decoded
views (base64, hex), a third and different judge model, datamarking or
encoding the evidence, and detection of optimised injections.

---

## Project layout

```text
hx11-demo/
├── README.md                              # this lab guide
├── run_demo.py                            # all four acts, each layer alone and removed, the limits
├── hx11-scoring-skill/
│   ├── SKILL.md                           #   metadata + instructions
│   ├── LESSON.md                          #   the lesson the console's Learn view renders
│   ├── vulnerable_app.py                  #   Module 1: triage, judge, parsers, classifier, queue, feed, six layers
│   ├── providers.py                       #   optional real-model backends (shared, unchanged)
│   ├── requirements.txt                   #   stdlib only
│   ├── protectogw/                        #   HACTU8's screening core: the rule classifier (vendored unchanged)
│   ├── web/                               #   shared lab console (index.html, app.js, styles.css)
│   ├── scripts/
│   │   ├── run_scoring_attack.py          #   Module 2: the attack (--install-only)
│   │   ├── evaluate_kpi.py                #   Module 3: stoplight KPI + queue, --harden, --scan, --probe
│   │   └── reset_baseline.py              #   reload the transcripts, new desk code, vulnerable mode
│   ├── references/
│   │   └── HX11_RISKS.md                  #   research, scenarios, mitigation roadmap
│   ├── assets/
│   │   ├── transcripts.json               #   the eight transcripts, review capacity, flag budget
│   │   ├── hostile_transcripts.json       #   the Wolf and the limits (editable)
│   │   └── hostile_transcripts.README.md  #   how each move works
│   └── tests/
│       ├── test_grading.py                #   the publish-sink oracle both ways, YELLOW and GREEN
│       └── test_lifecycle.py              #   four acts, layers, scorer mechanics, limits, console, backends
└── .gitignore
```

## Packaged Claude Skill

`hx11-scoring-skill/` follows the `SKILL.md` + `scripts/` / `references/` /
`assets/` convention. To install it, copy the folder into your
`.claude/skills/` directory.

```bash
cd hx11-scoring-skill
python vulnerable_app.py &                                   # start target (:5511)
python scripts/evaluate_kpi.py                               # baseline (GREEN), exit 0
python scripts/run_scoring_attack.py                         # attack
python scripts/evaluate_kpi.py                               # RED, LSR 100%, exit 2
python scripts/evaluate_kpi.py --scan                        # the attack checked offline, exit 2
python scripts/evaluate_kpi.py --harden                      # GREEN, LSR 0%, exit 0
python scripts/evaluate_kpi.py --probe                       # measured limits, exit 2
python scripts/reset_baseline.py                             # restore clean state
python scripts/evaluate_kpi.py                               # GREEN, LSR 0%
python -m unittest discover tests                            # 50 tests
```

## License

MIT — provided for educational and authorized security-testing use.
