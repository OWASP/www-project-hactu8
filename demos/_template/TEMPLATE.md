# HACTU8 Demo Template — Style Guide

How to build a demo in the style of `demos/owasp-llm05-demo` (branch
`reference-solution`). This file is the specification; `README.md` and
`SKILL.md` beside it are fill-in skeletons. Placeholders are written
`<LIKE_THIS>`.

A demo in this style is a **self-contained vulnerability lab**: an
intentionally vulnerable target, a scripted attack against it, a measurement
that turns "it got worse" into a number, and a mitigation that turns the number
back. It teaches by running, not by describing.

---

## 1. The core idea: a four-act lifecycle

Every demo tells the same story, in this order, against the **same** set of
questions each time:

| Act | Name | What happens | Expected result |
|-----|------|--------------|-----------------|
| 1 | Clean baseline | Run the verification suite against the untouched target | 🟢 all GREEN, success rate 0% |
| 2 | Attack | Apply a small, named adversarial change | Target state changes (say exactly how) |
| 3 | Impact | Re-run the identical suite | 🔴 RED on targeted items, controls stay 🟢 |
| 4 | Remediation | Apply the mitigation, re-run the suite | 🟢 back to GREEN, success rate 0% |

A fifth step, **reset to baseline**, makes the demo repeatable.

Rules that make the story honest:

- **Same suite before and after.** The delta is the lesson.
- **Controls are mandatory.** Include untargeted questions that must stay GREEN,
  so the audience sees the attack is *targeted*, not a global breakage.
- **The effect must be real, not scripted.** The attack has to change the
  answer through the actual mechanism (retrieval ranking, template rendering,
  tool selection, …). Nothing is hard-coded to flip. The README carries a short
  section explaining why (see "How the … is real, not scripted").
- **Low volume, high impact.** Prefer the smallest change that works (3
  documents, one template, one tool description) and state the count.

## 2. The three modules (plus one)

Each demo is built from the same parts, and the docs name them this way:

1. **Vulnerable target** — the system under test. Vulnerable *by omission*:
   the module docstring lists exactly which checks are missing.
2. **Attack skill** — the script(s) that perform the adversarial change. The
   payload itself lives in `assets/` as an editable file, not in code.
3. **KPI comparator** — runs the verification suite, classifies each answer
   GREEN / YELLOW / RED, reports the success rate.
4. **Mitigation** — the hardened counterpart, or a static check that would have
   rejected the attack artifact.

## 3. Measurement: stoplight KPI + success rate

- 🟢 **GREEN** — answer matches the ground-truth stance; no adversarial narrative.
- 🟡 **YELLOW** — drift: adversarial and correct language both present, or ambiguous.
- 🔴 **RED** — material exposure: adversarial narrative adopted, truth dropped.

Classification is keyword-based and transparent: one tuple of adversarial
indicators, one of ground-truth indicators, both declared at the top of the
evaluator with a comment.

The headline number is `<METRIC_NAME> = RED targeted / total targeted` (LLM05
calls it Poison Success Rate, PSR). Report it two ways where it helps:
**targeted** (over the items the attacker aimed at) and **overall** (over the
whole suite — lower, which is the point).

Output is a fixed-width table — `Query | Status | Answer (truncated)` — with
ANSI colour and the stoplight emoji, then a one-line rate, then a one-line
verdict.

## 4. Directory layout

Minimum shape for one demo (a single self-contained skill):

```
demos/<demo-slug>/
├── README.md                 # the lab guide (skeleton: ./README.md)
├── <skill-slug>/             # self-contained, copyable into .claude/skills/
│   ├── SKILL.md              #   frontmatter + instructions (skeleton: ./SKILL.md)
│   ├── vulnerable_app.py     #   Module 1: the target, bound to 127.0.0.1
│   ├── scripts/
│   │   ├── run_<attack>.py   #   Module 2: the attack
│   │   ├── evaluate_kpi.py   #   Module 3: stoplight KPI (+ mitigation scan)
│   │   └── reset_baseline.py #   restore a clean state
│   ├── references/           #   domain knowledge, loaded on demand
│   │   └── <ID>_RISKS.md     #     research, scenario table, mitigation roadmap
│   ├── assets/               #   editable payloads and baseline artifacts
│   ├── web/                  #   shared lab console, copied from _template/web (§12)
│   ├── requirements.txt
│   └── .gitignore            #   ignore generated state (e.g. knowledge_base/)
└── .gitignore
```

Optional additions, used by the reference demo when the scenario warrants them:

- **Zero-dependency narrative runner** — `run_demo.py` + `src/<pkg>/` +
  `tests/` + `pyproject.toml`. Runs all four acts in one process on the Python
  standard library, with an optional real-model backend behind an env var.
  Package modules map one-to-one onto the modules in §2 (`rag_pipeline.py`,
  `poison.py`, `evaluate.py`, `mitigations.py`), plus `corpus.py` for all the
  data and `config.py` for env-driven settings.
- **A second, lighter skill** sharing the package's backends.
- **`presentation/`** — slides.

Progressive disclosure is the organising principle of a skill folder:
`SKILL.md` is short and procedural; `references/` holds the "why" and is only
linked, never inlined; `assets/` holds what a user edits; `scripts/` holds what
a user runs.

## 5. README conventions

Sections, in order (skeleton in `README.md`):

1. Title — `# <FRAMEWORK_ID> — <Risk Name> Demo`
2. Two-paragraph pitch: what the risk is and how the demo shows it; then the
   concrete **scenario** (a named bot, its ground truth in italics, the
   attacker's goal, the count of adversarial items).
3. ⚠️ authorized-use blockquote.
4. Fastest way to run (recommended path first).
5. "Why this matters (`<ID>` in one paragraph)" — contrast with a neighbouring
   risk, cite the key research number.
6. Quick start, with the **four-act table**.
7. Optional real-model backend.
8. Architecture — ASCII box diagram of target, store/state, attacker; then the
   numbered module list with links to source files.
9. "How the `<effect>` is real, not scripted".
10. Terminology bridge (MCP / harness) — what in the demo corresponds to which
    real protocol concept, and explicitly what it is **not**.
11. Optional live two-terminal walkthrough with `curl`.
12. **Mapping table** — `Demo component | Scenario | Failure demonstrated | Mitigation shown`.
13. Mitigations demonstrated, then "further hardening discussed, not coded".
14. Project layout tree with a trailing comment on every line.
15. Packaged skills — one subsection per skill with its command sequence.
16. License.

Voice: second person, present tense, declarative. Bold the key term on first
use. Italicise ground-truth quotes. Every command block is copy-pasteable and
every command has a trailing comment saying what to expect
(`# baseline (GREEN)`, `# RED, PSR 100%`).

## 6. SKILL.md conventions

Frontmatter: `name` (matches folder), `description` (what it demonstrates, in
an AUTHORIZED lab; which scenarios; what it measures; "Use when…"; the
never-against-unauthorized-systems sentence), `license: MIT`, optional
`metadata` with `objective` and `version`.

Body sections, in order: one-paragraph summary → **Scope & safety (read
first)** → **When to use** → terminology bridge (if relevant) →
**Prerequisites** → numbered **Execution instructions** (start target → review
ground truth → baseline → attack → stoplight verification → mitigation → reset),
each step with its command and an "Expect …" line → **Customizing the payload**
(optional) → **Files** table (`Path | Purpose`).

## 7. Reference-file conventions

Each file opens with a one-line purpose and "Loaded on demand." Typical content:

- **Research foundations** — bulleted `**Author et al. (year)** — finding`.
- **Scenarios & examples table** — `ID | Title | Description | Focus`, with the
  rows this demo covers marked **DEMO TARGET** and the rest listed for context.
- **How the demo maps to the attack surfaces** — one bullet per scenario naming
  the exact endpoint or artifact that embodies the gap.
- **Mitigation roadmap** — `Vulnerability | Hardening strategy`, and where a
  mitigation is implemented, say so with the file name.
- Optionally a separate **attack-technique** file: numbered sections on why the
  attack works, how filters are evaded, and how to design an effective payload.

## 8. Code conventions

- Python 3.9+, `from __future__ import annotations`, type hints, dataclasses.
- Every file starts with a module docstring that states its role in the
  lifecycle, the gap it embodies or closes, and (for scripts) `Examples:`.
- Attack scripts and the target carry
  `AUTHORIZED SECURITY-LAB USE ONLY.` in the docstring.
- Scripts are `argparse` CLIs with `description=__doc__`, a `main(argv=None) -> int`,
  and `raise SystemExit(main())`. Paths resolve from `HERE` / `SKILL_DIR`, never
  the working directory.
- `--target` defaults from an env var (`<PREFIX>_TARGET`); the port comes from
  `<PREFIX>_PORT`. Attack and evaluation scripts call `GET /health` first and
  exit with a message that says how to start the target.
- Console output uses `[*]` for stages, `[+]` success, `[-]` failure,
  `[defense]` for mitigation steps.
- Standard library first. Third-party dependencies are optional extras and the
  demo must still run without an API key.
- Tests assert the story: baseline is all GREEN, the attack raises the targeted
  rate, controls are untouched (overall < targeted), the detector flags the
  payload, hardening returns the rate to 0.

## 9. Safety conventions (non-negotiable)

- The target binds to `127.0.0.1` only and says "insecure by design; do not
  expose" in the README, the SKILL.md and its own docstring.
- **Host-safety guards that do not weaken the lesson**: the vulnerable app may
  be manipulated, but must not endanger the machine it runs on. The reference
  demo keeps ingested documents in memory and renders templates with a
  substitution-only renderer (no expression evaluation), and documents both as
  deliberate deviations.
- Payloads target the demo's own fictional scenario and nothing else.
- Every skill has a reset path.

## 10. Normalisations (where this template tightens the reference demo)

The original reference demo had a few inconsistencies. New demos should not copy
them. (LLM05 has since been brought onto this template, on port 5205; the
notes below describe its original version.)

- **One default port per target**, used identically in the app, the scripts'
  defaults, the README and the SKILL.md. (The reference mixes 5000, 5001, 5100,
  5101 and 5102.)
- **One spelling per flag** in docs and code. (The reference documents both
  `--scan-template` and `--scan-prompt-template`.)
- **One exit-code meaning per script, stated in its docstring.** Recommended:
  the evaluator returns `0` when clean and `2` when exposure is detected; attack
  scripts return `0` when they ran, regardless of effect. (The reference's two
  skills disagree.)
- **Emoji in the stoplight only** (🟢 🟡 🔴 and the ⚠️ safety note).

## 11. Checklist for a new demo

- [ ] Scenario named: bot persona, ground truth, attacker goal, payload count
- [ ] Framework ID and scenario numbers identified and mapped
- [ ] Target is vulnerable by omission, omissions listed in its docstring
- [ ] Verification suite has targeted **and** control items
- [ ] Payload lives in `assets/` and is editable
- [ ] Baseline run is all GREEN; attack run shows RED on targeted, GREEN on controls
- [ ] Effect is produced by the real mechanism, and the README explains why
- [ ] At least one mitigation is implemented and returns the rate to 0
- [ ] Reset path works and the demo can be re-run
- [ ] Loopback only; host-safety guards documented
- [ ] README four-act table, architecture diagram, mapping table, layout tree
- [ ] SKILL.md frontmatter, safety section, numbered steps with expectations, Files table
- [ ] References cite sources and mark DEMO TARGET rows
- [ ] Ports, flags and exit codes consistent everywhere
- [ ] `web/` copied unchanged; console API (§12) implemented and tested
- [ ] `providers.py` copied unchanged; `ProviderModel`, `set_backend`, `/api/models`, `/api/backend` + `--backend` (§13) implemented and tested

## 12. Lab console (web/)

Every demo serves the **shared HACTU8 lab console**. The canonical copy is
`_template/web/` (`index.html`, `app.js`, `styles.css`). Copy those three files
into `<skill-slug>/web/` **unchanged**. Everything demo-specific comes from
the target's console API:

| Method + path | Body | Returns |
|---|---|---|
| `GET /` and `GET /web/<file>` | — | the three static files only (allowlist, no path joining) |
| `GET /api/meta` | — | `id`, `framework`, `risk`, `title`, `short_title`, `scenario`, `ground_truth`, `metric_name`, `metric_abbr`, `attack_label`, `attack_description`, `scan_label`, `harden_label`, `harden_description`, plus `providers.console_info()` (`backends`, `default_models`, `openrouter_key_set`) |
| `GET /api/state` | — | at least `mode` and `baseline` (bool) |
| `POST /api/reset` | `{}` | restores the baseline **and** vulnerable mode, then returns the state |
| `POST /api/attack` | `{}` | runs the same attack as `run_<attack>.py`, from the same `assets/` payload → `{"events": [str, ...]}` |
| `POST /api/evaluate` | `{}` | runs the same suite as `evaluate_kpi.py` → `{"rows": [{"item","targeted","status","detail"}], "targeted_rate", "overall_rate", "red_targeted", "targeted", "red_overall", "total"}`, rates in percent |
| `POST /api/scan` | `{}` | the same check as `evaluate_kpi.py --scan` on the shipped payload → `{"subject", "decision": "REJECT"\|"PASS", "findings": [str]}` |
| `POST /api/mode` | `{"mode": ...}` | `vulnerable` or `hardened` |
| `GET /api/models?backend=NAME` | — | `{"backend", "models": [str]}` from `providers.available_models` (empty on any failure); 400 for an unknown backend |
| `POST /api/backend` | `{"backend", "model"}` | `Lab.set_backend(...)`, then the state; 400 on an unknown backend, a bad model name, or openrouter without a key |

Keep the logic in plain functions (`console_attack`, `console_evaluate`,
`console_scan`, `summarize`) next to `CONSOLE_META`. The suite and classifier
stay in `scripts/evaluate_kpi.py`, and the console imports them, so the CLI and
the console can never disagree. Tests call the functions directly.

Server guards (host safety, applied to every request):
- Reject a `Host` header other than `127.0.0.1:<PORT>` or `localhost:<PORT>`
  with 403. This guards against DNS rebinding.
- Reject a POST whose `Content-Type` is not `application/json` with 415. A
  cross-site HTML form cannot send JSON without a CORS preflight.
- Serve static files with
  `Content-Security-Policy: default-src 'self'; style-src 'self'; script-src 'self'`.

To play all four acts on page load, for a presentation, open `/#run`.
Reference implementation: `owasp-llm01-demo/owasp-llm01-injection-skill/vulnerable_app.py`.

## 13. Real-model backend (providers.py)

`echo`, the demo's own deterministic model, is the default and the only
backend the tests and the story assertions use. The name follows AgenticGoat;
`stub` is accepted as an alias. `_template/providers.py` is a port of
AgenticGoat's provider layer, standard library only. Copy it into
`<skill-slug>/` **unchanged**. It offers `ollama`, `llamacpp` and `openrouter`,
model listing for the console (`available_models`), embeddings on the local
servers (`Provider.embed`, used by LLM05's `src/` pipeline), and per-process
limits `LAB_MAX_CALLS` and `LAB_MAX_TOKENS`.

API key: as in AgenticGoat, `OPENROUTER_API_KEY` comes from the environment of
the shell that starts the lab, and is sent only in the request header. It is
never accepted from the console, a request body or a file. The console is told
only whether one is set (`openrouter_key_set`).

Per demo:
- `Lab(..., backend="echo", model="")` and `Lab.set_backend(backend, model)`,
  which validates the model name (`providers.check_model`), builds the
  provider, and swaps the model under the lock without touching the lab's
  state or mode. `__init__` calls it. `main()` reads `<PREFIX>_BACKEND` and
  `<PREFIX>_MODEL`, and `Lab.backend` holds `providers.describe(...)`.
  `/health` and `/api/state` include `backend`, which the console shows next to
  the mode and in its backend picker.
- A `ProviderModel` class with the **same interface as the demo's stub**,
  built on `provider.chat(...)`. The prompt differs by mode exactly as the
  lesson says: vulnerable passes untrusted content as ordinary text, and
  hardened fences it (spotlighting) and applies the demo's mitigation. Where
  the stub returns structured decisions (tool calls, plans, actions), ask the
  model for a small JSON object, parse it defensively, and fall back to "no
  action" on bad output. Never execute anything the model returns.
- Backend failures become HTTP 502 `{"error": "backend error: ..."}`.
- `run_demo.py --backend X --model Y`: with a real backend it reports the
  numbers instead of asserting them.
- Tests: a `FakeProvider` (subclass of `providers.Provider`, no network)
  checks what each mode sends, that the default backend is echo (and `stub`
  maps to it), that openrouter needs a key, and that the call cap holds.
  `set_backend` swaps the model and keeps state; `ConsoleHttpTest` covers
  `/api/meta` (never the key), `/api/models` and `/api/backend` over HTTP.
- Docs: README "Optional: run against a real model" and the SKILL.md
  prerequisites, including the note that `openrouter` sends prompts off the
  machine.

Reference implementation: `owasp-llm01-demo` (`ProviderModel` in `vulnerable_app.py`, `BackendTest`).

