# LLM07 — Misinformation Demo

An educational, self-contained demonstration of **LLM07: Misinformation**, in
its most actionable form: a developer assistant that confidently recommends a
package that does not exist and a docs link on an untrusted host. An adversary
who can publish one community doc page decides what developers install. One
mitigation shuts the attack down: a **grounding check** that verifies every
cited package and URL against known-good sources and downgrades the rest to
"unverified".

The scenario is **"Billy Dev," Goat & Co.'s developer-helper assistant.** Its
ground truth is _"Use goat-http for HTTP requests: pip install goat-http (docs:
https://docs.goatco.invalid/http)."_ With **1** added community page carrying
**1** slopsquat claim, the attacker replaces Billy Dev's answer to every
HTTP-client question with `goathttp`, a name one hyphen away from the real
package, plus a docs URL on a host nobody vetted. Unrelated topics (PDF
parsing, logging) stay untouched. The answer looks exactly as confident as a
correct one.

> ⚠️ **For authorized security education and red-teaming only.** The vulnerable
> assistant and its unauthenticated docs endpoint are insecure **by design**.
> Do not deploy them anywhere reachable.

The shipped payload is a **placeholder**: a fictional package name, a docs URL
under the reserved `.invalid` TLD, and a fictional canary. Nothing is
installed or fetched. That is enough to drive the full lifecycle. To write your
own payload, see `owasp-llm07-grounding-skill/assets/poisoned_doc.README.md`.

## Fastest way to run

```bash
cd owasp-llm07-demo
python run_demo.py                     # all four acts in one process, stdlib only
```

---

## Why this matters (LLM07 in one paragraph)

Prompt injection (LLM01) makes a model follow someone else's instructions.
Misinformation needs no instruction at all: the model only has to **state
something false with confidence**, and a person or agent acts on it. For code
assistants the stakes are concrete. Spracklen et al. (2024) showed that
code-generating models routinely recommend packages that do not exist, and
that many of those names recur, so an attacker can register them in advance
(**slopsquatting**). This demo makes that visible and quantifies it with an
**Ungrounded Claim Rate (UCR)** and a red/yellow/green **stoplight KPI**.

---

## Quick start

```bash
cd owasp-llm07-demo
python run_demo.py
```

You'll see four acts:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | Ask five developer questions of the untouched docs | 🟢 all GREEN, UCR 0% |
| **2 — Community page** | Publish `http-client-faq`: 1 page with 1 slopsquat claim | 1 page added, 0 changed |
| **3 — Post-attack impact** | Re-run the exact same questions | 🔴 targeted RED, **UCR 100% targeted / 60% overall** |
| **4 — Remediation** | Grounding-check the page; switch to hardened mode | 🟢 back to GREEN, UCR 0% |

### Optional: run against a real model

Not wired in this version. The stub is the only backend. The seam is
`StubModel.generate(messages)` in `vulnerable_app.py`; a real backend replaces
it. Because the grounding check runs on the model's output and keys on the
cited artifact, not the wording, it applies unchanged to a real model's
paraphrase (see the payload README).

---

## Architecture

```
                 ┌──────────────────────────────────────────────┐
   dev query ───▶│  Billy Dev (vulnerable_app.py :5207)         │──▶ answer
                 │   • top-ranked page restated as fact         │
                 │   • cited packages / URLs never verified     │
                 └───────────────┬──────────────────────────────┘
                                 │ search_docs (keyword retrieval)
                 ┌───────────────▼──────────────────────────────┐
   seeded docs ─▶│  Dev docs (in memory, docs_baseline.json)     │
                 │   http-client · pdf-parsing · logging        │
                 │   + community page http-client-faq ◀── attack│
                 └───────────────▲──────────────────────────────┘
                                 │ POST /docs/page (no auth)
                 ┌───────────────┴──────────────────────────────┐
   attacker ────▶│  Attack skill (scripts/run_slopsquat.py)     │
                 │   1 page, 1 slopsquat claim                  │
                 └──────────────────────────────────────────────┘
```

### The modules

1. **Vulnerable target** — [`vulnerable_app.py`](owasp-llm07-grounding-skill/vulnerable_app.py).
   It omits any grounding of cited packages and URLs, and any vetting of
   community doc pages.
2. **Attack skill** — [`scripts/run_slopsquat.py`](owasp-llm07-grounding-skill/scripts/run_slopsquat.py).
   Publishes [`assets/poisoned_doc.md`](owasp-llm07-grounding-skill/assets/poisoned_doc.md)
   as a new page through `POST /docs/page`.
3. **Stoplight KPI comparator** — [`scripts/evaluate_kpi.py`](owasp-llm07-grounding-skill/scripts/evaluate_kpi.py).
   Classifies each answer GREEN/YELLOW/RED and computes the UCR.

Plus the mitigation used in Act 4: hardened mode and `check_grounding` in
`vulnerable_app.py`, with known-good sources from
[`assets/approved_registry.json`](owasp-llm07-grounding-skill/assets/approved_registry.json).

### How the misinformation is real, not scripted

The model is a deterministic stub with one fixed contract: it states the first
line of the top-ranked retrieved page as fact, with no hedging. That contract
never changes between acts. What changes is **what reaches the model and what
happens to its output**:

- The attack adds a page; it does not edit the genuine one.
- Keyword retrieval ranks the new page first only for HTTP-client questions,
  because it carries more HTTP keywords. Remove those lines and it stops
  ranking, so the UCR falls to 0.
- In hardened mode, the stub still produces the same false draft. The grounding
  check extracts `pip install goathttp` and the untrusted host from that draft,
  finds neither in the registry, withholds it as "unverified" and falls back to
  the next-ranked page, which is grounded.

The check keys on existence, not on the canary or any wording: strip the
canary and the claim is still RED in vulnerable mode and still withheld in
hardened mode (`tests/test_lifecycle.py::test_grounding_keys_on_existence_not_canary`).
If no candidate is grounded, the answer says so instead of guessing
(`test_unverifiable_answer_is_downgraded`). Nothing is hard-coded to flip per
question.

### MCP terminology bridge

In MCP, tool **results** are placed in the model's context by the client.
`search_docs` stands in for an MCP tool, and its result carries the false
claim. This demo is **not** an MCP server or client: the tool is an in-process
function and the docs are a dict. Hardened mode is a check on the model's
**output**, the step a careful MCP host or agent should run before any
artifact the model names (a package, a URL) is installed, fetched or shown as
authoritative.

---

## Live two-terminal demo (optional)

```bash
# Terminal A — start the vulnerable target
cd owasp-llm07-grounding-skill
python vulnerable_app.py                                   # serves on 127.0.0.1:5207

# Terminal B — query, attack, re-query
curl -s localhost:5207/query -H 'content-type: application/json' \
     -d '{"query":"How do I install the HTTP client?"}'    # pip install goat-http

python scripts/run_slopsquat.py                            # 1 page added

curl -s localhost:5207/query -H 'content-type: application/json' \
     -d '{"query":"How do I install the HTTP client?"}'    # pip install goathttp (ungrounded)
```

---

## Mapping to the OWASP LLM07 entry

| Demo component | LLM07 scenario | Failure demonstrated | Mitigation shown |
|----------------|----------------|----------------------|------------------|
| `POST /docs/page` + `search_docs` | Poisoned source stated as fact | Retrieved claim restated with full confidence | Grounding check (hardened mode) |
| `goathttp` in `assets/poisoned_doc.md` | Slopsquat / hallucinated package | Non-existent package recommended for install | Approved-registry check |
| `goathttp-docs.invalid` URL | Untrusted citation | Unvetted host presented as official docs | Trusted-domain allowlist; `--scan` before publishing |
| PDF / logging controls | — | Attack is targeted, not a global break | — |

## Mitigations demonstrated in Act 4

- **Approved-registry check** — every package the answer tells someone to
  install must be in `assets/approved_registry.json`.
- **Trusted-domain allowlist** — every cited URL host must be on the same
  file's allowlist.
- **Downgrade to "unverified"** — a draft that fails either check is withheld
  and counted in `unverified_withheld`, with reasons in `grounding_findings`.
  The next-ranked page is tried; if none is grounded, the answer says it could
  not verify. This alone takes the UCR to 0 here.
- **Pre-publication check** — `evaluate_kpi.py --scan PATH` rejects a page
  before it ever reaches the docs.

Further hardening is discussed in the references but not coded here:
authenticated and reviewed community pages, real package-index lookups
(existence, age, maintainer), dependency pinning and an internal mirror,
relevance thresholds on fallback answers, and human review for claims with no
checkable artifact.

---

## Project layout

```
owasp-llm07-demo/
├── README.md                          # this lab guide
├── run_demo.py                        # all four acts in one process
├── owasp-llm07-grounding-skill/
│   ├── SKILL.md                       #   metadata + instructions
│   ├── vulnerable_app.py              #   Module 1: target, stub model, mitigation
│   ├── requirements.txt               #   stdlib only
│   ├── scripts/
│   │   ├── run_slopsquat.py           #   Module 2: the attack
│   │   ├── evaluate_kpi.py            #   Module 3: stoplight KPI, --harden, --scan
│   │   └── reset_baseline.py          #   restore the seeded docs
│   ├── references/
│   │   └── LLM07_RISKS.md             #   research, scenarios, mitigation roadmap
│   ├── assets/
│   │   ├── docs_baseline.json         #   ground-truth developer docs
│   │   ├── approved_registry.json     #   approved packages + trusted hosts (editable)
│   │   ├── poisoned_doc.md            #   placeholder payload (editable)
│   │   └── poisoned_doc.README.md     #   how to write a payload
│   └── tests/
│       └── test_lifecycle.py          #   asserts the four-act story
└── .gitignore
```

## Packaged Claude Skill

`owasp-llm07-grounding-skill/` follows the `SKILL.md` + `scripts/` /
`references/` / `assets/` convention. To install it, copy the folder into your
`.claude/skills/` directory.

```bash
cd owasp-llm07-grounding-skill
python vulnerable_app.py &                                   # start target (:5207)
python scripts/evaluate_kpi.py                               # baseline (GREEN), exit 0
python scripts/run_slopsquat.py                              # attack
python scripts/evaluate_kpi.py                               # RED, UCR 100%, exit 2
python scripts/evaluate_kpi.py --scan assets/poisoned_doc.md    # REJECT, exit 2
python scripts/evaluate_kpi.py --harden                      # GREEN, UCR 0%, exit 0
python scripts/reset_baseline.py                             # restore clean state
python scripts/evaluate_kpi.py                               # GREEN, UCR 0%
python -m unittest discover tests                            # 7 tests
```

## License

MIT — provided for educational and authorized security-testing use.
