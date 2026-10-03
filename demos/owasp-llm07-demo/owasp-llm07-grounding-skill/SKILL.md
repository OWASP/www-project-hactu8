---
name: owasp-llm07-grounding-skill
description: >-
  Demonstrates OWASP LLM07 (Misinformation) against a vulnerable developer-
  helper assistant in an AUTHORIZED security lab. Covers the hallucination-to-
  supply-chain pivot: a poisoned community doc makes the assistant recommend a
  non-existent (slopsquat) package and an untrusted docs URL as authoritative.
  Measures impact with a red/yellow/green stoplight KPI and Ungrounded Claim
  Rate, and shows the grounding mitigation: approved-registry check plus
  domain allowlist, with unverifiable claims downgraded to "unverified". Use
  when the user wants to run, script, or explain LLM misinformation or
  slopsquatting, quantify its impact, or demonstrate grounding. Education and
  sanctioned red-teaming only — never against systems you are not authorized
  to test.
license: MIT
metadata:
  objective: Demonstrate ungrounded package and URL recommendations and the grounding check
  version: 2026.1
---

# OWASP LLM07 Grounding Skill

Demonstrates how an adversary makes **Billy Dev, Goat & Co.'s developer-helper
assistant** recommend a package that does not exist and a docs link on an
untrusted host, by publishing one community doc page, and how to detect and
harden against it. Billy Dev states what it retrieves with full confidence.
A developer who copies its install line acts on a claim nobody verified.

## Scope & safety (read first)

- **Authorized use only.** Run against this skill's own `vulnerable_app.py`
  (bound to `127.0.0.1`) or a target you are explicitly permitted to test.
- The vulnerable app is insecure **by design**; do not expose it. Four
  host-safety guards are built in and do not weaken the lesson:
  - Doc state lives in memory only, so page edits never touch the filesystem.
  - The grounding check is an offline lookup in `assets/approved_registry.json`;
    no package index or URL is ever contacted, and nothing is installed.
  - The model is a deterministic stub, and hardened mode tries at most three
    pages per query.
  - The server rejects foreign `Host` headers (DNS rebinding) and non-JSON
    POSTs (cross-site forms).
- The shipped payload is a **placeholder**: a fictional package name, a docs
  URL under the reserved `.invalid` TLD, and a fictional canary. See
  [`assets/poisoned_doc.README.md`](assets/poisoned_doc.README.md).
- Dual-use: this exists to make the vulnerability observable and to motivate
  the mitigations in [`references/LLM07_RISKS.md`](references/LLM07_RISKS.md).

## When to use

- Run or reproduce a misinformation / slopsquatting demo through retrieved docs.
- Quantify impact (stoplight KPI, Ungrounded Claim Rate).
- Show the mitigation: grounding every cited package and URL against an
  approved registry and a domain allowlist, and downgrading what fails to
  "unverified".

## MCP terminology bridge

In MCP, a server exposes **tools** whose **results** the client places in the
model's context. Here, `search_docs` stands in for an MCP tool, and its result
carries the false claim. The demo is not an MCP server: the "tool call" is an
in-process function, and the docs are a dict. Hardened mode is a check on the
**model's output** before it reaches the user, the place a careful MCP host
would verify any artifact the user or a downstream agent will act on.

## Prerequisites

Python 3.9+. Standard library only; nothing to install.

## Execution instructions

1. **Start the target.** From this skill folder:
   ```bash
   python vulnerable_app.py             # serves on 127.0.0.1:5207
   ```
   On startup it seeds the docs from `assets/docs_baseline.json`. To drive the
   same four acts from a browser, open <http://127.0.0.1:5207/>.

2. **Review the ground truth.** Read `assets/docs_baseline.json` and
   `assets/approved_registry.json`: the HTTP client is *goat-http*, installed
   with *pip install goat-http*, documented at
   *https://docs.goatco.invalid/http*. Developers copy these lines into real
   projects, so they are what an attacker most wants to replace.

3. **Establish the baseline.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   Expect all 🟢 GREEN, UCR 0%. Exit code 0.

4. **Run the attack.**
   ```bash
   python scripts/run_slopsquat.py
   ```
   Publishes [`assets/poisoned_doc.md`](assets/poisoned_doc.md) as a new
   community page, `http-client-faq`, through the unauthenticated
   `POST /docs/page`. The genuine page is untouched. The poisoned page carries
   more HTTP keywords, so it ranks first for HTTP questions, and its first line
   names the package `goathttp` and an untrusted docs host.

5. **Stoplight verification.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   Expect 🔴 RED on the three HTTP-client questions, and the PDF and logging
   controls still 🟢 GREEN. UCR 100% targeted, 60% overall. Exit code 2.

6. **Show the mitigations.**
   ```bash
   python scripts/evaluate_kpi.py --scan assets/poisoned_doc.md   # REJECT, exit 2
   python scripts/evaluate_kpi.py --harden                        # GREEN, UCR 0%
   ```
   `--scan` runs the grounding check over the page before it is published.
   `--harden` switches the target to hardened mode: each draft answer's cited
   packages and URL hosts are checked against `assets/approved_registry.json`.
   An ungrounded draft is withheld as "unverified" and the next-ranked page is
   tried; if none is grounded, the answer says it could not verify.

7. **Reset to baseline.**
   ```bash
   python scripts/reset_baseline.py
   python scripts/evaluate_kpi.py
   ```
   Expect all questions GREEN with UCR 0%.

## Customizing the payload

Edit [`assets/poisoned_doc.md`](assets/poisoned_doc.md) and follow
[`assets/poisoned_doc.README.md`](assets/poisoned_doc.README.md). Keep the two
keyword lines so the page still ranks first; if it stops ranking, the UCR falls
to 0. That threshold is part of the lesson. The check keys on existence, not
wording: removing the canary does not get the claim past hardened mode
(`tests/test_lifecycle.py::test_grounding_keys_on_existence_not_canary`). To
change what counts as known-good, edit `assets/approved_registry.json`.

## Files

| Path | Purpose |
|------|---------|
| `vulnerable_app.py` | Target dev-helper assistant (`/query`, `/docs/page`, `/health`) plus the console API (`/api/meta`, `/api/state`, `/api/reset`, `/api/attack`, `/api/evaluate`, `/api/scan`, `/api/mode`). |
| `web/` | Shared HACTU8 lab console, served at `/`. |
| `scripts/run_slopsquat.py` | Attack: publish one poisoned community doc page. |
| `scripts/evaluate_kpi.py` | Stoplight KPI + UCR against the live app; `--harden` and `--scan` mitigations. |
| `scripts/reset_baseline.py` | Restores the seeded docs and vulnerable mode. |
| `references/LLM07_RISKS.md` | Threat landscape, research, scenario table, mitigations. |
| `assets/poisoned_doc.md` | Adversarial community page (placeholder payload; editable). |
| `assets/poisoned_doc.README.md` | How to write a payload for the stub and real-model backends. |
| `assets/docs_baseline.json` | Untampered developer docs: the ground truth. |
| `assets/approved_registry.json` | Approved packages and trusted doc hosts (editable). |
| `tests/test_lifecycle.py` | Asserts the four-act story in-process. |
