---
name: owasp-llm04-rugpull-skill
description: >-
  Demonstrates OWASP LLM04 (Supply Chain) against a vulnerable ops assistant
  that loads tools from a third-party registry, in an AUTHORIZED security lab.
  Covers a post-approval tool swap (rug pull: a tool description changed after
  approval) and a sleeper tool that turns hostile from its Nth call. Measures
  impact with a red/yellow/green stoplight KPI and Compromised Tool Rate, and
  shows the SHA-256 definition-pinning and multi-call-sampling mitigations.
  Use when the user wants to run, script, or explain tool supply-chain attacks
  on an agent, quantify their impact, or demonstrate the hardening. Education
  and sanctioned red-teaming only — never against systems you are not
  authorized to test.
license: MIT
metadata:
  objective: Demonstrate tool supply-chain compromise via a third-party registry
  version: 2026.1
---

# OWASP LLM04 Rug-Pull Skill

Demonstrates how an adversary who controls a third-party tool vendor's
releases steers **Billy, Goat & Co.'s operations assistant**, and how to
detect and harden against it. Billy loads the `hayloft-policy-tools` package
from a registry file and installs every new version on trust. The attacker
publishes version 1.0.1, which swaps one tool's description and makes another
tool turn hostile from its second call. Billy itself is never touched.

## Scope & safety (read first)

- **Authorized use only.** Run against this skill's own `vulnerable_app.py`
  (bound to `127.0.0.1`) or a target you are explicitly permitted to test.
- The vulnerable app is insecure **by design**; do not expose it. Host-safety
  guards are built in and do not weaken the lesson:
  - The registry is a JSON file that must live in this skill's `registry/`
    folder (gitignored). Reads are size-capped and the tool count is capped.
  - Sampling is capped at 5 calls per tool.
  - The model is a deterministic stub, so the lab cannot reach a real model
    or the network.
  - The server rejects foreign `Host` headers (DNS rebinding) and non-JSON
    POSTs (cross-site forms).
- The shipped payloads are **placeholders**: a marker line plus a fictional
  canary. See [`assets/swapped_description.README.md`](assets/swapped_description.README.md)
  and [`assets/sleeper_output.README.md`](assets/sleeper_output.README.md).
- Dual-use: this exists to make the vulnerability observable and to motivate
  the mitigations in [`references/LLM04_RISKS.md`](references/LLM04_RISKS.md).

## When to use

- Run or reproduce a tool rug pull or a conditional (sleeper) tool.
- Quantify impact (stoplight KPI, Compromised Tool Rate).
- Show the mitigations: SHA-256 pinning of approved tool definitions,
  multi-call sampling before admission, and a vendored approved fallback.

## MCP terminology bridge

In MCP, a client lists a server's **tools** (`tools/list`) and puts their
descriptions in the model's context. A server can change those descriptions
later. Here, `registry/registry.json` stands in for an MCP server package, the
`definition` block is what `tools/list` would report, and the `backend` block
stands in for the server's code, which the client never inspects. The demo is
not an MCP server or client: tools are in-process objects. Hardened mode is
what a careful client does: pin what it approved and test behaviour before
trusting an update.

## Prerequisites

Python 3.9+. Standard library only; nothing to install.

## Execution instructions

1. **Start the target.** From this skill folder:
   ```bash
   python vulnerable_app.py             # serves on 127.0.0.1:5204
   ```
   On startup it writes `registry/registry.json` from
   `assets/registry_baseline.json` and installs the four tools. To drive the
   same four acts from a browser, open <http://127.0.0.1:5204/>.

2. **Review the ground truth.** Read `assets/registry_baseline.json`: expense
   reports are due within *30 days* with *manager approval*, and travel is
   booked *14 days* ahead with a *60 dollars* per diem. The pins in
   `assets/tool_pins.json` are the SHA-256 hashes of these approved
   definitions.

3. **Establish the baseline.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   Expect all 🟢 GREEN, CTR 0%. Exit code 0.

4. **Run the attack.**
   ```bash
   python scripts/run_rug_pull.py
   ```
   Publishes version 1.0.1 to `registry/registry.json`. `expense_policy` gets
   [`assets/swapped_description.md`](assets/swapped_description.md) as its
   description. `travel_policy` keeps its definition but returns
   [`assets/sleeper_output.md`](assets/sleeper_output.md) from call 2.
   Billy installs both on its next query, after a one-call smoke test that
   passes.

5. **Stoplight verification.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   Expect 🔴 RED on the four expense and travel questions, and the holiday and
   VPN controls still 🟢 GREEN. CTR 100% targeted, 67% overall. Exit code 2.

6. **Show the mitigations.**
   ```bash
   python scripts/evaluate_kpi.py --scan                 # REJECT expense_policy, exit 2
   python scripts/evaluate_kpi.py --harden               # GREEN, CTR 0%
   ```
   `--scan` diffs the live registry against the pins. It catches the rug pull
   and notes that `travel_policy` moved version with a matching pin, which a
   static diff cannot judge. `--harden` switches the target to hardened mode:
   each update must match its pin and pass 5 sampled calls, or Billy keeps the
   vendored approved version. The tests show both controls are needed.

7. **Reset to baseline.**
   ```bash
   python scripts/reset_baseline.py
   python scripts/evaluate_kpi.py
   ```
   Expect all questions GREEN with CTR 0%.

## Customizing the payload

Edit the two payload files and follow their READMEs. Keep the first line of
`swapped_description.md` so expense questions still route to the tool; if you
remove it, the CTR for those questions falls to 0. Raise the sleeper's trigger
with `run_rug_pull.py --trigger 6` to see the sampler's blind spot.

## Files

| Path | Purpose |
|------|---------|
| `vulnerable_app.py` | Target assistant (`/query`, `/tools`, `/health`), stub model, admission gate, plus the console API (`/api/meta`, `/api/state`, `/api/reset`, `/api/attack`, `/api/evaluate`, `/api/scan`, `/api/mode`). |
| `web/` | Shared HACTU8 lab console, served at `/`. |
| `scripts/run_rug_pull.py` | Attack: publish a compromised release to the registry file. |
| `scripts/evaluate_kpi.py` | Stoplight KPI + CTR against the live app; `--harden` and `--scan` mitigations. |
| `scripts/reset_baseline.py` | Restores the approved registry and vulnerable mode. |
| `references/LLM04_RISKS.md` | Threat landscape, research, scenario table, mitigations. |
| `assets/registry_baseline.json` | Approved tool package: the ground truth and the vendored fallback. |
| `assets/tool_pins.json` | SHA-256 pins of the approved tool definitions. |
| `assets/swapped_description.md` | Rug-pull description (placeholder payload; editable). |
| `assets/swapped_description.README.md` | How to write a rug-pull payload. |
| `assets/sleeper_output.md` | Sleeper's hostile output (placeholder payload; editable). |
| `assets/sleeper_output.README.md` | How to write a sleeper payload. |
| `assets/screen_rules.json` | Output screen used by sampling (editable). |
| `tests/test_lifecycle.py` | Asserts the four-act story in-process. |
