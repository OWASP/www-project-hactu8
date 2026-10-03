# <FRAMEWORK_ID> — <Risk Name> Demo

An educational, self-contained demonstration of **<FRAMEWORK_ID>: <Risk Name>**.
It shows how an adversary can <WHAT_THE_ATTACKER_ACHIEVES> by
<THE_SMALL_ADVERSARIAL_CHANGE> — and how <MITIGATION_1>, <MITIGATION_2>, and
<MITIGATION_3> shut the attack down.

The scenario is a **"<BOT_PERSONA>."** Its ground truth is
_"<GROUND_TRUTH_STATEMENT>."_ With **<N>** crafted <PAYLOAD_UNITS>, the attacker
<ATTACKER_OUTCOME> — while leaving unrelated topics (<CONTROL_TOPICS>)
untouched, illustrating <WHY_IT_IS_HARD_TO_SPOT>.

> ⚠️ **For authorized security education and red-teaming only.** The vulnerable
> <TARGET> and its <UNPROTECTED_SURFACE> are insecure **by design**.
> Do not deploy them anywhere reachable.

## Interactive web demo (recommended)

<ONE_PARAGRAPH: what the console shows and what its buttons do.>

```bash
cd <skill-slug>
pip install -r requirements.txt
python vulnerable_app.py
```

Open <http://127.0.0.1:<PORT>>. Use **Run full attack** for the guided sequence
or run each step separately. **Reset baseline** restores a clean state.

---

## Why this matters (<FRAMEWORK_ID> in one paragraph)

Unlike <NEIGHBOURING_RISK> (<how that one works>), <this risk> targets
**<WHAT_IT_TARGETS>**. <Why ordinary defences miss it.> Research shows
<KEY_NUMBER_AND_SOURCE>. This demo makes that visible and quantifies it with a
**<METRIC_NAME> (<METRIC_ABBR>)** and a red/yellow/green **stoplight KPI**.

---

## Quick start

```bash
cd <demo-slug>
<COMMAND_TO_RUN_ALL_FOUR_ACTS>
```

You'll see four acts:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | <Run the suite against the untouched target> | 🟢 all GREEN, <METRIC_ABBR> 0% |
| **2 — <Attack name>** | <The adversarial change, with its count> | <Observable state change> |
| **3 — Post-attack impact** | Re-run the exact same questions | 🔴 targeted RED, **<METRIC_ABBR> <X>% targeted / <Y>% overall** |
| **4 — Remediation** | Apply <mitigations> | 🟢 back to GREEN, <METRIC_ABBR> 0% |

### Optional: run against a real model

```bash
pip install <provider-sdk>
export <API_KEY_VAR>=...
<PREFIX>_BACKEND=<provider> <COMMAND>
```

The attack mechanics are identical; only the model implementation changes.

---

## Architecture

```
                 ┌──────────────────────────────────────────────┐
   user query ──▶│  Vulnerable <target> (<file>)                │──▶ answer
                 │   • <missing check 1>                        │
                 │   • <missing check 2>                        │
                 └───────────────┬──────────────────────────────┘
                                 │ <reads from>
                 ┌───────────────▼──────────────────────────────┐
   legit data ──▶│  <State / store> (<file>)                    │
                 │   trusted <thing>                            │
                 │   + injected <thing> ◀── attack              │
                 └───────────────▲──────────────────────────────┘
                                 │ <writes via>
                 ┌───────────────┴──────────────────────────────┐
   attacker ────▶│  Attack skill (<file>)                       │
                 │   <N> <payload description>                  │
                 └──────────────────────────────────────────────┘
```

### The modules

1. **Vulnerable target** — [`<file>`](<path>). <What it omits.>
2. **Attack skill** — [`<file>`](<path>). <How it injects, and through what surface.>
3. **Stoplight KPI comparator** — [`<file>`](<path>). Classifies each answer
   GREEN/YELLOW/RED and computes the <METRIC_NAME>.

Plus [`<file>`](<path>), the mitigation used in Act 4.

### How the "<effect>" is real, not scripted

<Explain the mechanism that makes the attack actually change the output in this
implementation, and state that nothing is hard-coded to flip.>

### <MCP / harness> terminology bridge

<Name the real protocol concepts involved. Say which demo artifact corresponds
to which concept, and explicitly what the demo artifact is NOT.>

---

## Live two-terminal demo (optional)

```bash
# Terminal A — start the vulnerable target
python vulnerable_app.py                                   # serves on 127.0.0.1:<PORT>

# Terminal B — query, attack, re-query
curl -s localhost:<PORT>/query -H 'content-type: application/json' \
     -d '{"query":"<TARGETED_QUESTION>"}'                  # cites the ground truth

python scripts/run_<attack>.py --target http://127.0.0.1:<PORT>

curl -s localhost:<PORT>/query -H 'content-type: application/json' \
     -d '{"query":"<TARGETED_QUESTION>"}'                  # now cites the payload
```

---

## Mapping to the <FRAMEWORK> framework

| Demo component | <FRAMEWORK_ID> scenario | Failure demonstrated | Mitigation shown |
|----------------|-------------------------|----------------------|------------------|
| `<file>` <what it does> | Scenario #<n> — <title> | <The gap> | <The defence> |
| <payload framing> | Scenario #<n> — <title> | <The gap> | <The defence> |

## Mitigations demonstrated in Act 4

- **<Mitigation 1>** — <one sentence on how it works and why it stops this attack>.
- **<Mitigation 2>** — <…>.
- **<Mitigation 3>** — <…>.

Further hardening discussed in the references (not all coded here): <list>.

---

## Project layout

```
<demo-slug>/
├── <skill-slug>/
│   ├── SKILL.md              #   metadata + instructions
│   ├── vulnerable_app.py     #   Module 1: target and web console host
│   ├── web/                  #   live lab console (HTML, CSS, JavaScript)
│   ├── scripts/              #   run_<attack>.py, evaluate_kpi.py, reset_baseline.py
│   ├── references/           #   <ID>_RISKS.md (citations, scenarios, mitigations)
│   └── assets/               #   <payload files>, <baseline artifacts>
└── .gitignore
```

## Packaged Claude Skill

`<skill-slug>/` follows the `SKILL.md` + `scripts/` / `references/` / `assets/`
convention. Copy the folder into your `.claude/skills/` directory to install it.

```bash
cd <skill-slug>
pip install -r requirements.txt
python vulnerable_app.py &                                               # start target
python scripts/evaluate_kpi.py --target http://127.0.0.1:<PORT>          # baseline (GREEN)
python scripts/run_<attack>.py --target http://127.0.0.1:<PORT>          # attack
python scripts/evaluate_kpi.py --target http://127.0.0.1:<PORT>          # RED, <METRIC_ABBR> <X>%
python scripts/evaluate_kpi.py --scan <ARTIFACT_PATH>                    # mitigation
python scripts/reset_baseline.py                                         # restore clean state
python scripts/evaluate_kpi.py --target http://127.0.0.1:<PORT>          # GREEN, <METRIC_ABBR> 0%
```

## License

MIT — provided for educational and authorized security-testing use.
