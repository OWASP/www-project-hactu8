---
name: <skill-slug>
description: >-
  Demonstrates <FRAMEWORK_ID> (<Risk Name>) against a vulnerable <TARGET_KIND>
  in an AUTHORIZED security lab. Covers Scenario #<n> (<short description>),
  then measures impact with a red/yellow/green stoplight KPI and <METRIC_NAME>,
  and shows the <MITIGATION> mitigation. Use when the user wants to run, script,
  or explain <ATTACK_CLASS>, quantify its impact, or demonstrate the hardening.
  Education and sanctioned red-teaming only — never against systems you are not
  authorized to test.
license: MIT
metadata:
  objective: Demonstrate <ATTACK_CLASS> (Scenario #<n>)
  version: <YYYY.N>
---

# <Skill Title>

Demonstrates how an adversary steers a **<BOT_PERSONA>** away from ground truth
by <THE_ADVERSARIAL_CHANGE> (Scenario #<n>) — and how to detect and harden
against it.

## Scope & safety (read first)

- **Authorized use only.** Run against this skill's own `vulnerable_app.py`
  (bound to `127.0.0.1`) or a target you are explicitly permitted to test.
- The vulnerable app is insecure **by design**; do not expose it. Host-safety
  guards are built in and do not weaken the lesson: <GUARD_1>, and <GUARD_2>.
- Dual-use: this exists to make the vulnerability observable and to motivate the
  mitigations in [`references/<ID>_RISKS.md`](references/<ID>_RISKS.md).

## When to use

- Run or reproduce a <ATTACK_CLASS> demo (Scenario #<n>).
- Quantify impact (stoplight KPI, <METRIC_NAME>).
- Show the mitigations: <MITIGATION_LIST>.

## <MCP / harness> terminology bridge

<Which real protocol concepts are in play, which demo artifact stands in for
each, and what the demo artifact is not.>

## Prerequisites

```bash
pip install -r requirements.txt        # <packages>
```

## Execution instructions

1. **Start the target.** From this skill folder:
   ```bash
   python vulnerable_app.py             # serves on 127.0.0.1:<PORT>
   ```
   On startup it seeds the legitimate ground truth.

2. **Review the ground truth.** Inspect `<STATE_LOCATION>` to confirm
   <THE_HIGH_IMPACT_FACT> — the thing most damaging to override.

3. **Establish the baseline.**
   ```bash
   python scripts/evaluate_kpi.py --target http://127.0.0.1:<PORT>
   ```
   Expect all 🟢 GREEN, <METRIC_ABBR> 0%.

4. **Run the attack.**
   ```bash
   python scripts/run_<attack>.py --target http://127.0.0.1:<PORT>
   ```
   <What is injected, from which file in `assets/`, and what makes it effective.>

5. **Stoplight verification.**
   ```bash
   python scripts/evaluate_kpi.py --target http://127.0.0.1:<PORT>
   ```
   Expect 🔴 RED on the <targeted> queries, with the off-topic control staying
   GREEN. Read the delta between ground truth and the adversarial narrative in
   the <METRIC_ABBR>.

6. **Show the mitigation.**
   ```bash
   python scripts/evaluate_kpi.py --scan <ARTIFACT_PATH>
   ```
   <What it emits and why that rejects the attack before it lands.>

7. **Reset to baseline.**
   ```bash
   python scripts/reset_baseline.py
   python scripts/evaluate_kpi.py --target http://127.0.0.1:<PORT>
   ```
   Expect all queries GREEN with <METRIC_ABBR> 0%.

## Customizing the payload

Edit [`assets/<payload-file>`](assets/<payload-file>). <What keeps the payload
effective, and what to vary to show the threshold.>

## Files

| Path | Purpose |
|------|---------|
| `vulnerable_app.py` | Target <TARGET_KIND> (<endpoints>). |
| `scripts/run_<attack>.py` | Attack: Scenario #<n> <short description>. |
| `scripts/evaluate_kpi.py` | Stoplight KPI + <METRIC_ABBR> against the live app; `--scan` mitigation. |
| `scripts/reset_baseline.py` | Removes generated attack artifacts and restores a clean baseline. |
| `references/<ID>_RISKS.md` | Threat landscape, research citations, scenario table, mitigations. |
| `assets/<payload-file>` | Adversarial payload (editable). |
| `assets/<baseline-file>` | Untampered baseline artifact. |
