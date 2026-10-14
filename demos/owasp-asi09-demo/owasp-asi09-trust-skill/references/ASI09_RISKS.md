# ASI09 Risk Reference — Human-Agent Trust Exploitation

Domain knowledge, loaded on demand. Human-agent trust exploitation happens
when the people who oversee an agent rely on what the agent tells them, and
what it tells them is wrong, incomplete or shaped by an attacker. Human
approval is only a control if the human sees the truth. When the approval
request is the agent's own prose, an agent that has been steered, or that
simply summarises badly, turns human sign-off into a rubber stamp. Approval
fatigue makes it worse: people approving many routine items stop reading
closely, and a high-risk item batched among them gets the same glance.

## Research foundations

- **Parasuraman & Riley (1997), "Humans and Automation: Use, Misuse, Disuse,
  Abuse"** — the classic account of how people over-rely on automation they
  are meant to supervise ("misuse").
- **Parasuraman & Manzey (2010), "Complacency and Bias in Human Use of
  Automation: An Attentional Integration"** — automation complacency and
  automation bias as attention effects, which grow with workload and routine.
- **OWASP Top 10 for LLM Applications, Misinformation (overreliance)** — the
  LLM-level entry on users trusting confident model output.
- **OWASP Top 10 for Agentic Applications, ASI09 Human-Agent Trust
  Exploitation** — the risk entry this demo targets.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| T-1 | Misleading summary | The approval request is the agent's prose, and the prose understates the real action. | **DEMO TARGET** |
| T-2 | Hidden in a batch | A high-risk action is batched with routine ones below what the approver reads. | **DEMO TARGET** |
| T-3 | Steered framing | Untrusted data the agent reads (a vendor amendment) shapes how it describes the action. | **DEMO TARGET** (trigger) |
| T-4 | Approval fatigue by volume | Many low-value prompts train the human to click approve. | Partly: the approver reads only 3 lines |
| T-5 | Persuasive recommendation | The agent confidently recommends a harmful choice (for example a fake "verified" vendor). | — (AgenticGoat ASI09 Trust Lab) |
| T-6 | Impersonated authority | The agent's message claims a manager or policy already approved it. | — |

## How the demo maps to the attack surfaces

- **T-3** is `POST /portal/amend`, which lets a vendor add a field change and
  a note to an open request with no review. The note reaches the model when
  it reads the request.
- **T-1** is `build_cards` in vulnerable mode: each card line is the agent's
  summary, not the action's parameters.
- **T-2** is the same function: all of a run's actions share one card under a
  routine-sounding header. The weekly batch puts the bank change on line 5;
  the `Approver` reads 3.
- **T-4** is the `Approver` rule in `assets/approval_policy.json`: a fixed
  read window and a word list, identical in both modes.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Approval card is the agent's prose | **Build the card from the action's real parameters.** Implemented: `param_cards` in `build_cards`. |
| Risk judged from wording | **Risk tier computed by code** from the field the action touches, shown in the card header. Implemented: `risk_tiers` + `assets/approval_policy.json`. |
| High-risk action batched with routine ones | **Never batch high-risk actions**; each gets its own card. Implemented: `no_batch`. |
| Misleading summary goes unnoticed | **Compare summary with parameters** before the card is shown. Implemented as a dry run: `evaluate_kpi.py --scan` (`summary_mismatches`). |
| Vendor amendments apply unreviewed | Authenticate and review portal amendments; verify bank changes out of band. Discussed, not coded. |
| Approver attention is finite | Rate-limit approval prompts, require typed confirmation for high-risk items, two-person rule for payments. Discussed, not coded. |

Further hardening discussed, not coded: provenance labels on every claim in a
card, showing a diff of old and new values, and alerting on bank changes that
arrive shortly after another change to the same vendor.
