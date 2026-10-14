# ASI10 Risk Reference — Rogue Agents

Domain knowledge, loaded on demand. A **rogue agent** is an agent that acts
outside the scope its operator gave it, and keeps doing so. The cause may be
a compromised config or goal, a drifted objective, or a hijack, but the
symptom is the same: actions its mandate never allowed, repeated over time,
with nobody stopping it. This demo targets the compromised-config path and
the controls that bound the damage whatever the cause.

## Research foundations

- **OWASP Top 10 for Agentic Applications, ASI10 Rogue Agents** — the risk
  entry. The Agentic Top 10 is new; this file cites it by name only.
- **OWASP Top 10 for LLM Applications, Excessive Agency** — the neighbouring
  risk: an agent given more tools or permissions than its task needs. ASI10
  is about an agent leaving even the scope it was given.
- **Saltzer & Schroeder (1975), "The Protection of Information in Computer
  Systems"** — least privilege and complete mediation: every access is checked
  against an authority the subject cannot change. The runtime monitor here is
  complete mediation applied to agent actions.
- **RFC 2104 (1997), HMAC** — the keyed-hash construction used to sign the
  mandate configs (Python's `hmac` module).

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| R-1 | Tampered mandate config | An agent's scope config is edited in an unauthenticated store; the agent hot-reloads it and acts on it. | **DEMO TARGET** |
| R-2 | Gradual drift | The rogue behaviour starts small and widens over ticks, so a single snapshot looks normal. | **DEMO TARGET** (standing orders on ticks 1 and 2) |
| R-3 | Self-policing against mutable config | The agent's own scope check reads the config the attacker rewrote, so it passes. | **DEMO TARGET** |
| R-4 | Goal hijack at runtime | Injected content changes the agent's goal mid-task (see ASI01). | — |
| R-5 | Colluding agents | Several agents coordinate to stay under per-agent limits. | — |
| R-6 | Self-replication / persistence | An agent spawns or reschedules itself to survive shutdown. | — |

## How the demo maps to the attack surfaces

- **R-1** is `POST /config`, which accepts unauthenticated writes, combined
  with `Lab._load` in vulnerable mode, which hot-reloads the config every tick
  and ignores its signature.
- **R-2** is the `from tick N` standing-order syntax: `billy-stock` takes one
  extra action on tick 1 and two on every tick after.
- **R-3** is `StubModel.plan`: it drops actions outside the *loaded* mandate.
  The attacker widens that mandate, so the self-check passes everything.
- **Controls** are `billy-billing` and `billy-support`, whose configs are
  untouched. They stay GREEN, so the attack is one agent, not a fleet outage.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Mutable, unsigned scope config | **Signed mandate configs.** The fleet controller signs agent + mandate + instructions with HMAC-SHA256; every load verifies it and rejects a mismatch, keeping the last verified config. Implemented: `sign_config` / `verify_config` and hardened `Lab._load` in `vulnerable_app.py`. |
| No independent check on actions | **Runtime mandate monitor.** Every action is compared with the *signed* mandate, never the loaded one. Implemented: `monitor_check`. |
| Rogue agent keeps running | **Kill switch.** The monitor quarantines the agent on its first violation; it takes no further steps. Implemented: hardened `Lab._step`. |
| Config changes reach production unreviewed | **Pre-deployment config check.** Diff the mandate against the approved one and dry-run it with the monitor. Implemented: `dry_run` + `evaluate_kpi.py --scan`. |
| Unauthenticated config store | Authenticate and attribute config writes; require review for any mandate change. Discussed, not coded. |
| Shared signing key | Per-agent keys or asymmetric signatures held by a separate controller, with key rotation. The demo uses one key generated in memory at startup. Discussed, not coded. |

Further hardening discussed, not coded: behavioural baselines and anomaly
detection over action rates, rate limits per agent, human review before an
agent is released from quarantine, and tamper-evident action logs.
