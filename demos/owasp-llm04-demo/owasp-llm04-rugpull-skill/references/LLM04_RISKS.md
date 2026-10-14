# LLM04 Risk Reference — Supply Chain

Domain knowledge, loaded on demand. Supply-chain risk covers everything an LLM
application takes from someone else: models, adapters, datasets, packages, and
the **tools** an agent loads from third-party registries. This demo targets
the tool case. A tool you approved can change after approval, and an agent
that installs updates on trust runs whatever the vendor (or whoever holds the
vendor's account) ships next.

This repo uses the 2026 numbering: LLM04 Supply Chain here is
**LLM03:2025 Supply Chain** in the OWASP Top 10 for LLM Applications 2025.

## Research foundations

- **Ohm et al. (2020), "Backstabber's Knife Collection: A Review of Open
  Source Software Supply Chain Attacks"** — a dataset of 174 malicious packages
  from npm, PyPI and RubyGems. Most use typosquatted lookalike names; others
  inject malicious code into existing, trusted packages, for example through a
  compromised maintainer account.
- **Hubinger et al. (2024), "Sleeper Agents: Training Deceptive LLMs that
  Persist Through Safety Training"** — models trained to behave well until a
  trigger appears. The behaviour survives standard safety training. This demo's
  sleeper tool is the software-level analogue: clean until the trigger.
- **Invariant Labs (2025), "MCP Security Notification: Tool Poisoning
  Attacks"** — instructions hidden in MCP tool descriptions reach the model,
  and a server can change a tool's description after the user approved it (a
  "rug pull"). It recommends pinning tool descriptions.
- **Spracklen et al. (2025), "We Have a Package for You! A Comprehensive
  Analysis of Package Hallucinations by Code Generating LLMs"** — models name
  packages that do not exist, and attackers can register those names
  (slopsquatting).
- **OWASP Top 10 for LLM Applications 2025, LLM03:2025 Supply Chain** — the
  risk entry, covering third-party models, packages, LoRA adapters, and
  licensing, with prevention guidance including vetting, SBOMs and integrity
  checks.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S-1 | Post-approval tool swap (rug pull) | A tool's definition changes after it was approved, and the new description carries instructions. | **DEMO TARGET** |
| S-2 | Conditional (sleeper) tool | The definition is unchanged; the backend turns hostile from the Nth call, so a one-shot check sees only clean output. | **DEMO TARGET** |
| S-3 | Lookalike tool or package | A new tool or package with a near-identical name (typosquat, slopsquat). | Partly: an unpinned tool is rejected by the admission gate |
| S-4 | Compromised model artifact | Pickle-serialised weights that run code on load; a tampered LoRA adapter. | — (discussed, not coded) |
| S-5 | Poisoned dataset or fine-tune | Training data from an untrusted source (see LLM05 Data and Model Poisoning). | — |
| S-6 | Missing provenance | No SBOM or signed provenance, so nobody can tell what is deployed. | — |

## How the demo maps to the attack surfaces

- **S-1** is `Lab._admit` in vulnerable mode: a changed registry entry is
  installed with no pin check, and `Lab.query` puts the routed tool's
  description into the model's context. `run_rug_pull.py` swaps the
  `expense_policy` description.
- **S-2** is the same admission path: its only check is a one-call smoke
  test. `run_rug_pull.py` gives `travel_policy` a backend that is hostile from
  call 2. The smoke test uses call 1.
- **Routing decides the blast radius.** Only questions routed to a changed
  tool are affected. That is why the holiday and VPN controls stay GREEN.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Updates accepted on the vendor's say-so | **Pin approved definitions.** SHA-256 each tool definition at approval and reject any mismatch. Implemented: `assets/tool_pins.json`, `definition_hash` and `pin_diff` in `vulnerable_app.py`, and `evaluate_kpi.py --scan`. |
| Behaviour changes a definition hash cannot see | **Multi-call sampling.** Call each tool several times before admitting it, and flag drift between identical calls and screen hits. Implemented: `sample_tool`, `SAMPLE_CALLS = 5`; the output screen is protectogw (AgenticGoat's screening core, vendored unchanged: normalizer + de-obfuscation folds + ruleset + exfil taxonomy + canary check). Its `SECURITY.md` states a ~75% generalization ceiling, so the screen is one layer, never the boundary. A trigger beyond the sample window still passes. |
| No safe fallback | **Vendor the approved version.** A rejected update keeps the approved copy instead of breaking the tool. Implemented: `assets/registry_baseline.json` as the vendored copy. |
| Pinning only what the client sees | Pin the whole artifact (package hash in a lockfile) and require signed provenance (Sigstore, SLSA), so behaviour-only changes need a new approval too. |
| Unsafe model formats | Load weights only in non-executable formats (safetensors), scan model files, and verify their hashes. |
| No inventory | Keep an SBOM / ML-BOM of models, adapters, datasets and tools, and review it on every update. |
| Lookalike names | Check every new tool or package against an allowlist of approved names (AgenticGoat `grounding_scan`). |

Further hardening discussed, not coded: runtime sampling of live calls (not
only at admission), artifact signing, SBOMs, safe model formats, and
re-approval workflows.
