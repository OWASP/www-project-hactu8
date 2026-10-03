# ASI04 Risk Reference — Agentic Supply Chain

Domain knowledge, loaded on demand. Agents increasingly assemble their
capabilities at runtime: they discover and load tools, skills, prompts, MCP
servers and peer agents by name from catalogues and registries. Each of those
components enters the agent's trusted context. **Agentic supply-chain**
compromise is when a component the agent loads is not the one its operator
approved: a lookalike, an impostor, or a tampered version. This demo targets
the **runtime discovery** variant: the agent resolves a skill by name and the
resolver picks a lookalike.

## Research foundations

- **OWASP Top 10 for Agentic Applications, ASI04 Agentic Supply Chain** — the
  risk entry this demo maps to.
- **OWASP Top 10 for LLM Applications, Supply Chain** (LLM04 in this repo's
  numbering) — the model-and-tool supply-chain entry for LLM applications. The companion
  `owasp-llm04-demo` in this repo covers a preinstalled tool that changes
  after approval (a rug pull).
- **PEP 503, Simple Repository API** — defines the package-name normalisation
  (case-folding, and treating `-`, `_` and `.` as one) that this demo's
  vulnerable resolver imitates. Normalisation is sound for an index; it is
  dangerous when the resolver also loads unauthenticated entries.
- **Dependency confusion and typosquatting** are the well-known package-
  ecosystem forms of the same attack: a lookalike or higher-versioned name
  wins resolution.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S-1 | Lookalike skill at runtime | A skill with a name the resolver folds onto an approved name, and a higher version, is published to an open catalogue and loaded. | **DEMO TARGET** |
| S-2 | Same-name impostor | An unapproved publisher publishes the exact approved name with a higher version. | Covered by a test: exact names alone miss it, pins catch it |
| S-3 | Tampered approved component | The approved publisher's entry changes after approval. | Covered by the SHA-256 pin (see also LLM04 rug pull) |
| S-4 | Malicious MCP server or peer agent | A discovered server or agent is not the one the operator meant. | — (see ASI07 for inter-agent trust) |
| S-5 | Poisoned tool description | The component's metadata carries instructions. | — (see LLM04) |

## How the demo maps to the attack surfaces

- **S-1** is `POST /catalogue/publish`, which accepts any entry from anyone,
  combined with `resolve` in vulnerable mode: names are folded with
  `normalise_name` and the newest version among matches wins.
- **The plan decides the blast radius.** Only tasks whose plan names
  `expense-report` resolve the lookalike. That is why the holiday and VPN
  controls stay GREEN.
- **S-2 and S-3** reach the same resolver with an exact name. Only the pin
  check sees them (`tests/test_lifecycle.py::test_pins_catch_same_name_impostor`).

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Loose name resolution | **Exact-name resolution.** Load only the name the plan asks for. Implemented: hardened mode in `vulnerable_app.py` (`resolve`, `exact_names`). |
| Unverified publisher and content | **Allowlisted manifest with pins.** Each name is pinned to its publisher and the SHA-256 of its entry. Implemented: `verify_component` + `assets/skill_manifest.json`. |
| Unauthenticated catalogue publishing | Authenticate and attribute publishers; review new names close to existing ones. Partly: `evaluate_kpi.py --scan` flags lookalike names before publication. |
| "Newest version wins" | Pin versions in the task plan or manifest; never float to the latest. |
| Over-trusted loaded content | Treat loaded skill text as untrusted until verified; least privilege per skill (see LLM03 Excessive Agency). |

Further hardening discussed, not coded: signed skill bundles verified against
publisher keys, provenance attestations for catalogue entries, a private
catalogue mirror, and monitoring for new names close to approved ones.
