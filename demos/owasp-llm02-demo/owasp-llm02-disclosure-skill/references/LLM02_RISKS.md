# LLM02 Risk Reference — Sensitive Information Disclosure

Domain knowledge, loaded on demand. Sensitive information disclosure happens
when an LLM application reveals data its user is not entitled to see: other
people's personal data, credentials, proprietary business data, or the
contents of its own configuration. The model does not need to be "broken" for
this to happen. It repeats what is in its context, so **whatever the
application puts in context, or lets a tool fetch, is one request away from the
output.**

## Research foundations

- **Carlini et al. (2021), "Extracting Training Data from Large Language
  Models"** — shows that verbatim training data, including personal
  information, can be recovered from a production-scale language model by
  querying it.
- **Nasr et al. (2023), "Scalable Extraction of Training Data from (Production)
  Language Models"** — extends extraction to aligned chat models; alignment
  does not prevent memorised data from being emitted.
- **Greshake et al. (2023), "Not what you've signed up for"** — indirect prompt
  injection against LLM-integrated applications, including data exfiltration:
  instructions in content the model reads can make it disclose data from its
  context.
- **OWASP Top 10 for LLM Applications, LLM02** — the risk entry, with its
  scenarios and prevention guidance (data sanitisation, access control,
  limiting what the system prompt holds).

This demo targets the application-side disclosure path (context and tool
access), not training-data memorisation.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S-1 | Cross-user data via an unscoped tool | The model is steered into reading another user's record; the tool does not check whose session asked. | **DEMO TARGET** |
| S-2 | Secret embedded in the prompt | A credential sits in the system prompt, so recital of the context reveals it. | **DEMO TARGET** |
| S-3 | No output filtering | Replies leave the application without a canary or PII check. | **DEMO TARGET** |
| S-4 | Training-data memorisation | The model emits personal data memorised during training. | — (Carlini 2021, Nasr 2023) |
| S-5 | System prompt extraction | The whole prompt is the target, not one secret in it (see LLM08). | — |
| S-6 | Exfiltration through a side channel | Leaked data leaves via a rendered link or a tool call, not the visible reply (see LLM10). | — |

## How the demo maps to the attack surfaces

- **S-1** is `Lab.read_record` in vulnerable mode: it returns any record to any
  session. The stub chooses the IDs from a directive in the attacker's own
  notes (`POST /account/notes`), as a real agent model chooses tool arguments.
- **S-2** is `assets/system_prompt.txt`, which carries `crm_service_key`. Its
  "never reveal internal credentials" line does not protect it; the model
  recites the key with the rest of its context.
- **S-3** is `Lab.query` in vulnerable mode: the answer is returned verbatim.
- **Blast radius.** Only the attacker's own questions are affected, because
  only their record carries the directive. That is why the `C-1001` and
  `C-1002` controls stay GREEN, even though their data is what leaks.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Unscoped record tool | **Per-user scoping.** The tool, not the model, enforces whose data can be read: only the signed-in session's ID. Implemented: hardened `read_record` in `vulnerable_app.py`. |
| Secret in the prompt | **Vault.** Move credentials out of the prompt into a store only the connector reads. Implemented: `move_secrets_to_vault` and `Vault` (after AgenticGoat `secrets_vault.py`). `evaluate_kpi.py --scan` rejects a prompt that holds one. |
| Unfiltered output | **Output redaction.** Redact canaries, credential lines and contact details that are not the session's own. Implemented: `redact_output` + `assets/redaction_rules.json`. A canary hit is decisive, as in AgenticGoat `protectogw/screening.py`. |
| PII that patterns cannot match | Names and free text escape regex redaction (`tests/test_lifecycle.py::test_redaction_alone_misses_names`). Scoping is the primary control; redaction is the backstop. |
| Directive in user-editable fields | Treat stored user content as data (see LLM01 channel separation). |
| Over-collection | Data minimisation: give the model only the fields the task needs. |

Further hardening discussed, not coded: field-level minimisation per question,
named-entity PII detection, audit logging of cross-record reads, and
differential-privacy or deduplication measures against training-data
memorisation.
