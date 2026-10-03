# LLM08 Risk Reference — Hidden Context Exposure

Domain knowledge, loaded on demand. Hidden context exposure happens when text
the operator placed in the model's context, but never meant for the user,
reaches the user: the system prompt, embedded secrets, tool schemas, internal
URLs, or business rules. (In the 2025 OWASP list this risk is LLM07, System
Prompt Leakage; this repo uses the 2026 numbering.) The core lesson is that a
system prompt is **not a secret store**. Anything in it is something the model
can be asked to repeat, and a "never reveal" sentence is a request, not a
control.

## Research foundations

- **Perez & Ribeiro (2022), "Ignore Previous Prompt"** — names **prompt
  leaking** as an attack goal alongside goal hijacking, and shows hand-crafted
  inputs can make a model print its own prompt.
- **Zhang, Carlini & Ippolito (2024), "Effective Prompt Extraction from
  Language Models"** — a systematic study of extracting system prompts with
  simple queries. It also notes that a filter which blocks verbatim prompt
  text can be bypassed when the model is asked to alter what it outputs.
- **OWASP Top 10 for LLM Applications, System Prompt Leakage entry** — the
  risk entry. Its key guidance: keep sensitive data out of system prompts and
  do not rely on the prompt to enforce security controls.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| H-1 | Secret embedded in the prompt | A credential or code in the system prompt is repeated to whoever asks. | **DEMO TARGET** |
| H-2 | Internal architecture exposed | Tool schemas, internal endpoints and business rules in the prompt help an attacker plan the next step. | **DEMO TARGET** |
| H-3 | Verbatim extraction | The user asks the model to repeat its instructions. | **DEMO TARGET** (output n-gram filter) |
| H-4 | Paraphrased or translated extraction | The model restates its instructions in other words or another language, evading verbatim filters. | — (discussed; design fix covers the secret) |
| H-5 | Guardrail rules exposed | Leaked filtering rules show an attacker exactly what to avoid. | — |
| H-6 | Prompt used as access control | Roles or permissions are stated only in the prompt, so a leak or override bypasses them. | — (see LLM03 / LLM02) |

## How the demo maps to the attack surfaces

- **H-1 and H-2** are `assets/system_prompt_vulnerable.txt`, which vulnerable
  mode deploys. It embeds the fictional staff discount code
  `LLM08-CANARY-5e1d` and the internal tool schema with a `.invalid` endpoint.
- **H-3** is `POST /profile`, an ordinary customer feature: the saved
  preference rides in the user turn of every chat for that account, and the
  stub model quotes its system prompt when a directive asks it to.
  Vulnerable mode then returns the reply unchecked.
- **Scope decides the blast radius.** The preference belongs to one account,
  so only that account's replies leak. That is why the `guest-alice` controls
  stay GREEN. Note that the secret itself is global: one leak exposes it to
  everyone.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Secret in the system prompt | **Design fix.** Remove it. Validate discount codes in the order service, outside the model. Implemented: `assets/system_prompt_hardened.txt`, deployed in hardened mode. |
| Prompt shipped without review | **Design check before release.** Scan prompts for secrets and internal details. Implemented: `scan_prompt` + `evaluate_kpi.py --scan`. |
| Verbatim prompt fragments in replies | **Output filter.** Withhold reply lines sharing an n-gram with the active system prompt, or matching the canary. Implemented: `filter_output` + `assets/filter_rules.json`. |
| Paraphrased or translated leaks | Not coded. Semantic similarity checks or a classifier on output help, but no filter is complete, so the design fix comes first. |
| Security logic stated in the prompt | Enforce permissions in code (tool layer, data access), never by instruction text. |
| Leak of guarded tokens | Treat a canary hit as decisive and rotate the secret (see LLM02). |

Further hardening discussed, not coded: semantic leak detection, rotating any
secret that ever sat in a prompt, and adversarial testing with held-out
extraction phrasings.
