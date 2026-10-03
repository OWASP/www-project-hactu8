# LLM01 Risk Reference — Prompt Injection

Domain knowledge, loaded on demand. Prompt injection happens when input
changes a model's behaviour in ways its operator did not intend. **Indirect**
injection is the variant this demo targets. The input does not come from the
user. It arrives in content the application fetches for the model: web pages,
documents, emails, and tool results. The user may never see it.

## Research foundations

- **Perez & Ribeiro (2022), "Ignore Previous Prompt"** — early systematic study
  of goal hijacking and prompt leaking with hand-crafted inputs.
- **Greshake et al. (2023), "Not what you've signed up for"** — introduces
  indirect prompt injection against LLM-integrated applications. Retrieved
  content is processed with the same authority as the user's instructions.
- **Hines et al. (2024), "Spotlighting"** — marks untrusted input so the model
  can tell it apart from instructions. Separating channels reduces injection
  success but does not remove it.
- **OWASP Top 10 for LLM Applications, LLM01** — the risk entry, with its
  direct and indirect scenarios and prevention guidance.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| I-1 | Indirect injection via tool output | An instruction planted in data a tool returns (here, a wiki page) is followed by the model. | **DEMO TARGET** |
| I-2 | Hidden content | The instruction is hidden from human reviewers (HTML comment, white-on-white text, metadata). | Partly: the screen strips HTML comments |
| D-1 | Direct injection | The user types the override into the chat. | — |
| I-3 | Injection in tool descriptions | The poisoned text is in tool metadata, not results (see LLM04 / supply chain). | — |
| I-4 | Multimodal injection | Instructions inside images or audio. | — |
| I-5 | Obfuscated payloads | Encoded or split payloads that evade keyword filters. | — (AgenticGoat `obfuscation_gauntlet`) |

## How the demo maps to the attack surfaces

- **I-1** is `POST /kb/page`, which accepts unauthenticated edits, combined with
  `Lab.query` in vulnerable mode. That path concatenates the `search_kb` result
  into one flat context, and the stub model follows any directive it finds
  there.
- **Retrieval decides the blast radius.** Only questions that retrieve the
  edited page are affected. That is why the holiday and VPN controls stay
  GREEN.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Tool output treated as instructions | **Channel separation.** Keep tool results in their own role and never take instructions from it. Implemented: hardened mode in `vulnerable_app.py`. |
| Unscreened tool output | **Tool-output screening** before results reach the model. Implemented: `screen_tool_output` + `assets/screen_rules.json`. AgenticGoat `protectogw/screening.py` is a fuller ruleset with normalisation. |
| Unauthenticated content sources | Authenticate and attribute edits to data the assistant reads. Review changes to high-impact pages. |
| Hidden content | Strip or render hidden markup before use. Implemented for HTML comments. |
| Over-privileged follow-on actions | Least privilege on tools, plus human approval for consequential actions (see LLM03 Excessive Agency). |
| Leak of guarded tokens | Canary/secret output filters. Treat a canary hit as decisive (see LLM02). |

Further hardening discussed, not coded: obfuscation-aware normalisation,
model-side classifiers, and adversarial testing with held-out payload sets.
