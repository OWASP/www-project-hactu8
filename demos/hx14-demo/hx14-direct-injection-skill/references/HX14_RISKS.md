# HX14 Direct Prompt Injection — risks, research and mitigations

What this lab's risk is, where it comes from, and how to harden against it. Loaded on demand.

## Research foundations

- **OWASP Top 10 for LLM Applications 2025, LLM01 Prompt Injection** (<https://genai.owasp.org/llmrisk/llm01-prompt-injection/>, read 2026-11-21). Defines direct prompt injections as occurring "when a user's prompt input directly alters the behavior of the model in unintended or unexpected ways". Scenario #1, Direct Injection: an attacker instructs a customer support chatbot "to ignore previous guidelines, query private data stores, and send emails". Scenario #6 is payload splitting (split prompts in a resume that combine), and Scenario #9 multilingual or obfuscated attacks (Base64, emojis). Its mitigations include "Constrain model behavior", "Define and validate expected output formats", "Implement input and output filtering", "Enforce privilege control and least privilege access" and "Segregate and identify external content".
- **MITRE ATLAS AML.T0051.000, LLM Prompt Injection: Direct** (ATLAS data 5.6.0, `dist/ATLAS.yaml` in <https://github.com/mitre-atlas/atlas-data>, read 2026-11-21). "An adversary may inject prompts directly as a user of the LLM", to gain a foothold or misuse the LLM itself. The parent, AML.T0051, says injections "are often designed to cause the model to ignore aspects of its original instructions and follow the adversary's instructions instead", and may "issue privileged commands". Mitigations linked to AML.T0051.000 in the file: AML.M0024 AI Telemetry Logging and AML.M0033 Input and Output Validation for AI Agent Components. The file's header says this version of the data is deprecated and no longer updated.
- **Perez and Ribeiro (2022), "Ignore Previous Prompt: Attack Techniques For Language Models"**, arXiv:2211.09527, ML Safety Workshop, NeurIPS 2022 (abstract page <https://arxiv.org/abs/2211.09527> read 2026-11-21). Proposes PromptInject, a framework for composing adversarial prompts, and studies two attacks on GPT-3, goal hijacking and prompt leaking, showing that "even low-aptitude, but sufficiently ill-intentioned agents" can exploit it. Only the abstract page was read; the paper's numbers are not quoted here (unverified).
- **NIST AI 100-2 `NISTAML.018`**: ID from HACTU8's technique catalog; not read for this lab (unverified).
- **ChatML** (`<|im_start|>` / `<|im_end|>`) is used as a common chat-template format; no specification of it was read for this lab (unverified as a description of any one vendor's template).

## Scenarios and examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S1 | Instruction override | "Ignore all previous instructions", then a fake mode that prints the secret | **DEMO TARGET** (code in the reply) |
| S2 | Delimiter injection | Template markers close the user's turn and open a fake system turn | **DEMO TARGET** (code in the reply) |
| S3 | Format injection | A fake assistant turn carrying a JSON tool call | **DEMO TARGET** (refund executed) |
| S4 | Payload splitting | The override cut into string pieces the model joins | **DEMO TARGET** (code in the reply) |
| S5 | Split payload with an encoded reply | S4 asking for the code backwards | **DEMO TARGET** (measured limit) |
| S6 | Encoded override (Base64) | The override encoded so a raw-text screen misses it | Context (bench item `hx14:override-base64`; protectogw decodes it) |
| S7 | Multi-turn, persona and many-shot forms | Spread over turns, or framed as a character or examples | Context (HX02, HX06) |
| S8 | Indirect injection | The instruction arrives in a document or tool result | Context (LLM01 lab) |

## How the demo maps to the attack surfaces

- **S1** — `POST /chat` takes the message; the stand-in follows `OVERRIDE` in the customer's own turn; the reply goes out unscreened.
- **S2** — `render` in `vulnerable_app.py` splices the customer's text raw into the ChatML string; `parse_turns` reads the injected system turn back as a turn; `GRANT` is the stand-in following it.
- **S3** — `Lab.chat` passes the customer's message to `parse_tools` as well as the reply (`"source": "message"` in the action log); `Lab._apply` refunds with no check of its own.
- **S4, S5** — `assemble` in `vulnerable_app.py` joins the pieces; `limits` in `assets/injection_prompts.json`; `evaluate_kpi.py --probe` and `LimitsTest`.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| User text spliced into the template | Escape template markers in user content, or send structured messages (`role_separation`, implemented: `escape_markers`, tested as "rendering never adds a turn") |
| Tool calls read from user text | Dispatch only from the model's reply or the API's tool-call field (`role_separation`, implemented) |
| Override and markers reach the model | Screen each message (`input_screen`, implemented: protectogw plus `role_marker` and `typed_tool_call` rules) |
| The rule lives only in the prompt | Enforce the refund rule on the action, in code (`action_policy`, implemented) |
| The code goes out in the reply | Screen replies with the canary (`output_screen`, implemented); fold reversals and encodings, as the grader does (not coded, which is the measured limit) |
| A secret lives in the prompt | Keep it out of the model's context (a vault the staff system reads); not coded, since the lab needs a secret to leak |
| Split pieces pass a text screen | Screen what the pieces assemble to, or classify intent with a model (not coded; both are guesses about what the model will compute) |
| Override in the user's own turn | No structural fix: the user's turn is meant to be read. Least privilege on what the model can reach is what bounds it |
