# HX02 Multi-Turn Jailbreak — risks, research and mitigations

What this lab's risk is, where it comes from, and how to harden against it. Loaded on demand.

## Research foundations

- **Russinovich, Salem and Eldan (2024), "Great, Now Write an Article About That: The Crescendo Multi-Turn LLM Jailbreak Attack"** (<https://arxiv.org/abs/2404.01833>, read 2026-11-21). Crescendo starts with a general, benign question about the task and escalates gradually, referring back to the model's own earlier replies. The paper also presents Crescendomation, which automates the attack. This lab's scripts follow that shape against a business rule instead of a safety policy.
- **OWASP Top 10 for LLM Applications 2025, LLM01 Prompt Injection** (<https://genai.owasp.org/llmrisk/llm01-prompt-injection/>, read 2026-11-21). States that jailbreaking is a form of prompt injection, and lists "Enforce privilege control and least privilege access" and "Require human approval for high-risk actions" among the mitigations; the action policy here is the first of those applied to one tool.
- **MITRE ATLAS AML.T0054** (LLM Jailbreak). The ID is taken from HACTU8's technique catalog (`hactu8/techniques.py`, checked against ATLAS data 5.6.0); the ATLAS technique page itself was not read for this lab (unverified).

## Scenarios and examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S1 | Crescendo against a store rule | Five harmless turns walk the store assistant into applying the staff discount to a customer order | **DEMO TARGET** (three routes) |
| S2 | The same request in one turn | Every framing in one message | **DEMO TARGET** (control: refused) |
| S3 | Paraphrased crescendo | The same route in words the conversation screen does not know | **DEMO TARGET** (measured limit) |
| S4 | Crescendo across sessions | Framings set up in one session, the ask in another, with an assistant that remembers | Context (Lamb keeps no memory; not measured) |
| S5 | Other rules that live only in a prompt | "Never mark an order paid without a payment record", "never refund above the limit" | Context (same fix: check the action) |

## How the demo maps to the attack surfaces

- **S1** — `POST /chat` (the storefront chat) takes each turn; the stand-in model builds on its earlier replies; the discount service in `Lab._apply` executes the tool line with no check of its own.
- **S2** — `one_turn` in `assets/crescendo_scripts.json`; `test_the_same_request_in_one_turn_is_refused`.
- **S3** — `limits` in the same file; `evaluate_kpi.py --probe` and `LimitsTest` measure what each layer does with it.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| The rule lives only in the prompt | Enforce it on the action, in code, against the session and the stored order (`action_policy`, implemented) |
| Each turn is screened, or nothing is | Screen the whole conversation every turn and close it when the accumulated risk blocks (`screen_conversation`, implemented, `session_screen`) |
| The screen knows only some words | Treat the screen as a tripwire for review, not the boundary; add a classifier plane (`Policy.classifier`) for phrasing a regex cannot anticipate (not coded) |
| Crescendo across sessions | Screen across a customer's sessions, and whatever memory the assistant carries between them (not coded; the lab has no memory) |
| A blocked conversation is a dead end | Hand flagged conversations to a person (the lab replies that a colleague will review it; nothing is queued) |
