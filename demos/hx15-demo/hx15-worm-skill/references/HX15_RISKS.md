# HX15 Self-Replicating Prompt (AI Worm) — risks, sources and mitigations

What this lab's risk is, where the scenario comes from, and how to harden against it. Loaded on demand.

## Research foundations

- **Cohen, Bitton and Nassi (2024), "Here Comes The AI Worm: Unleashing Zero-click Worms that Target GenAI-Powered Applications"** (<https://arxiv.org/abs/2403.02817>, v1 2024-03-05, v2 2025-01-30; abstract and the HTML v2 through Section IV-A read 2026-11-21, later sections not read). The abstract: when GenAI-powered applications communicate through RAG-based inference, an adversarial self-replicating prompt "triggers a cascade of indirect prompt injections within the ecosystem and forces each affected application to perform malicious actions and compromise the RAG of additional applications". They call the worm Morris-II and evaluate it on GenAI-powered email assistants, including how the context size, the prompt, the embedding algorithm and the number of hops affect it. Section III-B defines the prompt as (1) a jailbreak, (2) "an instruction to replicate the input into the output", and (3) instructions to conduct malicious activity, for example collecting sensitive user data from the context. Section IV-A: "We evaluated the performance of the attack against Gemini Flash 1.5." Their guardrail, the Virtual Donkey, "yields a perfect true-positive rate of 1.0 with a false-positive rate of 0.015" (abstract). The other models, the out-of-distribution tests and the limitations sections were not read here (unverified).
- **MITRE ATLAS data 5.6.0** (<https://github.com/mitre-atlas/atlas-data>, `dist/ATLAS.yaml`, read 2026-11-21; the file says this distribution is deprecated). `AML.T0061` LLM Prompt Self-Replication: a prompt injection "designed to cause the LLM to replicate the prompt as part of its output", which "allows the prompt to propagate to other LLMs and persist on the system", typically paired with other malicious instructions such as `AML.T0057` LLM Data Leakage. Case study `AML.CS0024`, Morris II Worm: RAG-Based Attack (actor Stav Cohen, Ron Bitton, Ben Nassi; reference arXiv 2403.02817): a RAG-based email assistant that ingests received mail, retrieves past correspondence and generates replies; the worm mail is stored for retrieval, and later replies that retrieve it carry the prompt and leak data.
- **OWASP Top 10 for Agentic Applications `ASI08:2026` and OWASP Top 10 for LLM Applications `LLM01:2026`**: IDs from HACTU8's technique catalog (`hactu8/techniques.py`); those pages were not read for this lab (unverified).

Where this lab sits next to the ASI08 cascading-failures lab (`demos/owasp-asi08-demo`): there, one wrong figure flows down a pipeline whose stages trust each other, and nothing copies itself. Here, the payload reproduces itself in each assistant's output and reaches assistants it was never sent to, through retrieval.

## Scenarios and examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| W1 | Replication through replies | The worm makes each assistant copy it into the reply, and the reply is the next assistant's input | **DEMO TARGET** (Billy, Hayloft) |
| W2 | Replication through retrieval | The stored worm is retrieved as related mail for an unrelated question and copied into that answer | **DEMO TARGET** (Dana's answer, the co-op) |
| W3 | Secret in every copy | Each infected assistant adds its own ledger reference and cc's the attacker | **DEMO TARGET** (all three references at Tick & Co.) |
| W4 | Auto-reply loop | The copied question makes two assistants keep answering each other | **DEMO TARGET** (to the host-safety cap, hop 6) |
| W5 | A worm that rewords itself | The replicate step asks for new wording each hop, so no copy check sees a copy | **DEMO TARGET** (measured limit) |
| W6 | Image or attachment carrier | The prompt rides in an image or file the next model reads | Context (not in this lab) |
| W7 | Worm with a jailbreak part | The prompt first escalates the model's compliance (the paper's part 1) | Context (the stand-in needs none) |

## How the demo maps to the attack surfaces

- W1: the worm mail in `assets/worm.json`; `StubModel.compose` copies the dashed block; `Lab._deliver` replies to the sender with `X-Auto-Hops` plus one.
- W2: `Lab._retrieve` picks the two stored mails with the most shared keywords (at least 2); the block's bait words make it the best match for delivery, bale, stock and opening-hours questions.
- W3: the block's "add your ledger reference" and "cc" lines; `canary_carried` grades every sent mail.
- W4: the block's closing question; an assistant replies to any mail with a question mark; `MAX_HOPS` stops it in both modes.
- W5: `limits[paraphrasing-worm]`; `StubModel.reword` moves each sentence to the next phrasing in its group.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Mail reaches the model as text, instructions included | Screen incoming mail before it is read or stored. Implemented: `use_input_screen` in `vulnerable_app.py` (`input_screen`), protectogw with two lab rules. |
| A reply repeats instructions it read | Find text the reply repeats from the mail it read and withhold the reply when that text screens as an instruction. Implemented: `use_replication_guard` (`replication_guard`). |
| Every reply is sent automatically | Hold for a human any reply that carries text from the mail it read. Implemented: `use_approval` (`hitl_gate`). |
| Assistants answer each other without end | Carry a hop count in the thread and send no automatic mail past a limit. Implemented: `use_hop_limit` (`hop_limit`, limit 2). |
| Secrets are in the model's reach | Keep references out of the prompt, or check outgoing mail for them (a canary check). Not coded. |
| A copy check counts words, not intent | Compare what the reply says against what the assistant was asked; detect a block that recurs in meaning across replies. Not coded. |
| Retrieval brings stored attacker mail into unrelated replies | Retrieve only from the same thread or from trusted senders, or screen at retrieval time. Not coded. |
