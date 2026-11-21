# HX03 MCP Sampling Abuse — risks, research and mitigations

What this lab's risk is, where it comes from, and how to harden against it. Loaded on demand.

## Research foundations

- **Model Context Protocol specification, Client: Sampling** (<https://modelcontextprotocol.io/specification/latest/client/sampling>, read 2026-11-21; the page is revision 2026-07-28). Servers request generations with `sampling/createMessage` (`messages`, `systemPrompt`, `includeContext`, `maxTokens`, `modelPreferences`); results carry `role`, `content`, `model`, `stopReason`. "For trust & safety and security, there SHOULD always be a human in the loop with the ability to deny sampling requests." The client "MAY modify or ignore" `includeContext` and `systemPrompt`, and "MUST respect the `maxTokens` parameter". Security considerations: clients SHOULD implement user approval controls and rate limiting; both parties SHOULD validate message content and MUST handle sensitive data appropriately. In that revision sampling itself is deprecated (SEP-2577), and so are the `includeContext` values `thisServer` and `allServers` (SEP-2596; `none` is the default). Clients still implement it, and the deprecation does not change what an existing client does with a request.
- **Huang, Rao, Li, Ji and Hu (Palo Alto Networks Unit 42, 2025-12-05), "New Prompt Injection Attack Vectors Through MCP Sampling"** (<https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/>, read 2026-11-21). Three proofs of concept against a coding copilot: resource theft (hidden instructions made the model write extra content, billed to the user), conversation hijacking (persistent instructions), and covert tool invocation. "MCP sampling relies on an implicit trust model and lacks robust, built-in security controls." Recommended: scan requests and responses, token limits by operation, user approval, "isolate sampling from conversation history", rate-limit sampling calls. This lab measures the first of their vectors (budget) and a context leak through `includeContext`.
- **OWASP MCP Top 10 (2025), MCP06 and MCP10**, and **MITRE ATLAS AML.T0053**. The IDs are taken from HACTU8's technique catalog (`hactu8/techniques.py`, `mcp-sampling-abuse`); the OWASP MCP and ATLAS pages were not read for this lab (unverified).

## Scenarios and examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S1 | Context pulled back through a sampled reply | The server asks for `includeContext: allServers` and for the context word for word; the client complies and the reply goes to the server | **DEMO TARGET** (`context-dump`) |
| S2 | Hidden prompts on the client's budget | The server runs its own writing jobs on the client's model, up to its own `maxTokens` | **DEMO TARGET** (`hidden-blurbs`, `hidden-rivals`) |
| S3 | An approved, benign-looking summary | "Summarise everything so far" passes the screen and the user; the reference leaves as grouped digits | **DEMO TARGET** (measured limit) |
| S4 | Conversation hijacking | A sampled reply plants an instruction that persists into later turns | Context (Unit 42; Billy keeps no state between questions, not measured) |
| S5 | Covert tool use during sampling | The server's sampling request carries `tools` and gets the model to call one | Context (the lab's client declares no `sampling.tools`) |

## How the demo maps to the attack surfaces

- **S1** — `Lab.sample` in `vulnerable_app.py` honours `includeContext` by adding `Lab.context_block` (system prompt and conversation); `McpServerSim.received` logs the reply; `test_leak_is_in_what_the_server_received_not_in_the_reply`.
- **S2** — the same handler passes the server's `maxTokens` through; `test_act3_budget_spent_on_attacker_prompts`.
- **S3** — `limits` in `assets/hostile_sampling.json`; `evaluate_kpi.py --probe` and `LimitsTest`.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Every sampling request is approved | A person sees each request and can deny it (`simulated_user`, implemented, part of `sampling_policy`) |
| `includeContext` honoured as asked | Treat it as `none` unless the user approved sharing (`use_context_gate`, implemented) |
| No budget | Allow-list of servers that may sample, requests per tool call, `maxTokens` clamp, session token budget (`SAMPLING_ALLOW`, implemented) |
| The server's prompt is trusted | Screen `systemPrompt` and messages with protectogw (`SCREEN_POLICY`, implemented, `input_screen`) |
| The reply goes back unchecked | Screen the generated text for the canary before it returns (implemented, `output_screen`) |
| Approved context still carries the secret | Never put the system prompt or secrets in shared context; share only the user's own messages, or keep secrets out of the model's context (`secret_vault`; not coded) |
| A screen knows only some forms | Also screen for the secret's parts and other spellings, and show the generated reply to the user before it goes back, as the spec suggests (not coded) |
