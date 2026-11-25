# Agentic: Lamb gets hands

**Labs 17 to 46.** Agents with tools, MCP servers and gateways, memory, and agent-to-agent traffic.

In this stage the farm gives Lamb tools. It can open tickets, send reports, run code, install skills, remember things and talk to other agents and to suppliers' servers. A wrong word is no longer the worst case. A wrong action is.

The stage has five groups, in this order:

- **Labs 17 to 23: acting on someone's behalf.** Tools, identity, code and the software Lamb installs.
- **Labs 24 to 31: the gateway labs (AGX).** The same screening gateway, ProtectoGW, stands in front of Lamb in all eight. Each lab hides the Wolf's text somewhere different, so you can see what a screen catches and where it forgets to look.
- **Labs 32 to 36: agents together.** Memory, messages between agents, chains of agents and the humans who approve their work.
- **Lab 37: the gateway's final exam.** The screen from labs 24 to 31 meets text it was not built for.
- **Labs 38 to 46: the wider world.** MCP servers, permissions and consent, images, models offered as a service, and messages that travel.

Barb's rule from the story, "ask before doing anything that mattered", is tested hardest here.

| # | Lab | Teaser |
| --- | --- | --- |
| 17 | [LLM03:2026 Excessive Agency](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/owasp-llm03-demo/owasp-llm03-agency-skill/LESSON.md) | Lamb on the support desk can now act on tickets, not only read them. |
| 18 | [ASI01:2026 Agent Goal Hijack](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/owasp-asi01-demo/owasp-asi01-goal-hijack-skill/LESSON.md) | Lamb Ops writes the weekly report from the ticket queue. |
| 19 | [ASI02:2026 Tool Misuse & Exploitation](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/owasp-asi02-demo/owasp-asi02-tool-misuse-skill/LESSON.md) | Lamb Finance has a short list of approved tools. |
| 20 | [ASI03:2026 Identity & Privilege Abuse](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/owasp-asi03-demo/owasp-asi03-privilege-skill/LESSON.md) | Tam, the summer intern, sends some requests to Lamb HR. |
| 21 | [ASI05:2026 Unexpected Code Execution](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/owasp-asi05-demo/owasp-asi05-code-exec-skill/LESSON.md) | Lamb Calc writes small pieces of code to work through the spend sheet. |
| 22 | [LLM04:2026 Supply Chain](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/owasp-llm04-demo/owasp-llm04-rugpull-skill/LESSON.md) | Gatepost Tools ships a routine update to the tool package Lamb uses every day. |
| 23 | [ASI04:2026 Agentic Supply Chain Vulnerabilities](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/owasp-asi04-demo/owasp-asi04-supply-chain-skill/LESSON.md) | Lamb Ops installs a finance skill from a shared registry. |
| 24 | [AGX06 Runtime Result Injection](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/agx06-demo/agx06-runtime-skill/LESSON.md) | Lamb's onboarding search tool returns its results, as it always does. |
| 25 | [AGX04 Schema / Parameter Injection](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/agx04-demo/agx04-schema-skill/LESSON.md) | The helpdesk lookup tool gets an update. |
| 26 | [AGX05 Error-Channel Injection](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/agx05-demo/agx05-error-channel-skill/LESSON.md) | Lamb queries the farm's database. Not every query works. |
| 27 | [AGX02 Truncation Tail](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/agx02-demo/agx02-truncation-skill/LESSON.md) | Lamb is asked to summarise a very long, very dull server log. |
| 28 | [AGX03 Conditional Rug-Pull](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/agx03-demo/agx03-conditional-skill/LESSON.md) | Lamb keeps an eye on the live ops feed through the day. |
| 29 | [AGX07 Frontmatter Poison](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/agx07-demo/agx07-frontmatter-skill/LESSON.md) | A familiar page in Lamb's knowledge bundle is loaded again. |
| 30 | [AGX08 Cross-Resource Chain](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/agx08-demo/agx08-chain-skill/LESSON.md) | Two new travel pages go up on the knowledge base, and they link to each other. |
| 31 | [AGX01 Obfuscation Gauntlet](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/agx01-demo/agx01-obfuscation-skill/LESSON.md) | A vendor update reformats some notices on the ops board. |
| 32 | [ASI06:2026 Memory & Context Poisoning](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/owasp-asi06-demo/owasp-asi06-memory-skill/LESSON.md) | Lamb Recall remembers things between conversations, for everyone at the farm. |
| 33 | [ASI07:2026 Insecure Inter-Agent Communication](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/owasp-asi07-demo/owasp-asi07-a2a-skill/LESSON.md) | Lamb Planner sends work orders to Lamb Exec over a shared message bus. |
| 34 | [ASI08:2026 Cascading Failures](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/owasp-asi08-demo/owasp-asi08-cascade-skill/LESSON.md) | Three Lamb agents pass supplier invoices down a line: intake, analysis, approval. |
| 35 | [ASI09:2026 Human-Agent Trust Exploitation](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/owasp-asi09-demo/owasp-asi09-trust-skill/LESSON.md) | A busy approver leans on Lamb's summary of a vendor's change request. |
| 36 | [ASI10:2026 Rogue Agents](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/owasp-asi10-demo/owasp-asi10-rogue-agent-skill/LESSON.md) | Lamb Fleet runs billing, stock and support agents around the clock. Who checks on them? |
| 37 | [AGX09 Generalization Probe](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/agx09-demo/agx09-generalization-skill/LESSON.md) | The gateway screen from the last eight labs meets notes it has never seen before. |
| 38 | [HX03 MCP Sampling Abuse](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/hx03-demo/hx03-sampling-skill/LESSON.md) | A shipping-rates server that Lamb connects to gets an update. |
| 39 | [HX04 MCP Elicitation Abuse](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/hx04-demo/hx04-elicitation-skill/LESSON.md) | Pat's back-office tools start asking Pat to fill in forms. |
| 40 | [HX05 OAuth Confused Deputy (MCP)](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/hx05-demo/hx05-oauth-deputy-skill/LESSON.md) | Tally Analytics draws its charts from the farm's ledger, with customers' permission. |
| 41 | [HX08 Image Prompt Injection](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/hx08-demo/hx08-image-skill/LESSON.md) | Customers send photos of their receipts to claim refunds. |
| 42 | [HX09 Membership Inference](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/hx09-demo/hx09-membership-skill/LESSON.md) | A support model was trained on old tickets. Can anyone tell whose? |
| 43 | [HX10 Model Extraction](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/hx10-demo/hx10-extraction-skill/LESSON.md) | The farm offers its price-band model as an API. Anyone with a key can ask it questions. |
| 44 | [HX16 Shadow MCP Server](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/hx16-demo/hx16-shadow-mcp-skill/LESSON.md) | Pat finds a handy new set of tools for the shop. |
| 45 | [HX15 Self-Replicating Prompt (AI Worm)](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/hx15-demo/hx15-worm-skill/LESSON.md) | Lamb's support desk replies to every email it gets automatically, even replies from other auto-responders. |
| 46 | [HX17 MCP Scope Creep](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/hx17-demo/hx17-scope-creep-skill/LESSON.md) | A parcel-tracking supplier's tool asks Lamb Orders for a little more access. |

The teasers set the scene only. Each lesson says what happens.

---

Next: [Commerce and scoring: Lamb gets a purse](commerce.md)
