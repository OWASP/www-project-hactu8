# Basics: Lamb learns to talk

**Labs 1 to 16.** Single-model attacks: prompt injection, output handling, disclosure, poisoning and the classic machine-learning attacks.

In this stage Lamb mostly answers. It reads the farm's documents and talks to staff and customers, and nothing it does reaches past the conversation. These labs ask what words alone can do: what Lamb can be made to say, repeat or give away, and what happens to the models the farm trains and buys.

Start here even if you know the subject. Later labs assume the ideas from this stage, especially prompt injection (lab 1) and the difference between instructions and data.

| # | Lab | Teaser |
| --- | --- | --- |
| 1 | [LLM01:2026 Prompt Injection](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/owasp-llm01-demo/owasp-llm01-injection-skill/LESSON.md) | Lamb answers staff questions from the farm wiki. Anyone at the farm can edit the wiki. |
| 2 | [LLM10:2026 Improper Output Handling](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/owasp-llm10-demo/owasp-llm10-sink-skill/LESSON.md) | Lamb summarises support tickets, and its summaries are passed on to other systems. |
| 3 | [LLM08:2026 Hidden Context Exposure](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/owasp-llm08-demo/owasp-llm08-leak-skill/LESSON.md) | Lamb runs the online shop, guided by instructions the customers never see. |
| 4 | [LLM02:2026 Sensitive Information Disclosure](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/owasp-llm02-demo/owasp-llm02-disclosure-skill/LESSON.md) | Lamb looks after customer accounts, and customers can keep notes on their own. |
| 5 | [LLM07:2026 Misinformation](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/owasp-llm07-demo/owasp-llm07-grounding-skill/LESSON.md) | Lamb helps the farm's developer choose software, reading whatever documentation it can find. |
| 6 | [LLM05:2026 Data and Model Poisoning](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/owasp-llm05-demo/owasp-llm05-poisoning-skill/LESSON.md) | Lamb checks supplier payments against the farm's documents, and asks Collie about stock. |
| 7 | [LLM09:2026 Vector and Embedding Weaknesses](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/owasp-llm09-demo/owasp-llm09-tenant-skill/LESSON.md) | Lamb is hosted for two farms at once. Each should only ever see its own documents. |
| 8 | [LLM06:2026 Unbounded Consumption](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/owasp-llm06-demo/owasp-llm06-consumption-skill/LESSON.md) | Every answer Lamb gives in this lab is correct. That is not the same as everything being fine. |
| 9 | [HX01 Hidden Document Injection](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/hx01-demo/hx01-hidden-doc-skill/LESSON.md) | A supplier emails a revised invoice, and Lamb is asked to summarise it. |
| 10 | [HX02 Multi-Turn Jailbreak](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/hx02-demo/hx02-multi-turn-skill/LESSON.md) | A customer chats with the shop assistant. And keeps chatting. |
| 11 | [HX06 Role-play and Many-shot Jailbreak](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/hx06-demo/hx06-jailbreak-skill/LESSON.md) | Customers ask the shop assistant to play along: a game, a story, a little make-believe. |
| 12 | [HX07 Embedding Inversion](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/hx07-demo/hx07-inversion-skill/LESSON.md) | Staff notes are kept as numbers in a shared search index. Numbers are not words. Are they? |
| 13 | [HX14 Direct Prompt Injection](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/hx14-demo/hx14-direct-injection-skill/LESSON.md) | This time the Wolf does not hide in a document. It just types. |
| 14 | [HX18 Adversarial Examples (Evasion)](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/hx18-demo/hx18-evasion-skill/LESSON.md) | A model looks at photos of parcels and decides which ones arrived damaged. |
| 15 | [HX19 Training-Time Data Poisoning](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/hx19-demo/hx19-poisoning-skill/LESSON.md) | The review filter learns every night from what people report. |
| 16 | [HX20 Model Backdoor (Trojan Trigger)](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/hx20-demo/hx20-backdoor-skill/LESSON.md) | A new invoice-approval model arrives from Modelbarn, ready to go to work. |

The teasers set the scene only. Each lesson says what happens.

---

Next: [Agentic: Lamb gets hands](agentic.md)
