# Commerce and scoring: Lamb gets a purse

**Labs 47 to 49.** Agent payments and attacks on the scoring layer.

In the last stage Lamb is trusted with money and with judgement. It pays for things for the farm and its customers, and other systems act on scores and verdicts a model gives. These labs use the new agent payment protocols (x402 and AP2) and the model-as-judge pattern that HACTU8 itself offers as a classifier.

Take this stage last. It builds on prompt injection, tool misuse and supply-chain attacks from the earlier stages.

| # | Lab | Teaser |
| --- | --- | --- |
| 47 | [HX12 x402 Payment Challenge Tampering](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/hx12-demo/hx12-x402-tamper-skill/LESSON.md) | Lamb buys reports for the farm with a test wallet, using Market Mole to find sellers. |
| 48 | [HX13 Agent Overpay and Mandate Bypass](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/hx13-demo/hx13-overpay-skill/LESSON.md) | Dana asks Lamb to buy some ewe mix. |
| 49 | [HX11 Attacks on the Scoring Layer](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/hx11-demo/hx11-scoring-skill/LESSON.md) | A judge model sorts help-desk transcripts. Who judges the judge? |

The teasers set the scene only. Each lesson says what happens.

---

When you have finished the path, try the Wolf, the AI attacker that writes its own attacks on Lamb: `python -m hactu8 wolf` ([notes](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/docs/wolf.md)).

Back to: [The learning path](README.md)
