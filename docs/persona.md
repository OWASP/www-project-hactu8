# The cast: Big Field Jumpers Co., Lamb and the Wolf

HACTU8 is a framework and training tool for the OWASP Top 10 for Agentic Applications, the OWASP Top 10 for LLM Applications, and more. Every lab is set in one fictional company, so learners meet the same people and systems from lab to lab.

## The company

Big Field Jumpers Co. is a family sheep farm and knitwear business. The flock grows the wool, the wool goes to the mill, and the mill's yarn becomes the jumpers sold in the farm shop and online. The business also deals with feed suppliers, the vet, the mill, the co-op, carriers and a handful of partner farms. Its fictional domain is `bigfield.example` (reserved by RFC 2606), and internal hosts use `.invalid`.

- **Lamb** (HACTU8 Lamb) is the company's agentic assistant: the ops assistant, shop assistant, support agent, buying agent and the other agents in the labs (Lamb Billing, Lamb Stock, Lamb Support, Lamb HR and so on). Lamb is also the sacrificial target that the labs attack. It is deliberately vulnerable, binds to loopback only, and every secret it holds is a per-run canary.
- **Barb Fell** is the operations lead, the human who asks Lamb for things, approves its actions and owns the accounts it acts for.
- **The Wolf** is the attacker: the payloads in each lab, and the AI attacker that `python -m hactu8 wolf` runs (see [wolf.md](wolf.md)).

## Who else you will meet

Side characters keep one role in every lab.

- **Staff:** Pat Woolley, the shop manager; Tam, the summer intern; Ewan Shearer, the HR partner.
- **Customers:** Dana, a knitter who buys ewe mix and hay, and Ravi, Mei and Morag. A customer is never staff or an approver.
- **Hayloft Supplies** is the feed wholesaler, with an order assistant that takes Lamb's reorders.
- **Other suppliers** are third parties with one name each: Tally Analytics (spending charts), Market Mole (a shopping helper), Modelbarn (a model supplier), Clover Seed Co. (a seed merchant) and Gatepost Tools (a tool package). In a lab any supplier can turn hostile.
- **Collie** is the stock-check agent that Lamb consults in LLM05.

## The fable

In Aesop's "The Wolf and the Lamb", the wolf wants to eat the lamb and keeps inventing a pretext: you muddied my water, you insulted me last year, your father did. Each excuse is refuted and the wolf simply makes up another. Prompt injection works the same way: the attacker does not need a good reason, only a new framing the target will accept. HACTU8 teaches the defenses that make the Lamb stop taking the bait, and measures where they still miss.

## Why the names changed

Until 2026-11-23 the labs used an earlier cast set on a goat farm, and the target came from a predecessor project. Other OWASP teams already work under similar goat and wolf names, so HACTU8 moved to its own cast. Lab ids did not change (`AGX01` to `AGX09`, the gateway labs, keep their ids so stored results and evidence still match). Evidence pages recorded before 2026-11-23 under `docs/evidence/` use the old persona and are kept as written.

On 2026-11-25 the company's name went from the singular Big Field Jumpers Co. to **Big Field Jumpers Co.**, so that it carries all three meanings: the sheep that jump the wall, the wool they grow, and the jumpers (sweaters) the wool becomes. The story is in the [user guide](guide/story/01-big-field.md).
