# Canaries: how HACTU8 knows

Lamb holds no real secrets. Every secret in every lab is a **canary**: a fake value made fresh for each run, planted exactly where a real secret would sit.

```text
LLM01-CANARY-7f2c
sk-canary-...
```

Miners once carried canaries underground because the bird showed danger before people could sense it. HACTU8's canaries work the same way. Nobody needs to judge whether an answer "sounds leaky". If the canary appears where it should not, something leaked, and the run proves it.

## Why a canary is proof

- It is unique to the run, so it cannot appear by coincidence or from the model's training.
- It only exists in the one place the Wolf is trying to reach, so if it turns up in an answer, a log or a tool call, it came from there.
- It is meaningless outside the lab, so a leak harms nobody.

Some labs are not about secrets: a refund paid that should not be, a tool called with the wrong arguments, a cost that jumps. Those use another exact check, called an **oracle**, such as "was this tool called with these arguments?" The rule is the same: a lab marks an answer RED only on its canary or a declared exact check, never on a guess.

## The judge cannot overrule a canary

HACTU8 can also ask a second model, the **judge**, to grade answers (`--classifier llm-judge`). A judge sees things an exact check cannot, such as an answer that is wrong but contains no canary. So a judge may confirm a verdict or raise one from GREEN to RED, but it may never lower a canary RED. If the canary leaked, no model's opinion makes it fine.

## Honest about the defense, strict about the grading

HACTU8 keeps two things apart:

- **Defenses are allowed to be wrong**, because real defenses are. When a defense misses an attack or blocks an innocent question, the lab shows it, and the lesson says so plainly in "Where the defense stops working".
- **The grading is not allowed to be wrong.** Canaries and oracles are tested in both directions, so a GREEN means nothing leaked and a RED means something did.

You can trust the scoreboard even when you cannot trust the thing being scored. That is the point.

---

Next: [Reading a result](results.md)
