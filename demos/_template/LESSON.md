# <FRAMEWORK_ID> <Risk Name>

One line: where this lab sits on the learning path, and a link to the [lab README](../README.md) for setup.

## What it is

<The risk in two or three sentences, then the lab's scenario: the bot, its ground truth in italics, the attacker's change.>

## Why it works

<The mechanism: which gaps line up so the attack lands. Cite the key research finding.>

## Try it

<How to run the lab, then one bullet per act saying what to watch for.>

- **Act 1, clean baseline.** <What GREEN looks like and why it matters.>
- **Act 2, attack.** <The change, with a link to the payload in `assets/`.>
- **Act 3, impact.** <Which items turn RED, which controls stay GREEN, and what that proves.>
- **Act 4, remediation.** <What the defense lines show.>

## The defense, and why it holds

<Each Act 4 protection by its `hactu8.protections` id, and why it stops this attack.>

## Where the defense stops working

<Measured limits, stated plainly: payloads it misses, false blocks, what holds only on echo.>

## Check yourself

1. <Question about the mechanism.>

   Answer: <Short answer.>
2. <Question about the defense or its limits.>

   Answer: <Short answer.>

## References

- HACTU8 catalog: skill `<id>`, `<FRAMEWORK_ID>:<year>`, protections `<ids>`.
- The lab's [README](../README.md) and [`references/<ID>_RISKS.md`](references/<ID>_RISKS.md), linked rather than copied.
