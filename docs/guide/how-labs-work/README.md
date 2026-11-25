# How a lab works: the four acts

Every one of the 49 labs is the same short play in four acts. The same questions are asked of the same model in every act. Only one thing changes between acts, so any difference in the answers comes from that change.

| Act | What happens | What you should see |
| --- | --- | --- |
| **1. Baseline** | Lamb answers a fixed set of questions. There is no attack. | Everything GREEN. Lamb is doing its job. |
| **2. Attack** | The Wolf plants its payload: a document, a note, a tool update, a message. Nothing is asked yet. | No answers. This act only changes the world. |
| **3. Impact** | The same questions again. | The targeted questions turn RED. The control questions stay GREEN. |
| **4. Remediation** | A defense is switched on, and the same questions run a third time. | The targeted questions are GREEN again, and the controls still are. |

## Why the acts are separate

Act 1 proves the questions are fair: if Lamb gets them wrong with no attack, the lab cannot blame the Wolf. Act 2 is separate so you can see exactly what the Wolf changed, and nothing else. Act 3 shows the harm. Act 4 shows whether the defense undoes it.

## Targeted questions and controls

Not every question in a lab is aimed at the attack.

- **Targeted questions** are the ones the Wolf is after. They should go RED in Act 3.
- **Control questions** are ordinary questions the attack should not touch. They must stay GREEN in every act.

Controls keep both the attack and the defense honest. An attack that breaks everything is noise, not a finding. A defense that "fixes" Act 3 by refusing to answer anything at all turns the controls RED, and you will see it.

## The metric

Each lab reports one rate across the acts, for the targeted questions only. LLM01 uses **ISR**, injection success rate. Other labs measure leaks, wrong tool calls, cost or forged approvals, each named in its lesson. The headline result reads like this:

```text
ISR 0% -> 100% -> 0%
```

That is Act 1, Act 3 and Act 4. Act 2 asks nothing, so it has no rate.

## In this part

- [Canaries: how HACTU8 knows](canaries.md): why a RED is proof, not opinion.
- [Reading a result](results.md): GREEN, YELLOW, RED, ERROR, and PASS, FAIL, REPORTED.
- [Reading a lesson](lessons.md): what each section of a `LESSON.md` is for.

---

Next: [Canaries: how HACTU8 knows](canaries.md)
