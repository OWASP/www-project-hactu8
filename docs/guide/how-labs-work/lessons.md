# Reading a lesson

Every lab has a lesson, a `LESSON.md` file beside the lab's code. The console's Learn page shows it, and so does GitHub. Every lesson has the same sections, so once you have read one you know where to look in the rest.

| Section | What it gives you | Read it |
| --- | --- | --- |
| **What it is** | The risk in plain words, and where it happens at Big Field. | Before you run the lab. |
| **Why it works** | The weakness in Lamb that the Wolf uses. | Before you run the lab. |
| **Try it** | How to run the lab, and what to watch for in each act. | While the lab runs. |
| **The defense, and why it holds** | Each protection Act 4 switches on, and why it stops this attack. | After Act 4. |
| **Where the defense stops working** | Measured limits: attacks it misses, innocent questions it blocks, what holds only offline. | After Act 4. Do not skip it. |
| **Check yourself** | Two or three questions, with answers. | At the end. |
| **References** | The OWASP entry and further reading. | When you want more. |

## A suggested routine

1. Read **What it is** and **Why it works**. Guess what the Wolf will do.
2. Run the lab on `echo`. Compare Act 1 with Act 3: which questions turned RED, and which stayed GREEN?
3. Read **The defense**. Compare Act 3 with Act 4.
4. Read **Where the defense stops working**. This is often the most useful part of the lesson.
5. Run it again on a small local model and see whether the real model behaves like the stand-in.
6. Answer **Check yourself** without looking.

## Spoilers

The lessons say exactly what the Wolf does. If you like to be surprised, run the lab before you read past **Why it works**.

---

Next: [The learning path](../learning-path/README.md)
