# Writing your own lab

A lab for your organization tests one scenario you care about, in four acts, with an exact check. Start small: one weakness, one attack, one defense.

## 1. Name the scenario

Write these down before any code:

- **Who the assistant is** and what job it does.
- **What it should say or do:** the ground truth your questions check.
- **What the attacker wants:** a canary to leak, a tool call to trigger, a cost to inflate.
- **Where the attack gets in:** a document, a tool, a message, a memory, another agent.
- **The defense:** what will bring the rate back to 0, and what it might miss.

If the scenario fits an existing lab, copy that lab instead of starting from nothing. The nearest lab already has most of the code you need.

## 2. Copy a lab

```bash
cp -R demos/owasp-llm01-demo demos/acme-docs-demo
```

Rename the skill folder inside it, update `SKILL_DIR` in `run_demo.py`, and give the lab its own identity in `SKILL.md`: an id in `hactu8.owasp` (your own prefix, such as `ACME01`), a metric, a free `hactu8.port` and a place on the path in `hactu8.path`. The [anatomy page](anatomy.md#identity-skillmd) lists every key.

## 3. Build the four acts

- **Questions:** a handful of targeted questions the attack should break, and at least two controls it should not.
- **Act 1:** all GREEN, or the questions are unfair.
- **Act 2:** the payload goes in `assets/` as an editable file, so others can read and vary it.
- **Act 3:** the targeted questions turn RED on the offline model. The controls stay GREEN.
- **Act 4:** the hardened mode switches on the defense, and the targeted rate returns to 0 with the controls still GREEN.

Grade every answer with the canary or an exact oracle, never with a guess. Keep the payload benign: its only possible effect should be revealing a fake canary or calling a pretend tool on your own machine. Keep the target on `127.0.0.1`.

## 4. Write the lesson

`LESSON.md` has seven sections, in order: What it is; Why it works; Try it; The defense, and why it holds; Where the defense stops working; Check yourself; References. Report measured limits in "Where the defense stops working", not hopes. [Reading a lesson](../how-labs-work/lessons.md) shows what each section is for.

## 5. Check it

```bash
python3 -m hactu8 list                  # your lab appears
python3 -m hactu8 run acme01            # PASS on echo: 0% -> above 0% -> 0%
python3 -m hactu8 run acme01 --backend ollama --model llama3.2:3b
python3 -m unittest discover -s tests -t .
```

The core tests check every lab: it passes on `echo` with four acts, its defenses are known, its lesson is valid, its port is unique and its shared files match the master copies. The tests count the lab folders under `demos/` themselves, so a new lab needs no test edits. If your lab's folder is there but HACTU8 does not find it (for example, a wrong `SKILL_DIR` in `run_demo.py`), the count no longer matches and the tests say which folder is missing.

The template's [checklist](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/_template/TEMPLATE.md#11-checklist-for-a-new-demo) is the full list.

## Add a technique or defense

If your lab covers an attack technique HACTU8 does not know yet:

1. Add it to `TECHNIQUES` in `hactu8/techniques.py`, with its family, a one-line summary, its ids in the reference lists (OWASP, MITRE ATLAS, NIST), its defenses and its labs.
2. If the defense is new, add it to `hactu8/protections.py` and give it a kind in `hactu8/defenses.py`.
3. If a text screen applies, add attack items and a clean control to the screening bench, `hactu8/bench/corpus.json`. Record what the screen really does today, even when it misses.

`python3 -m hactu8 coverage` and `python3 -m hactu8 defenses` then show your lab as evidence. Section 17 of the template has the details.

## Share it

A lab is a folder, so you can review it, share it with another team, or keep it private. To contribute it to HACTU8, set it at Big Field Jumpers Co. and open a pull request against `phase1-mvp`.

---

Next: [Automation](automation.md)
