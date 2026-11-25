# Your first run

The first lab on the path is LLM01, Prompt Injection. Run it:

```bash
python3 -m hactu8 run llm01
```

```text
running llm01 (LLM01:2026 Prompt Injection) on echo ...
  PASS     ISR 0% -> 100% -> 0%  (72 ms)
  saved .hactu8/results/20261125T152649Z-llm01-cb55.json
```

That one line is the whole story of the lab:

- **`ISR`** is the lab's metric, here the injection success rate. Every lab has its own, named in its lesson.
- **`0% -> 100% -> 0%`** is the rate before the attack, after it, and after the defense is switched on.
- **`PASS`** means the story held: nothing went wrong before the attack, something did after it, and the defense put it right. [Reading a result](../how-labs-work/results.md) explains every status.
- **`saved`** is the full result, every question and every answer, as JSON.

Now read what happened. Open the [LLM01 lesson](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/owasp-llm01-demo/owasp-llm01-injection-skill/LESSON.md), or open the console's **Learn** page, which shows the same lesson next to a **Run this lab** button.

## Useful next commands

```bash
python3 -m hactu8 path            # all 49 labs in the order to take them
python3 -m hactu8 show latest     # the full result you just made
python3 -m hactu8 results         # every stored run
python3 -m hactu8 defenses        # each defense, what it covers and the evidence it works
python3 -m hactu8 coverage        # known attack techniques, and which have a lab
```

## A real model

The `echo` model is a stand-in that always falls for the attack in the same way, so you can learn the lab without any noise. A real model is more interesting: it might resist, or fall for only part of the attack, or behave differently on a second run.

With [Ollama](https://ollama.com) installed and a small model pulled:

```bash
ollama pull gemma3:4b
python3 -m hactu8 run llm01 --backend ollama --model gemma3:4b
```

Small local models are the best teachers. A model that resists every attack shows you nothing about the defense. With a real model the status reads `REPORTED` instead of `PASS`, because HACTU8 reports what a real model did rather than asserting what it should do.

Cloud models (Anthropic, OpenAI, OpenRouter) work too, but they send lab text off your machine and cost money, so HACTU8 never escalates to them on its own and asks you to confirm spend with `--confirm-spend`. The [README](https://github.com/OWASP/www-project-hactu8/tree/phase1-mvp#models-and-scoring) and the [local engines notes](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/docs/local-engines.md) cover the options.

---

Next: [The console](console.md)
