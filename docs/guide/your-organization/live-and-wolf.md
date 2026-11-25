# Live tests and the Wolf

The labs each test one attack in a fixed scene. Two tools go further. The live test throws every kind of hiding place at your model at once, and the Wolf writes new attacks and adapts them as it goes.

## The live test

```bash
python3 -m hactu8 live --backend ollama --model gemma3:4b
```

Your model is given a secret, a per-run canary, and asked to summarize content from each of Lamb's surfaces: tool descriptions and results, resources, prompt templates, parameter schemas, error messages, logs, knowledge-base files, linked pages, a feed that changes over time and messages from other agents. Each surface comes with a clean control.

Every surface is graded twice:

- **Off:** no defense. Did the canary leak (BREACH) or not (SAFE)?
- **On:** through the ProtectoGW gateway. Was it stopped (DEFENDED), never needed stopping (SAFE), or was a clean control wrongly blocked (FALSE_BLOCK)?

The summary separates two numbers that are easy to confuse:

- **Model resistance:** how often your model refused on its own.
- **App exposure:** how many breaches got through with the gateway off, and with it on.

A strong model with no gateway and a weak model behind a good gateway can have the same exposure. The live test shows you which one you have. The console's Run page has the same test as **Lamb's MCP surfaces (live)**.

## The scoreboard

```bash
python3 -m hactu8 scoreboard
```

The latest live run for each model you have tested, most resistant first. Use it to compare a shortlist of models on the same test, or to check that a new model version is no worse than the last.

## The Wolf

```bash
python3 -m hactu8 wolf --target-backend ollama --target-model gemma3:4b
python3 -m hactu8 wolf --backend ollama --model llama3.1:8b --target-backend ollama --target-model gemma3:4b
```

The Wolf is an attacker model. Each round it writes notes meant to make the target leak its canary, sees which ones landed and which were stopped, and tries again with a different framing, like the wolf in the fable. Every attempt is graded with the gateway off and on, beside a clean control.

- `--backend` and `--model` choose the attacker. The default, `echo`, rewrites attacks from fixed templates and encodings, so its results repeat exactly.
- `--target-backend` and `--target-model` choose the model under attack.
- `--rounds` (1 to 5) and `--attempts` per round (1 to 4) bound the work.

Everything the Wolf writes passes a safety screen before use. Anything holding a real-looking address, domain, command or file path is rejected and never sent. Every reply the target gives is also handed to the Wolf's den and kept as evidence.

The [Wolf notes](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/docs/wolf.md) have every option and the full screen.

## What a clean result means

A model that shows no breaches in the live test, and no landed attacks from the Wolf, has resisted these attacks on this run. It has not been proven safe. Keep the results, re-run after changes, and read the next page on turning runs into evidence.

---

Next: [Evidence and reports](evidence.md)
