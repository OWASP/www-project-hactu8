# Your models

Every lab, every live test and the Wolf can run on the model you choose. The lab, its questions and its grading stay the same. Only the model inside changes.

## Pick a backend

| Backend | For | Where it looks |
| --- | --- | --- |
| `echo` | The offline stand-in. The default. | Built in |
| `ollama` | Ollama | `OLLAMA_HOST`, default `http://localhost:11434` |
| `llamacpp` | llama.cpp server | `LLAMACPP_HOST`, default `http://localhost:8080` |
| `openai-compat` | Any OpenAI-compatible server: LM Studio, vLLM, LocalAI, Jan, llamafile, mlx_lm and most in-house gateways | `LOCAL_OPENAI_BASE_URL`, default `http://localhost:1234/v1`, with an optional `LOCAL_OPENAI_API_KEY` |
| `strata`, `basalt` | Mixture-of-experts engines | `STRATA_HOST`, `BASALT_HOST` |
| `openrouter`, `anthropic`, `openai` | Cloud APIs | `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` |

```bash
python3 -m hactu8 run llm01 --backend ollama --model llama3.2:3b
python3 -m hactu8 run all --backend openai-compat --model my-model
python3 -m hactu8 router          # what is configured, and what is reachable now
```

Keys are read from environment variables only. HACTU8 never reads them from a file, the console or a request, and it removes any key a server echoes back from errors, results and reports.

## A model on another machine

Local backends only talk to your own machine unless you allow otherwise. To test a model your organization hosts elsewhere, for example behind an OpenAI-compatible gateway, set the URL and allow remote access for that backend:

```bash
export LOCAL_OPENAI_BASE_URL=https://models.internal.example/v1
export LOCAL_OPENAI_API_KEY=...            # if the gateway needs one
export LOCAL_OPENAI_ALLOW_REMOTE=1
python3 -m hactu8 run all --backend openai-compat --model our-assistant-v3
```

The same switch exists for each local backend (`OLLAMA_ALLOW_REMOTE`, `LLAMACPP_ALLOW_REMOTE` and so on). Remember that lab prompts, including the attack payloads, then leave your machine. The payloads are benign and the secrets are fake canaries, but your gateway's logs and filters will see them. Tell the people who run it first.

## Cloud and spending

Cloud backends cost money and send lab text to a provider, so HACTU8 never uses them without your say-so:

- The router stops at local models by default (`router.max_tier: local` in `hactu8.yaml`).
- A run, live test or Wolf run that would use a paid backend prints a cost estimate and stops, unless you add `--confirm-spend`.
- A judge model that could reach a paid backend needs the same confirmation.
- The console asks for the same consent with a checkbox.

## Limits that protect you

| Setting | Default | What it caps |
| --- | --- | --- |
| `LAB_MAX_CALLS` | 200 | Model calls per lab process |
| `LAB_MAX_TOKENS` | 400 | Tokens per answer |
| `LAB_HTTP_TIMEOUT` (or `<BACKEND>_TIMEOUT`) | 120 s | One model call |
| `--timeout` on `run` | 300 s | One whole lab |

## Configure the router

`hactu8.yaml` decides which model each role uses when you do not name one. The two roles are `target`, the model under test, and `judge`, the model that grades answers with `--classifier llm-judge`. Tiers go from `deterministic` (echo) to `local` to `cloud`. Point `HACTU8_CONFIG` at your own copy to keep your organization's settings out of the repo. The [README](https://github.com/OWASP/www-project-hactu8/tree/phase1-mvp#models-and-scoring) and the [local engines notes](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/docs/local-engines.md) have the details.

## Reading your model's numbers

On a real model the status is `REPORTED`: HACTU8 records what happened and asserts nothing. Run each lab two or three times, because models vary between runs. A model that resists an attack on its own (`0% -> 0% -> 0%`) is good news, but it tells you nothing about the defense. [Reading a result](../how-labs-work/results.md) covers the patterns to look for.

---

Next: [Live tests and the Wolf](live-and-wolf.md)
