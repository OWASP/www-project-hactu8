# Local engines and MoE models

HACTU8 runs labs against a local model through five backends. All of them keep lab text on the host, and the OpenAI-compatible ones refuse a non-loopback URL unless you set the override on purpose.

| Backend | Engine | Host variable (default) | Override for a non-loopback host |
|---------|--------|-------------------------|----------------------------------|
| `ollama` | Ollama | `OLLAMA_HOST` (`http://localhost:11434`) | none (no guard) |
| `llamacpp` | llama.cpp `llama-server` | `LLAMACPP_HOST` (`http://localhost:8080`) | none (no guard) |
| `openai-compat` | LM Studio, vLLM, LocalAI, Jan, llamafile, `mlx_lm.server` | `LOCAL_OPENAI_BASE_URL` (`http://localhost:1234/v1`) | `LOCAL_OPENAI_ALLOW_REMOTE=1` |
| `strata` | Strata | `STRATA_HOST` (`http://localhost:8080`) | `STRATA_ALLOW_REMOTE=1` |
| `basalt` | Basalt | `BASALT_HOST` (`http://localhost:8080`) | `BASALT_ALLOW_REMOTE=1` |

`strata` and `basalt` are named presets of the `openai-compat` client: the backend calls `<HOST>/v1/chat/completions` and lists models from `<HOST>/v1/models`. `STRATA_API_KEY` and `BASALT_API_KEY` are optional and, when set, ride only in the `Authorization` header. The model defaults to `local`; pick the served model with `--model` or the console's model list. Per-call timeouts are `STRATA_TIMEOUT` and `BASALT_TIMEOUT`.

```bash
STRATA_HOST=http://127.0.0.1:8081 python -m hactu8 run llm01 --backend strata
BASALT_HOST=http://127.0.0.1:8082 python -m hactu8 run llm01 --backend basalt --model <served-model>
```

The router's local tier lists `strata` and `basalt` as commented lines in [`hactu8.yaml`](../hactu8.yaml). Uncomment them to let the router fall back to them.

## Ports: llama.cpp, Strata and Basalt all default to 8080

llama.cpp's `llama-server`, Strata and Basalt's example config all listen on `127.0.0.1:8080`. If two of them run at once, the second fails to bind, or a backend talks to the wrong engine without noticing: the router's probe only checks that `/v1/models` answers. Give each engine its own port and point its variable at it, for example llama.cpp on 8080, Strata on 8081 (`--port 8081`), and Basalt on 8082 (`"server": {"port": 8082}` in its config).

What was confirmed, and from where (checked 2026-11-23):

- Strata: `127.0.0.1:8080` by default, `--port` to change it, endpoints `/v1/chat/completions`, `/v1/models`, `/v1/messages` and `/v1/responses`. An API key is recommended but optional; without one the server only answers requests whose Host header it allows. Sources: the project's [README](https://github.com/Niko1221/Strata), [AGENTS.md](https://github.com/Niko1221/Strata/blob/main/AGENTS.md) and [docs/DETAILS.md](https://github.com/Niko1221/Strata/blob/main/docs/DETAILS.md).
- Basalt: binds `127.0.0.1` and speaks the OpenAI and Anthropic APIs; the README's quick-start config sets port 8080, and its site's curl example uses `127.0.0.1:8080/v1/chat/completions`. The README does not say 8080 is the built-in default, and it does not list `/v1/models` or the key rules; the `basalt` backend assumes both work as in Strata, which Basalt was forked from. Sources: [github.com/azjhf-dev/basalt](https://github.com/azjhf-dev/basalt), [basalt.jgulfo.com](https://basalt.jgulfo.com/).
- Third-party summaries, not checked against the projects: Strata's experimental Apple Silicon (Metal) support from v0.1.44 ([everydev.ai](https://www.everydev.ai/tools/strata), [note.com](https://note.com/natty_toucan386/n/nd44021d2d274), [smartscope.blog](https://smartscope.blog/en/blog/strata-local-llm-engine-qwen3-8-flash-next-2026/)). Strata's README lists Apple Silicon M1 or newer and ships a macOS arm64 build.

No Strata or Basalt server has been run against HACTU8 yet. The backends are tested offline with a mocked server.

## Which engine fits which hardware

| Hardware | Engines that fit |
|----------|------------------|
| Apple Silicon, e.g. an M4 Mac mini with 16 GB | Ollama, llama.cpp (Metal), Strata (Apple Silicon support is new; treat it as experimental), `openai-compat` servers such as LM Studio or `mlx_lm.server` |
| NVIDIA Blackwell (compute capability 12.0) with CUDA 13, Linux x86-64 or Windows 10 1903+ | Basalt, plus all of the above that support CUDA |
| Older NVIDIA (Ada and earlier) | Ollama, llama.cpp, Strata; Basalt only through community forks |

Basalt cannot run on a Mac. To use it from a Mac, run it on the GPU machine and reach it through an SSH tunnel (`ssh -L 8082:127.0.0.1:8082 gpu-box`), so `BASALT_HOST` stays loopback, and set `HACTU8_FORCE_BACKENDS=basalt` so the hardware check below lets it through. `BASALT_ALLOW_REMOTE=1` works too, but lab prompts and payloads then cross the network.

## Backends this host's hardware cannot run

HACTU8 checks the host once per process and offers `strata` and `basalt` only where their engine can run:

| Backend | Offered when |
|---------|--------------|
| `strata` | macOS on Apple Silicon (arm64), or `nvidia-smi` lists an NVIDIA GPU (any compute capability) |
| `basalt` | Linux or Windows, and `nvidia-smi` lists a GPU with compute capability 12.x (Blackwell, `sm_120`); never on macOS |
| all others | always (they need a key or a running server, which are checked separately) |

The check runs `nvidia-smi --query-gpu=name,compute_cap --format=csv,noheader` with a 2-second timeout and never runs it on macOS. A missing `nvidia-smi`, a timeout or an error counts as no NVIDIA GPU. It does not check the CUDA version, so a Blackwell GPU with an older CUDA still passes.

Where a backend fails the check:

- Every lab console and the iac-host console list it greyed out, with a "(needs …)" suffix and the reason as the tooltip, for example "Basalt needs an NVIDIA Blackwell GPU (sm_120) with CUDA 13 on Linux or Windows; it cannot run on macOS". The console never selects it by default.
- `hactu8 --help` for `run`, `live`, `wolf` and `bench` marks it "(unavailable: needs …)".
- Choosing it anyway (`--backend`, `--target-backend`, `--classifier-backend`, a lab's `POST /api/backend`, `<PREFIX>_BACKEND`, or the router) fails with the same reason instead of a connection error.

The result is in `providers.backend_support()` and in the `hardware` field of each lab's `GET /api/meta` and the runner API's `GET /api/models`: `{"basalt": {"ok": false, "reason": "...", "needs": "an NVIDIA Blackwell GPU"}, ...}`.

To skip the check, for example when the engine runs on another machine behind an SSH tunnel, or to test on other hardware, set `HACTU8_FORCE_BACKENDS` to a comma-separated list of backends, or `all`:

```bash
HACTU8_FORCE_BACKENDS=basalt BASALT_HOST=http://127.0.0.1:8082 python -m hactu8 run llm01 --backend basalt
```

## Why MoE models can run faster

A mixture-of-experts (MoE) model has many expert sub-networks per layer, and a router picks a few of them for each token. Only those experts' weights are read for that token. Generating text locally is mostly limited by memory bandwidth (the weights read per token), not by compute, so a model with 30B total parameters and about 3B active runs closer to the speed of a 3B dense model than a 30B one.

The catch is that all experts must still be stored somewhere. That is what MoE-focused engines optimise: they keep attention and shared layers in fast GPU memory and put experts that do not fit in VRAM in system RAM, so a model larger than the GPU still runs at a usable speed. Strata and Basalt are built around this, and recent llama.cpp builds can do it too (`--n-cpu-moe`, `--override-tensor`). The benefit applies to MoE models only: a dense model reads every weight for every token, so offloading part of it to RAM slows every token down.

On Apple Silicon the CPU and GPU share the same unified memory, so GPU/CPU expert offload gains little. The speed-up there comes from the small active parameter count alone, and the whole model, plus its context, must fit in unified memory. macOS lets the GPU use only part of it by default (roughly two thirds to three quarters), so on a 16 GB machine about 10 to 12 GB is available for model weights.

## MoE candidates for a 16 GB Mac

Sizes are approximate 4-bit download sizes; real memory use is higher once the context is allocated. Only `granite3.1-moe:3b` is pulled on this host (2026-11-23, 2.0 GB, user approved). Pulling another downloads gigabytes and needs the user's go-ahead first.

| Model | Total / active parameters | Approx. size | Fit on 16 GB |
|-------|---------------------------|--------------|--------------|
| `granite3.1-moe:1b` | about 1.3B / 0.4B | about 1.4 GB | fits easily |
| `granite3.1-moe:3b` | about 3.3B / 0.8B | about 2 GB | fits easily |
| OLMoE-1B-7B (GGUF, `olmoe` where a registry offers it) | about 7B / 1.3B | about 4 GB | fits |
| DeepSeek-V2-Lite | about 16B / 2.4B | about 10 GB | tight |
| `gpt-oss:20b` | about 21B / 3.6B | about 13 to 14 GB | likely too tight for the GPU share; may run partly on CPU |
| `qwen3:30b-a3b` | about 30B / 3.3B | about 18 to 19 GB | too big at 4-bit |

Small MoE models are fast but weak, so expect them to follow lab payloads less reliably than a dense 7B to 8B model. Report what they do; do not tune the labs to them.

## Where model files go

On this host the main disk is small, so model files live on the secondary drive, `/Volumes/DockerDisk`:

- **Ollama**: `~/.ollama/models` is a symlink to `/Volumes/DockerDisk/ollama/models`, so `ollama pull` lands there. Check with `readlink ~/.ollama/models`. If the drive is not mounted, Ollama cannot find its models; mount the drive rather than pulling again onto the main disk.
- **Hugging Face downloads** (GGUF files for llama.cpp or Strata, MLX weights): set `HF_HOME=/Volumes/DockerDisk/hf` in the shell profile.
- **llama.cpp's own downloads** (`llama-server -hf ...`): set `LLAMA_CACHE=/Volumes/DockerDisk/llama.cpp-cache`.
- **Strata and Basalt model packs**: pass a path on the secondary drive when the engine asks for a model directory.

```sh
# ~/.zshrc
export HF_HOME=/Volumes/DockerDisk/hf
export LLAMA_CACHE=/Volumes/DockerDisk/llama.cpp-cache
```

## Reasoning models: `HACTU8_THINK`

Reasoning models such as `qwen3:8b` write a chain of thought before the answer. On Ollama 0.40 it comes back apart from the answer (`message.thinking`), so the replies in the results never show it, but it costs the time: a direct probe with one customer-support turn (outside the labs, 2 samples each) took 241 tokens and 12 to 17 s with reasoning (about 800 characters of it, 280 of answer) and 55 tokens and 3 s without. Reasoning also shares the `LAB_MAX_TOKENS` budget (Ollama's `num_predict`) with the answer.

- `HACTU8_THINK=off|on|default` sets the control for every backend; `OLLAMA_THINK` overrides it for Ollama. `off` and `on` send `think: false` or `think: true` in `/api/chat`. `default`, or unset, sends no `think` field, so the model's own default applies (for `qwen3:8b`, thinking on). Any other value stops the run with an error.
- Only Ollama has the control here. On other real backends the setting is recorded with `sent: false`: it was not applied.
- Every real-backend result records it under `model.think` (`mode`, `sent`), so runs with different settings are not mixed up. Compare like with like.
- Grading is unchanged. What a lab grades is the reply its app shows. Reasoning the API returns apart from the answer is never shown or logged by the lab apps, so it is not graded; it is also not dropped silently: each lab process tallies it and the result records `model.think.reasoning` (`replies`, `chars`, `answer_cut_off` for replies whose answer was empty because reasoning used the whole budget, and `canary_hits` for replies whose reasoning held the run canary). A canary only in reasoning is a near miss, not a leak, and reported as such. A `<think>` block inside the answer itself is shown by the app, so it is never stripped and is graded with the rest of the reply.
- Limits: `canary_hits` checks the provider's per-run canary (`canary()` or `LAB_CANARY`), not a lab's own fixed tag. A process killed by the run timeout prints no tally, so a timed-out run has no `reasoning` block.

Measured on HX04, `qwen3:8b`, `--timeout 900`, one sample each, alone on the host, commit `ad6285b` (raw: `hactu8-sweeps/hx/qwen3-8b-think/`):

| `HACTU8_THINK` | Time | ELR baseline -> impact -> remediated |
| --- | --- | --- |
| `off` | 122 s | 0% -> 100% -> 0% (story holds) |
| `default` | 900 s (timeout) | none |

The earlier `qwen3:8b` timeouts (HX02, HX04, HX11, HX15) are the reasoning, not the labs. A `think=off` run measures the model without its reasoning, which is a different configuration from the default: label it as such.
