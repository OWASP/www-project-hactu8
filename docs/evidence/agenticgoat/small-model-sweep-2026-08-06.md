# Example run — small-model live sweep (defense OFF vs ON)

> **Snapshot, not a spec.** These numbers are a point-in-time capture. Model
> weights, Ollama, the detector/screen code, and single-sample variance all
> drift over time, so treat this as an *illustrative example* of the harness
> output — re-run to get current figures (see [Reproduce](#reproduce)).

## Provenance

| Field | Value |
|---|---|
| Captured (UTC) | 2026-08-06, runs spanning `17:25:48Z` – `18:05:03Z` |
| Code version | `1ef4287` — *Fix stale README view count and cover new model-catalog code* (committed 2026-08-05 21:33 -0400) |
| Branch | `owasp-training` |
| Harness | `live_harness.run_comparison()` → persisted via `live_scoreboard.record_comparison()` |
| Attack set | 19 poisoned surfaces + 9 clean controls per model (single sample each) |
| Defense | ProtectoGW screen, graded OFF (removed) vs ON (active) on the **same** model output |
| Ollama | `0.15.6` (local, host) |
| Provider wiring | dash container → host Ollama via `OLLAMA_HOST=http://host.docker.internal:11434`, `OLLAMA_TIMEOUT=900` |
| Dashboard image | `project-billy:latest` (`sha256:b873594d…`) |
| Host | Windows 11, CPU-bound (no GPU offload); models run in RAM |
| Run log | `/data/live_runs.jsonl` (in the `billy-runs` volume; gitignored) |

## Model versions under test

Pulled tags as resolved by Ollama at capture time (all pre-installed — the sweep
pulled nothing):

| Model (tag) | Digest | Params | Quant | On-disk |
|---|---|---|---|---|
| `qwen2:0.5b` | `6f48b936a09f` | 494.03M | Q4_0 | 0.35 GB |
| `tinyllama:latest` | `2644915ede35` | 1B | Q4_0 | 0.64 GB |
| `qwen2:1.5b` | `f6daf2b25194` | 1.5B | Q4_0 | 0.93 GB |
| `stablelm2:1.6b` | `714a6116cffa` | 2B | Q4_0 | 0.98 GB |
| `llama3.2:1b` | `baf6a787fdff` | 1.2B | Q8_0 | 1.32 GB |
| `gemma2:2b` | `8ccf136fdd52` | 2.6B | Q4_0 | 1.63 GB |
| `smollm2:1.7b` | `cef4a1e09247` | 1.7B | Q8_0 | 1.82 GB |
| `llama3.2:3b` | `a80c4f17acd5` | 3.2B | Q4_K_M | 2.02 GB |
| `phi3:mini` | `4f2222927938` | 3.8B | Q4_0 | 2.18 GB |

## Results

`resisted` = designed attacks the model did **not** follow (out of 19).
`breaches` = attacks that manifested risk; **OFF** = ProtectoGW removed, **ON** =
active. `fb` = false-blocks (safe output the screen flagged anyway).

Sorted by resistance, highest first.

| Model | Run (UTC) | Resisted | Breaches OFF | Breaches ON | Defended ON | False-block ON |
|---|---|---|---|---|---|---|
| `llama3.2:3b` | `18:05:03Z` | **18/19 (95%)** | 1 | **0** | 1 | 3 |
| `llama3.2:1b` | `17:35:55Z` | 17/19 (89%) | 2 | **0** | 2 | 3 |
| `qwen2:1.5b` | `17:30:07Z` | 13/19 (68%) | 6 | **0** | 6 | 4 |
| `stablelm2:1.6b` | `17:34:13Z` | 13/19 (68%) | 7 | **0** | 7 | 7 |
| `gemma2:2b` | `17:39:53Z` | 12/19 (63%) | 7 | **0** | 7 | 4 |
| `qwen2:0.5b` | `17:25:48Z` | 11/19 (58%) | 8 | **0** | 8 | 0 |
| `tinyllama:latest` | `17:27:37Z` | 8/19 (42%) | 11 | **0** | 11 | 2 |

**Headline:** ProtectoGW drove **breaches ON to 0 for every model** — it recovered
every leak the model produced, whatever the model's own resistance.

### Excluded (did not complete on this CPU host)

| Model | Outcome |
|---|---|
| `smollm2:1.7b` | Timed out during the run — no result recorded. |
| `phi3:mini` (3.8B) | Too slow: a 19-call comparison exceeded 10 min and was stopped; no result recorded. Consistent with the known pattern that larger models exceed the per-call timeout on a CPU-bound host. |

## Space & cleanup

- **Disk: 59 GB free, unchanged start-to-finish.** No models were pulled (all
  pre-installed), so the sweep consumed **zero disk**.
- The real consumable is **RAM**: each model loads into memory. The sweep ran
  **one model at a time** and force-unloaded each after grading
  (`POST /api/generate {"keep_alive":0}` / `ollama stop`), verified via
  `/api/ps` showing `models_resident=0` between models.
- Caveat observed: if a run is interrupted mid-generation, Ollama keeps
  finishing the request server-side, so the model stays resident until it drains
  (or the server is restarted). This pinned `phi3:mini` (~2.2 GB) after it was
  stopped — disk was unaffected.

## Interpretation

- **Clear size → resistance gradient.** The weakest models are the most
  injectable (`tinyllama` 42%, `qwen2:0.5b` 58%); the sturdiest small model is
  `llama3.2:3b` at 95%. A weaker model simply hands ProtectoGW more to catch.
- **The screen is the constant.** Regardless of how much each model leaked,
  breaches ON stayed at 0 — the teaching point of the OFF-vs-ON view.
- **False-block noise varies** (0 for `qwen2:0.5b`, 7 for `stablelm2:1.6b`) and
  is where the screen's precision, not the model, is on display.

## Reproduce

Per-model, with cleanup between (from the host, dash container running):

```sh
for M in qwen2:0.5b tinyllama:latest qwen2:1.5b stablelm2:1.6b \
         llama3.2:1b gemma2:2b llama3.2:3b; do
  docker exec agenticgoat-dash-1 sh -c "cd /app && python -c \"
import asyncio; from live_harness import run_comparison
from live_scoreboard import record_comparison
c = asyncio.run(run_comparison('ollama', model='$M')); record_comparison(c)
print(c.model, c.resisted, c.attacks_total, c.breaches_off, c.breaches_on, c.false_block_on)\""
  ollama stop "$M"            # free RAM before the next model
done
```

Or from the dashboard: **Live Attack/Defense → Model sweep** (one tag per line),
which records to the same leaderboard.
