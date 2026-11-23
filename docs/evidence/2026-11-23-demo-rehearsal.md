# Demo rehearsal, 2026-11-23

Walk of [`docs/demo-script.md`](../demo-script.md) on the `echo` backend, from a worktree of branch `demo-rehearsal` at `7492799`, Python 3.14 venv with `.[lamb,api]`. Ollama was reserved for other runs, so no `gemma3:4b` step was run; every step used its echo fallback. Servers ran on spare ports because 8000 and 5173 (main checkout), 5508 and 5510 (HX08 and HX10 consoles) and 15500 (an older Lamb) were taken.

## Checks

| Check | Result |
| --- | --- |
| `python scripts/vendor.py --check` | pass, 381 of 381 vendored files match |
| `python -m unittest discover -s tests` | pass, 244 tests (245 after the fix below) |
| `python -m hactu8 run all --backend echo` | pass, 49/49 |
| `python -m hactu8 list` | 49 skills |
| markdownlint-cli2 0.17.2 | 0 errors |

## Steps

| Step | What was run | Result | Drift found |
| --- | --- | --- | --- |
| Before | API `HACTU8_API_PORT=18000 python -m hactu8.api` with the built console (`HACTU8_CONSOLE_DIR`); console `npm run build` | pass | The worktree had no `node_modules`; built with the main checkout's (same lockfile) by symlink. The script did not say how to get the console up without `npm install` or on another port |
| Before | Recording `hactu8_llm01_echo_demo_fallback.gif` | present, outside the repo | The script did not say where it is |
| 1. What HACTU8 is | lab list against `hactu8 list` | pass | HX list out of order with missing commas (HX13, HX16, HX14, HX15, HX17). gemma3:4b figure cited the 2026-11-20 sweep (19 of 25); the 2026-11-21 sweep has 25 of 31 |
| 2. Learn | console Learn, LLM01 lesson | pass | none: path basics then agentic, "Try it" and "Where the defense stops working" present |
| 3. One lab | console Run, Offline tier, `echo`, LLM01; `python -m hactu8 run llm01 --backend echo` | pass, ISR 0% -> 100% -> 0% | none: "Protections added" lists spotlight and input screen with before and after. Local tier lists Ollama models; Basalt greyed out (hardware) |
| 4. MCP surfaces | console lab "Billy's MCP surfaces, live"; `python -m hactu8 live --backend echo` | pass, 5 of 13 held by the model, 8 breaches off, 0 on, 0 false blocks | The result has no Wolf's den panel; the script said to show what the den captured. Now: "What leaked with no defense"; den captures in step 7 |
| 5. Agentic lab | `python -m hactu8 run asi05 --backend echo`; ASI05 lesson | pass, UER 0% -> 100% -> 0% | none: split-string limit and allow-list sandbox are in the lesson |
| 6. Honest numbers | `python -m hactu8 bench`, `--misses`; AGX09 in `run all` | pass, 53% held-out, 0 false positives; AGX09 screen 60% | Coverage is 95% (184 of 194), not 94% (166 of 176); 94% is the recorded baseline the bench prints next to it. 10 known misses unchanged |
| 7. Reports, CI, Wolf | `/api/reports/<run>/{markdown,html,sarif}`; `python -m hactu8 wolf --backend echo --rounds 2`; `python -m hactu8 mcp` (stdio client: 8 tools, `run_skill` llm01) and `--http --port 28765` | pass; Wolf 3 of 4 landed off, 0 on, 3 den captures | No echo fallback for the Wolf was given; added |
| Lamb (README) | `HACTU8_LAMB_PORT=25500 python -m hactu8.lamb`, `/api/labs`, `/labs/hx01/`, `/api/reset`, `/mcp` initialize | pass, 49 labs | Bug: after `kill` (SIGTERM) the lab worker it had started (HX01 on 5501) kept running, orphaned |
| Other CLI | `coverage`, `defenses`, `results`, `show latest`, `router`, `run llm01 --backend basalt` | pass; basalt refused with the hardware reason | README said Strata and Basalt are in the local tier; they are commented out in `hactu8.yaml` |

Not run: `--classifier llm-judge` (its judge is Ollama) and every `gemma3:4b` step.

## Fixes

- `hactu8/lamb/app.py`: the app's lifespan now stops the lab workers on shutdown. uvicorn re-raises SIGTERM after its graceful shutdown, so the `finally` in `hactu8/lamb/__main__.py` never ran on `kill`. Test: `tests/test_lamb.py` `test_app_shutdown_stops_lab_workers` (failed before the fix). Rechecked by hand: the worker port closed after `kill`.
- `docs/demo-script.md`: the drift above; console setup without `npm install` or on another port; expected echo numbers for steps 4 and 7; what an ERROR item means if a model call fails.
- `README.md`: Wolf and MCP server instead of "Coming in Phase 1: the AI attacker skill"; Strata and Basalt commented out in `hactu8.yaml`; hardware check; ERROR verdict; scripts list.
- `CLAUDE.md`: status (W0-W9 done, 49 labs, merged into `phase1-mvp`), backends, the judge-never-lowers-RED and ERROR rules, layout.
- `demos/README.md`: HX table in id order; `anthropic` and `openai` backends; hardware check and ERROR note.
- `docs/agenticgoat-merge-plan.md`: Handoff for 2026-11-23.
