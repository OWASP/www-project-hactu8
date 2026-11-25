# Automation

Everything the console does, you can do from a script, a pipeline or an AI assistant.

## The API

```bash
.venv/bin/python -m hactu8.api            # https://127.0.0.1:8000
```

| Method | Path | Returns |
| --- | --- | --- |
| GET | `/api/skills`, `/api/path`, `/api/skills/{id}/lesson` | The labs, the learning path, one lesson |
| GET | `/api/results`, `/api/results/{run_id}` | Stored runs |
| GET | `/api/reports/{run_id}/{markdown,html,sarif}` | A report to download |
| GET | `/api/coverage`, `/api/defenses`, `/api/protections` | Techniques, defenses and their evidence |
| GET | `/api/models`, `/api/scoreboard` | Available models, the live scoreboard |
| POST | `/api/runs` | Run labs |
| POST | `/api/live`, `/api/wolf` | Run the live test, run the Wolf |

The API answers only on your own machine. Every run request goes to the [audit log](../your-organization/evidence.md#the-audit-log), and paid backends need spend consent in the request. The interactive API docs are off by default (`HACTU8_API_DOCS=on` turns them on).

## The MCP server

HACTU8 is also an MCP server, so an AI assistant that speaks MCP can list labs, read lessons, run tests and read the results.

```bash
python3 -m hactu8 mcp                     # stdio
python3 -m hactu8 mcp --http              # http://127.0.0.1:8765
```

| Tools | What they do |
| --- | --- |
| `list_skills`, `learning_path`, `get_lesson` | Read the labs and lessons |
| `list_results`, `show_result` | Read stored runs |
| `run_skill`, `run_live`, `run_wolf` | Run tests. They use `echo` unless told otherwise, and a cloud backend needs `confirm_spend: true`. |

The [MCP notes](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/docs/mcp.md) show how to add it to an MCP client.

## The CLI in scripts

Every command takes `--json` for machine-readable output, and `run` exits non-zero when a lab fails on the offline model.

```bash
python3 -m hactu8 run all --backend echo --json > run.json
python3 -m hactu8 results --json
```

## A new classifier

HACTU8 grades with the lab's own exact check (`keyword`, the default), with a judge model (`llm-judge`), or with the optional `jev` classifier. A new grader is a subclass of `Classifier` in `hactu8/classify.py`, added to its registry there. There is no plugin hook for classifiers yet, so this is a change to the core. Whatever you add must follow the same rule as the others: it may confirm or raise a lab's verdict, but never lower a canary RED.

---

Back to: [Extending HACTU8](README.md)
