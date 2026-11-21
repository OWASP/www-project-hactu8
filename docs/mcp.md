# HACTU8 MCP server

`python -m hactu8 mcp` (or `hactu8-mcp`) serves the runner as MCP tools over stdio, built on the official `mcp` v2 SDK (`pip install 'hactu8[lamb]'`). `--http` serves streamable HTTP on `http://127.0.0.1:8765/mcp` instead (`--port` to change it); it never binds another address.

| Tool | Kind | What it does |
| --- | --- | --- |
| `list_skills` | read-only | The 41 labs: id, OWASP id, risk, metric |
| `learning_path` | read-only | Stages and labs in the order to take them |
| `get_lesson` | read-only | A lab's `LESSON.md`: title, sections, questions |
| `list_results`, `show_result` | read-only | Stored runs, newest first; one full `hactu8.result/v1` document (`latest` works) |
| `run_skill` | run | One lab, baseline to remediation; `backend` (default `echo`), `model`, `classifier` |
| `run_live` | run | Billy's MCP surfaces against a model, gateway off vs on |
| `run_wolf` | run | The Wolf ([wolf.md](wolf.md)); `rounds` 1 to 5, `attempts` 1 to 4 |

Every run stores its result under `$HACTU8_HOME/results` (default `./.hactu8`). A paid cloud backend (`openrouter`, `anthropic`, `openai`) is refused with the spend estimate unless the call passes `confirm_spend: true`, the same guard as the CLI's `--confirm-spend`. The server's instructions tell the client to ask the user first.

## Client configuration

Claude Code, from the repo root:

```bash
claude mcp add hactu8 -- /path/to/hactu8-phase1/.venv/bin/python -m hactu8 mcp
```

Claude Desktop (`claude_desktop_config.json`) or any client that takes the same shape. `HACTU8_ROOT` points at the repo, since the client starts the server from its own working directory:

```json
{
  "mcpServers": {
    "hactu8": {
      "command": "/path/to/hactu8-phase1/.venv/bin/python",
      "args": ["-m", "hactu8", "mcp"],
      "env": {
        "HACTU8_ROOT": "/path/to/hactu8-phase1",
        "HACTU8_HOME": "/path/to/hactu8-phase1/.hactu8"
      }
    }
  }
}
```
