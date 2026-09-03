# IAC Copilot API

Dedicated FastAPI service for the IAC Copilot.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
uvicorn app:app --reload --reload-exclude 'data/*' --port 8000
```

Note: `--reload-exclude 'data/*'` keeps the auto-reloader from watching the
ChromaDB persistence directory. Without it, every document upload/chat write
touches `data/chroma/chroma.sqlite3`, which the file watcher treats as a code
change and restarts the server mid-write — interrupting ChromaDB before it
flushes the updated HNSW vector index to disk. The SQLite metadata table
still shows the new document (so `/documents` and `/stats` look correct),
but semantic search (`/chat`) never finds it because the on-disk vector index
was never updated, resulting in the same "not enough information" response.

## Environment

- `OPENAI_API_KEY`: API key for OpenAI-compatible providers.
- `OPENAI_MODEL`: Default model for OpenAI-compatible providers.
- `ANTHROPIC_API_KEY`: API key for Anthropic.
- `ANTHROPIC_MODEL`: Default model for Anthropic.
- `CHROMA_PERSIST_DIR`: Optional path for ChromaDB persistence.
- `OWASP_GITHUB_TOKEN`: Optional GitHub token for higher rate limits.

## Notes

The API exposes:
- `/api/copilot/chat`
- `/api/copilot/documents`
- `/api/copilot/sync/owasp`
- `/api/copilot/sources`
- `/api/copilot/models`
