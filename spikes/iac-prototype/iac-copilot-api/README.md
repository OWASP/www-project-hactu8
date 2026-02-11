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
uvicorn app:app --reload --port 8000
```

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
