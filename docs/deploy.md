# Run HACTU8 with Docker, a devcontainer, or CI

One image holds the API, the 40 labs and the built console (H-50). The devcontainer builds the same Dockerfile's `dev` target (H-51). CI runs the deterministic suite and uploads SARIF (H-52).

## Docker

```bash
docker compose up --build -d                     # API and console on http://127.0.0.1:8000
docker compose exec hactu8 python -m hactu8 run all --backend echo
docker compose exec hactu8 python -m unittest discover -s tests -t .
docker compose down                              # add -v to delete the results volume
```

- `HACTU8_PORT=18000 docker compose up -d` picks another host port.
- Results are stored in the named volume `hactu8-results` (`/data` in the container) and survive restarts.
- The console is served by the API from the same origin; `/api/*` stays the API.
- The container's healthcheck polls `/api/health`.
- The image runs as an unprivileged user with all capabilities dropped. Python dependencies are pinned in `docker/requirements.txt`, and the base images are pinned in the Dockerfile.

## Loopback only

Compose publishes the port on the host's `127.0.0.1` only (`"127.0.0.1:8000:8000"`), never `0.0.0.0`. Inside the container the API listens on `0.0.0.0` so Docker can forward to it; that address is the container's private network, not the host's. The labs, and Lamb if started, bind the container's own `127.0.0.1` and are not published. Do not add a port without the `127.0.0.1:` prefix.

## Ollama on the host

Ollama (and llama.cpp) run on the host, not in a container. The container reaches them at `host.docker.internal`: `OLLAMA_HOST` defaults to `http://host.docker.internal:11434` and `LLAMACPP_HOST` to `http://host.docker.internal:8080`. Override either in the shell before `docker compose up`. Docker Desktop forwards to the host's loopback. On Linux, Ollama must listen on an address the Docker bridge can reach, such as `OLLAMA_HOST=0.0.0.0` on the host, behind a firewall. For an OpenAI-compatible server on the host, set `LOCAL_OPENAI_BASE_URL=http://host.docker.internal:1234/v1` and `LOCAL_OPENAI_ALLOW_REMOTE=1`, since that host name is not loopback.

## Keys

Keys are never baked into the image. Compose reads an optional env file outside the repo, `../.hactu8.env` by default (for a clone in `~/dev`, that is `~/dev/.hactu8.env`), or the file named by `HACTU8_ENV_FILE`:

```bash
# ~/dev/.hactu8.env, chmod 600, never committed
OPENROUTER_API_KEY=sk-or-...
```

Without the file, everything runs on the echo backend. Every variable in the file reaches the container, so use a separate file through `HACTU8_ENV_FILE` if it also holds unrelated secrets. Use an expendable, spend-capped key: cloud runs send lab payloads off the machine and still need `--confirm-spend`.

## Devcontainer

Open the repo in VS Code and choose "Reopen in Container". It builds the `dev` target and mounts the workspace at `/app`. Python comes from `/opt/venv` (the pinned dependencies, not the host's `.venv`), and the console's Linux `node_modules` live in a volume, so the host's are untouched.

```bash
python -m hactu8.api                                       # API on 127.0.0.1:8000
npm --prefix spikes/iac-prototype/iac-host run dev         # console on 127.0.0.1:5173
```

VS Code forwards ports 8000 and 5173 to the host's loopback; if they are taken, it picks free ones. In a `git worktree`, git inside the container cannot reach the main repository's `.git`; use a plain clone for container git work.

## CI

`.github/workflows/hactu8-deterministic.yml` runs on pushes and pull requests to the `phase1-*` branches. It runs the unit tests and `python -m hactu8 run all --backend echo` on Python 3.10 (standard library only) and 3.14 (pinned dependencies), markdownlint, and the console build. `scripts/sarif_all.py` merges the 3.14 runs into one SARIF file, which is kept as a build artifact and uploaded to code scanning. The findings are the attacks each lab demonstrates on purpose; the suite passes or fails on the exit code of `run all`. Only the upload job has `security-events: write`.

## Without Docker on macOS

Python from the python.org macOS installer does not use the system keychain and ships no CA bundle of its own, so HTTPS calls (OpenRouter, Anthropic, OpenAI) fail with `CERTIFICATE_VERIFY_FAILED`. Run "Install Certificates.command" from the Python folder in Applications, or set `SSL_CERT_FILE=/etc/ssl/cert.pem`. This does not apply inside the container, which uses Debian's CA bundle.
