# Run HACTU8 with Docker, a devcontainer, or CI

One image holds the API, the 49 labs and the built console (H-50). The devcontainer builds the same Dockerfile's `dev` target (H-51). CI runs the deterministic suite and uploads SARIF (H-52).

## Docker

```bash
docker compose up --build -d                     # API and console on https://127.0.0.1:8000
docker compose exec hactu8 python -m hactu8 run all --backend echo
docker compose exec hactu8 python -m unittest discover -s tests -t .
docker compose down                              # add -v to delete the results volume
```

- `HACTU8_PORT=18000 docker compose up -d` picks another host port.
- Results are stored in the named volume `hactu8-results` (`/data` in the container) and survive restarts.
- The console is served by the API from the same origin; `/api/*` stays the API.
- The container's healthcheck polls `/api/health` over HTTPS, trusting the container's certificate (`python -m hactu8.tls health`).
- The self-signed certificate is made on first start in the results volume (`/data/tls`) and kept with it. Copy it out to trust it: `docker compose exec hactu8 cat /data/tls/cert.pem > ~/.hactu8/docker-cert.pem`. `HACTU8_TLS=off docker compose up -d` serves plain HTTP.
- The image runs as an unprivileged user with all capabilities dropped. Python dependencies are pinned in `docker/requirements.txt`, and the base images are pinned in the Dockerfile.

## Loopback only

Compose publishes the port on the host's `127.0.0.1` only (`"127.0.0.1:8000:8000"`), never `0.0.0.0`. The API also answers only requests whose `Host` header is `127.0.0.1`, `localhost` or `[::1]` with its port (`HACTU8_API_PORT`, default 8000, or `HACTU8_PORT`, the host port compose publishes and passes in); anything else gets 421, which blocks DNS rebinding. If you reach the API on another port (a forwarded devcontainer port, say), set `HACTU8_PORT` to it. Inside the container the API listens on `0.0.0.0` so Docker can forward to it; that address is the container's private network, not the host's. The labs, and Lamb if started, bind the container's own `127.0.0.1` and are not published. Do not add a port without the `127.0.0.1:` prefix.

## HTTPS

The API and the console it serves use HTTPS by default, and so does the Vite dev server.

- Certificate: on first start `python -m hactu8.api` makes a self-signed ECDSA P-256 certificate for `localhost`, `127.0.0.1` and `::1`, valid for one year, in `~/.hactu8/tls` (or `HACTU8_TLS_DIR`; use an absolute path, since the API and Vite run in different folders). The key is `key.pem`, mode 0600, and is never printed or logged. Later starts reuse the pair; a new one is made when it is missing, broken, or within 7 days of expiry. `python -m hactu8.tls` makes it without starting the API and prints the certificate's path. It never goes in the repo.
- Your own certificate: set both `HACTU8_TLS_CERT` and `HACTU8_TLS_KEY` to PEM files (for example from `mkcert`). The API and Vite both use them. The Host check still allows only loopback names, so the certificate must cover `127.0.0.1` or `localhost`.
- Plain HTTP: `HACTU8_TLS=off` for the API, and the same variable for Vite, which then also defaults the console to `http://127.0.0.1:8000`. CORS allows the dev server at `https://127.0.0.1:5173` and `https://localhost:5173`, or their `http://` forms when TLS is off.
- Clients: the tests and `python -m hactu8.tls health` trust the generated certificate explicitly (`hactu8.tls.client_context()`); nothing turns off verification. With curl: `curl --cacert ~/.hactu8/tls/cert.pem https://127.0.0.1:8000/api/health`.

The browser warns about a self-signed certificate until you trust it. For a quick look, open `https://127.0.0.1:8000/api/health` and choose to proceed; with the Vite dev server, do that for both `https://127.0.0.1:5173` and the API URL, since the console calls the API from the page. To trust it instead (no warning):

- macOS: `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db ~/.hactu8/tls/cert.pem` (or open it in Keychain Access, then Trust, "Always Trust"). Chrome and Safari use the keychain; restart the browser.
- Linux (Chrome): Settings, Privacy and security, Security, Manage certificates, Authorities, Import `cert.pem`. Firefox: Settings, Certificates, View Certificates, Authorities, Import.
- Windows: `certutil -user -addstore Root %USERPROFILE%\.hactu8\tls\cert.pem`.

Remove that trust when you delete or regenerate the certificate. Trusting it trusts only this one certificate (it is not a CA and cannot sign others), and only you hold its key.

Response headers: every response carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` and `Cross-Origin-Opener-Policy: same-origin`. The console gets a Content-Security-Policy that allows only its own scripts, styles and images, calls to its own origin, and no framing (`frame-ancestors 'none'`); `/api` responses get `default-src 'none'`. FastAPI's `/docs` and `/redoc` get no CSP, since they load Swagger UI and ReDoc from a CDN. There is no HSTS: the API only answers `localhost` and loopback addresses, and HSTS on `localhost` would apply to every port, forcing HTTPS on unrelated local servers and on the labs' plain-HTTP consoles; browsers also ignore it for IP addresses and for untrusted certificates.

The labs, Lamb (`127.0.0.1:5500`) and the MCP server's `--http` mode stay plain HTTP on loopback: the console's browser code never calls them, only the API does, from the same machine. The console shows Lamb's URLs as text.

## Ollama on the host

Ollama (and llama.cpp) run on the host, not in a container. The container reaches them at `host.docker.internal`: `OLLAMA_HOST` defaults to `http://host.docker.internal:11434` and `LLAMACPP_HOST` to `http://host.docker.internal:8080`. That host name is not loopback, so the image and compose also set `OLLAMA_ALLOW_REMOTE=1` and `LLAMACPP_ALLOW_REMOTE=1`; outside Docker both backends refuse a non-loopback host unless you set the same variable. Override any of them in the shell before `docker compose up`. Docker Desktop forwards to the host's loopback. On Linux, Ollama must listen on an address the Docker bridge can reach, such as `OLLAMA_HOST=0.0.0.0` on the host, behind a firewall. For an OpenAI-compatible server on the host, set `LOCAL_OPENAI_BASE_URL=http://host.docker.internal:1234/v1` and `LOCAL_OPENAI_ALLOW_REMOTE=1`, since that host name is not loopback. Strata and Basalt work the same way: `STRATA_HOST=http://host.docker.internal:8081` with `STRATA_ALLOW_REMOTE=1`, or `BASALT_HOST` with `BASALT_ALLOW_REMOTE=1` (see [local-engines.md](local-engines.md) for ports).

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
python -m hactu8.api                                       # API on https://127.0.0.1:8000
npm --prefix spikes/iac-prototype/iac-host run dev         # console on https://127.0.0.1:5173
```

VS Code forwards ports 8000 and 5173 to the host's loopback; if they are taken, it picks free ones. In a `git worktree`, git inside the container cannot reach the main repository's `.git`; use a plain clone for container git work.

## CI

`.github/workflows/hactu8-deterministic.yml` runs on pushes and pull requests to the `phase1-*` branches. It runs the unit tests and `python -m hactu8 run all --backend echo` on Python 3.10 (standard library only) and 3.14 (pinned dependencies), markdownlint, and the console build. `scripts/sarif_all.py` merges the 3.14 runs into one SARIF file, which is kept as a build artifact and uploaded to code scanning. The findings are the attacks each lab demonstrates on purpose; the suite passes or fails on the exit code of `run all`. Only the upload job has `security-events: write`.

## Without Docker on macOS

Python from the python.org macOS installer does not use the system keychain and ships no CA bundle of its own, so HTTPS calls (OpenRouter, Anthropic, OpenAI) fail with `CERTIFICATE_VERIFY_FAILED`. Run "Install Certificates.command" from the Python folder in Applications, or set `SSL_CERT_FILE=/etc/ssl/cert.pem`. This does not apply inside the container, which uses Debian's CA bundle.
