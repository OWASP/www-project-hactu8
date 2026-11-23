# HACTU8 security audit against the OWASP Top 10:2025

- Edition: OWASP Top 10:2025, the current release at <https://top10.owasp.org/2025/> (fetched 2026-11-23). SSRF now sits under A01.
- Code: branch `ui-review` (PR #42) at `4795ca5`, audited read-only.
- Test setup: the build on <http://127.0.0.1:8010>, plus my own instances: API and console on 127.0.0.1:8030 (HACTU8_HOME in the scratch dir, console bundle copied to scratch with its API base changed to 8030), MCP HTTP on 8031, and a framing page on 8032. All were stopped afterwards. Only the echo backend was used, so nothing was spent.
- Scope: labs and Lamb were checked only for sandbox escape. Their intended vulnerabilities are not findings.

## Summary

| # | Category | Finding | Location | Severity |
|---|---|---|---|---|
| 1 | A02 Misconfiguration | No security headers. The console can be framed by another origin (clickjacking on "Run this lab" and the spend checkbox). There is also no CSP, X-Content-Type-Options or Referrer-Policy | hactu8/api.py:67-83 (no header middleware), api.py:263-281 | Medium |
| 2 | A03 Supply chain | FastAPI's default `/docs` page loads `swagger-ui-dist@5` (floating major version, no SRI) from cdn.jsdelivr.net. That script runs on the API's own origin, which has no authentication and can start paid runs | hactu8/api.py:66 (`FastAPI(...)` with docs_url and openapi_url left at their defaults) | Medium |
| 3 | A03 Supply chain | The console ships react-router / react-router-dom 7.7.1, which has 14 advisories; `npm audit --omit=dev` rates 2 of them high. In this SPA's usage every route target is a static path, so I could not reach any of them | spikes/iac-prototype/iac-host/package.json:24, package-lock.json:4196-4198 | Low |
| 4 | A05 Injection | The report's "Reproduce" command puts the stored backend and model into a bash block without quoting. Neither value is validated before the result is saved (echo/live accepts any model; /api/runs accepts any backend). So `--model $(id)` reaches a copy-paste shell line | hactu8/reports.py:181-186; api.py:167-181, 216-243 | Low |
| 5 | A08 Integrity | The Docker base images are pinned by tag, not by digest | Dockerfile:9-10 | Low |
| 6 | A02 Misconfiguration | The devcontainer image grants `hactu8 ALL=(root) NOPASSWD:ALL` | Dockerfile:50 | Low (dev target only) |
| 7 | A07 / A01 | There is no authentication. The Host allow-list is the only gate, and a non-browser client sets Host itself. This is fine on loopback. But the image binds 0.0.0.0 (Dockerfile:76), so `docker run -p 8000:8000` without compose exposes paid runs to the LAN | Dockerfile:76, api.py:77-83 | Low (needs a misconfiguration; docs/deploy.md:22 warns about it) |
| 8 | A09 Logging | Paid-run approvals have no audit record. A refused (402) attempt leaves only a uvicorn access line, and an accepted one only the result file. Access lines carry no backend, model or confirm_spend | api.py:167-243 | Low |
| 9 | A10 Exceptions | One stray valid-JSON file without `run_id` in the results directory makes `/api/results/<id>` and `/api/reports/...` return 500 (KeyError). It also becomes "latest". The stack trace is not leaked to the client | hactu8/store.py:31-49 | Low |

## Reproductions

### 1. Missing headers and framing (Medium)

`curl -si http://127.0.0.1:8010/` returns only date, server, content-type, accept-ranges, content-length, last-modified, etag and `vary: Origin`. There is no X-Frame-Options, CSP frame-ancestors, X-Content-Type-Options or Referrer-Policy. API responses are the same.

Browser test (Claude in Chrome): a page served from <http://127.0.0.1:8032> (a different origin) holding `<iframe src="http://127.0.0.1:8030/console" style="opacity:.5">` loaded and rendered the full console, with the "Run this lab" button visible and clickable.

The Run page's cloud flow is: select backend, tick `confirm-spend` (Console.tsx:149), click Run. A clickjacking page can stage these clicks against the owner's API keys. Chrome's Local Network Access prompt makes framing from a public site harder, but it is not a defence in depth the app sets itself.

Fix: add a middleware that sets

- `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'` (the HTML report too)
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`

### 2. Swagger UI from the CDN (Medium)

`curl -s http://127.0.0.1:8010/docs` contains:

- `src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"`
- `href=".../swagger-ui-dist@5/swagger-ui.css"`

`/openapi.json` and `/redoc` both return 200. The script is not pinned and has no SRI. It executes on the 127.0.0.1:8010 origin, which can `POST /api/live {"confirm_spend":true}`.

Fix: `FastAPI(docs_url=None, redoc_url=None)`, or serve a vendored, pinned Swagger bundle.

### 3. react-router 7.7.1 (Low)

`npm audit --omit=dev` in spikes/iac-prototype/iac-host reports react-router 6.0.0-7.17.0 at high severity (GHSA-2w69-qvjg-hvjx, -wrjc-x8rr-h8h6, -2j2x-hqr9-3h42, -49rj-9fvp-4h2h and others) and react-router-dom as dependent: "2 high severity vulnerabilities". The installed version is 7.7.1.

The console uses `BrowserRouter` with static `to=`/`navigate()` targets only (App.tsx, Learn.tsx:53-57), so none of these advisories could be reached. Upgrade anyway (`npm audit fix`, react-router >= 7.17.1) so a published OWASP project does not ship an audit-red lockfile. The full audit output is in the scratch dir as npm-audit.txt.

### 4. Unquoted shell in "Reproduce" (Low)

```text
curl -X POST :8030/api/live -H 'content-type: application/json' -d '{"backend":"echo","model":"$(id)"}'
# -> 200, stored model "$(id)"
curl :8030/api/reports/<run>/markdown
# line 307: python -m hactu8 live --backend echo --model $(id)
curl -X POST :8030/api/runs -d '{"skill_id":"hx01","backend":"echo; touch /tmp/pwned #..."}'
# -> 200, result saved (status error); report line 23:
# python -m hactu8 run hx01 --backend echo; touch /tmp/pwned #...
```

No command ran on the server (subprocess uses an argv list; /tmp/pwned was never created). The risk is a reader pasting the command from a shared report.

Fix:

- `shlex.quote` both values in `_reproduce`.
- Reject a backend not in `providers.BACKENDS` and a model failing `MODEL_RE` at the API boundary, as `mcp_server._backend` already does.

### 5-6. Dockerfile (Low)

- Dockerfile:9-10: `python:3.14.10-slim-trixie` and `node:24.22.3-trixie-slim` are mutable tags. Pin `@sha256:` digests.
- Dockerfile:50: passwordless sudo in the dev target. It is documented for the devcontainer's setup; keep it out of anything published.

### 7. No authentication (Low)

api.py:77-83 rejects only on the Host header. `curl -H 'Host: LOCALHOST:8010' ...` returns 200, and a non-browser client can always send an allowed Host. Compose publishes on `127.0.0.1:` only (docker-compose.yml:20), so the default exposure is the local user.

The Dockerfile CMD binds 0.0.0.0 (Dockerfile:76). With a plain `docker run -p 8000:8000`, any LAN client could run cloud backends on the owner's keys by sending `Host: 127.0.0.1:8000`.

Fix: consider an optional bearer token (HACTU8_API_TOKEN) required whenever cloud keys are set, or refuse `confirm_spend` unless the peer address is loopback.

### 8. No audit of spend approvals (Low)

The access log at 8030 shows only `"POST /api/live HTTP/1.1" 200 OK` and `"POST /api/wolf HTTP/1.1" 422`. Backend, model and confirm_spend are not recorded, and 402 refusals leave nothing else.

Fix: append one JSON line per paid-run request (time, endpoint, backend, model, confirm_spend, outcome, run_id) under $HACTU8_HOME.

### 9. A stray results file breaks lookups (Low)

`echo '{"note":"not a run"}' > $HACTU8_HOME/results/zz-stray.json` gives:

- `/api/results/nonexistent`: 500
- `/api/reports/latest/html`: 500
- `/api/results/latest`: the stray doc

The server log shows `KeyError: 'run_id'` and `KeyError: 'summary'`. The client gets only "Internal Server Error".

Fix: in `list_runs`, skip documents that are not dicts or lack schema/run_id.

## What held (tested)

- **A01, CSRF and DNS rebinding on the API:**
  - Host `evil.example`, `127.0.0.1:8010.evil` → 421.
  - Cross-origin preflight → 400, with no Access-Control-Allow-Origin.
  - Simple-request bodies are refused by FastAPI 0.165: `text/plain` → 422, no Content-Type → 422.
  - CORS allows only :5173.
- **A01, path traversal:**
  - Console static route: `/../../../etc/passwd`, `%2e%2e/...`, `..%2f...` and `assets/../../..` all return index.html (resolve plus is_relative_to).
  - `skill_id` is matched against the discovered catalog, so `../../etc` → 400 unknown skill.
  - `run_id` is matched against loaded documents and never joined into a path.
  - Report format is allow-listed.
- **A01, SSRF:** no endpoint takes a URL. Provider URLs come only from environment variables. The `_urlopen` wrapper allows http(s) only and refuses redirects. Local backends refuse non-loopback hosts unless `*_ALLOW_REMOTE=1`.
- **A01, spend gates:** cloud backends need `confirm_spend` on /api/runs, /api/live and /api/wolf, and on the llm-judge. `normalize()` is shared with the labs, so case and whitespace variants are still gated. The classifier name is matched exactly. Wolf rounds and attempts are clamped (`{"rounds":-5,"attempts":99999999}` → bounded run; `1e308` → 422).
- **MCP HTTP server (8031):**
  - Host `evil.example` → 421.
  - Origin `evil.example` → 403.
  - `text/plain` → 400.
  - Preflight → 403 "Invalid Origin header".
- **A04:** canaries, run ids and fences use `secrets.token_hex`. No secrets are in the repo (git grep for real key formats found only the test FAKE key). Keys come from an env_file outside the repo. `.dockerignore` excludes .env and .hactu8. `/api/models` exposes only `keys_set` booleans. Results and reports pass through `providers.redact`. Plain HTTP on loopback is the only transport issue, and it is being changed in parallel.
- **A05, command injection:** every subprocess call uses an argv list with no shell: lab.py:219, providers.py:866 and lamb/workers.py:81. Payload `echo; touch /tmp/pwned` did nothing. There is no eval, exec, pickle or yaml.load in the harness. scripts/notify-chat.sh builds its JSON with `json.dumps`.
- **A05, XSS:**
  - The HTML report escapes every line (`html.escape`); the payloads came out as `&lt;img...`.
  - Reports are served as attachments.
  - In the browser, a planted result with `<img onerror>`, `<script>` and `[x](javascript:...)` in evidence, reason, prompt and output rendered as text 21 times, with 0 injected elements and 0 javascript: links.
  - ReactMarkdown uses rehype-sanitize, and there is no dangerouslySetInnerHTML.
  - All 50 lab app.js files use textContent.
- **A03, Python:** osv.dev querybatch on all 30 pins in docker/requirements.txt found 0 known vulnerabilities.
- **A08, CI:** every action is pinned by SHA. The workflow sets `permissions: contents: read` and `persist-credentials: false`. SARIF upload is restricted to same-repo PRs. No `${{ github.event.* }}` value reaches a `run:` line.
- **Labs and Lamb sandbox:**
  - All 49 vulnerable_app.py bind `("127.0.0.1", PORT)` and check Host.
  - Static files are served from a WEB_FILES allow-list.
  - The ASI05 code-exec sink is AST-parse only.
  - Lamb binds 127.0.0.1 and requires a loopback Host and Origin and a JSON Content-Type on control calls.
  - The container drops all capabilities and sets no-new-privileges.
- **A10:** errors return JSON details with no stack traces, and provider errors are redacted.

## Fixes (2026-11-23, PR #42)

All nine findings are fixed, each with a regression test that failed before the fix (`tests/test_top10.py`, `tests/test_api_tls.py`):

1. Security headers on every response (nosniff, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, COOP) and a strict CSP on the console; the API and console serve HTTPS by default.
2. FastAPI `/docs`, `/redoc` and `/openapi.json` are off unless `HACTU8_API_DOCS=on`.
3. react-router-dom 7.7.1 -> 7.18.6; `npm audit --omit=dev` reports 0 vulnerabilities.
4. The "Reproduce" line quotes every value with `shlex.quote`; the API and CLI reject unknown backends and unsafe model names (422 / exit 2).
5. Base images pinned by digest.
6. The dev image's sudo allows one `chown` of the node_modules volume and nothing else.
7. Bound off-loopback, the API requires a token (login URL printed once; HttpOnly, Secure, SameSite=Strict cookie or `Authorization: Bearer`); the token is redacted from the access log.
8. Every request that could spend is appended to `$HACTU8_HOME/audit.log` (no keys or tokens).
9. Result files without a `run_id` are skipped with a warning; HEAD works on the console.
