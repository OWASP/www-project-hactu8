# Security policy

## Reporting a vulnerability

Report a vulnerability in HACTU8 privately through GitHub's
[security advisory form](https://github.com/OWASP/www-project-hactu8/security/advisories/new)
for this repository. Please do not open a public issue. Include the version or
commit, what you did, what happened, and what you expected.

## What is vulnerable on purpose

HACTU8 is a training and assurance tool, so parts of it are built to be
attacked:

- the labs under `demos/` (each `vulnerable_app.py` and its stand-ins), and
- HACTU8 Lamb (`hactu8/lamb`), the sacrificial target.

Their documented attacks are features, not vulnerabilities. Every payload is
benign-effect: the only possible effect is emitting a fictional per-run canary
or calling a Lamb tool on loopback. Please do report it if a lab or Lamb
escapes that sandbox, for example:

- it listens on anything other than `127.0.0.1`,
- it reads or writes real files outside its fixture directory, reaches the
  network, or runs real code, or
- a payload can have a real effect on a system, data or account.

## What must be secure

Everything else: the API and console (`hactu8/api.py`,
`spikes/iac-prototype/iac-host`), the CLI, the MCP server, the router and
providers, results and reports, scripts, the Docker image and compose file, and
the CI workflows.

Defaults that protect a local install (details in
[docs/deploy.md](docs/deploy.md)):

- The API and console serve HTTPS with a self-signed certificate created per
  user (`~/.hactu8/tls`, key readable only by its owner), and answer only a
  loopback `Host`.
- Bound to anything other than loopback, the API requires a token; the login
  URL is printed once at start.
- Anything that can spend money on a cloud model needs explicit confirmation
  (`--confirm-spend` or `confirm_spend`) and is recorded in `audit.log`.
- API keys come from the environment only, are never written to results or
  reports, and are redacted from error text.

CodeQL code scanning (`.github/workflows/codeql.yml`) checks the Python core,
the console and the workflows on every push and pull request to the phase1
branches and weekly; `demos/` is left out because the labs are vulnerable on
purpose.

The harness was audited against the
[OWASP Top 10:2025](https://top10.owasp.org/2025/) on 2026-11-23; findings and
fixes are in
[docs/evidence/2026-11-23-owasp-top10-audit.md](docs/evidence/2026-11-23-owasp-top10-audit.md).
