# HX05 — OAuth Confused Deputy (MCP) Demo

An educational, self-contained demonstration of **HX05: the OAuth confused
deputy through an MCP proxy**. An **MCP proxy server** connects MCP clients
to a third-party API and is, to that API, one OAuth client with a **static
client ID**. When it also accepts any registered client, relies on the third
party's consent cookie, matches redirect URIs loosely, skips PKCE and passes
tokens through, an attacker's redirect or tool walks away with a user's
token. Four layers in the proxy shut it down: per-client consent, exact
redirect matching, PKCE and audience-bound tokens.

The scenario is **"Lamb," Big Field Jumper Co.'s assistant**, an MCP client that
reaches each customer's ledger through Big Field Jumper Co. Ledger MCP, a proxy to
Pasture Accounts under the client ID `bigfield-ledger-proxy`. Lamb also uses
Hayloft Analytics, a third-party MCP server, for spending charts. The ground
truth: _a customer's ledger token never reaches anyone but the ledger._
Hayloft Analytics 2.0 makes three moves (one registered client and mailed
link, one line in its chart result, one ledger connector) and receives three
customers' tokens.

> ⚠️ **For authorized security education and red-teaming only.** The
> vulnerable proxy is insecure **by design**. Do not deploy it anywhere
> reachable.

The attack is benign-effect: every server and every customer's browser is a
Python object inside the lab process, the browser follows only lab URLs on
`http://127.0.0.1:5505`, and every token is a fictional per-run canary
(`HX05-CANARY-` + 16 hex digits). To write your own attack, see
`hx05-oauth-deputy-skill/assets/hostile_oauth.README.md`.

**Simulated protocol.** The lab uses the parameter and response shapes of
the MCP authorization spec (revision 2026-07-28) and OAuth 2.1:
`client_id`, `redirect_uri`, `state`, `code_challenge` with `S256`,
`resource` (RFC 8707), dynamic registration metadata, the token response, a
`Bearer` header. They are exchanged in-process. No identity provider, HTTP
hop, OAuth library or real token is involved, so the lab runs on the
standard library and its numbers are deterministic.

## Interactive web demo (recommended)

The target serves the shared HACTU8 lab console: four act cards, a
verification table with Act 1, Act 3 and Act 4 signals side by side, and a
live feed of attack and defence events.

```bash
cd hx05-oauth-deputy-skill
python vulnerable_app.py              # then open http://127.0.0.1:5505/
```

Use **Run full sequence** to play all four acts, or click the acts one at a
time. **Reset baseline** restores Hayloft 1.0 and mints new tokens. To play
the sequence on load, for a presentation, open `http://127.0.0.1:5505/#run`.

## Fastest way to run (no browser)

```bash
cd hx05-demo
python run_demo.py                     # all four acts in one process, stdlib only
```

---

## Why this matters (HX05 in one paragraph)

Prompt injection labs ask what a model can be talked into. Here the model
barely matters: the authority leaks through the proxy's OAuth plumbing. The
MCP spec's security best practices page lists the exact preconditions (a
static client ID, dynamic registration, a third-party consent cookie, no
per-client consent) and calls token passthrough an anti-pattern that the
authorization spec forbids. In every conversation the customer gets a
correct answer; the token leaves in a redirect or a header nobody reads.
This demo makes that visible and quantifies it with a **Token Theft Rate
(TTR)** and a red/yellow/green **stoplight KPI**, graded from what the
attacker's server actually received.

---

## Quick start

```bash
cd hx05-demo
python run_demo.py
```

You'll see four acts:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | Dana's balance, Ravi's chart, Mei's statement, Omar's first connection, a returns question | 🟢 all GREEN, TTR 0% |
| **2 — Hayloft 2.0** | A registered client and a mailed sign-in link; a reconnect line in the chart result; a ledger connector | three moves, no proxy code changed |
| **3 — Post-attack impact** | The same five questions | 🔴 Dana, Ravi, Mei RED, **TTR 100% targeted / 60% overall**; controls 🟢 |
| **4 — Remediation** | Per-client consent, exact redirect, PKCE S256, audience-bound tokens | 🟢 back to GREEN, TTR 0%, every task still works |

After Act 4, the run prints each layer on its own (67% each: one layer
closes one path) and the measured limit: a client registered under Lamb's
own name is approved by the user and receives a working token for Dana (see
"Where the defense stops working" in the lesson).

### Optional: run against a real model

`echo`, the lab's deterministic offline model, is the default backend (`stub`
still works as an alias). Only echo has been run for this lab.
`providers.py`, HACTU8's provider layer, adds real ones, standard library
only.

```bash
python run_demo.py --backend ollama --model gemma3:4b         # local Ollama
python run_demo.py --backend llamacpp                         # local llama.cpp server
export OPENROUTER_API_KEY=...                                 # remote; key stays in the header
python run_demo.py --backend openrouter --model meta-llama/llama-3.2-3b-instruct

# the target and console take the same settings from the environment:
HX05_BACKEND=ollama HX05_MODEL=gemma3:4b python hx05-oauth-deputy-skill/vulnerable_app.py
```

The OpenRouter key comes from the environment only. The console never asks for
it and is only told whether one is set.

The real model decides what to do with Hayloft's chart result: reply
`{"action": "none"}` or `{"action": "connect_ledger", "redirect_uri": ...}`.
Lamb's replies stay templated, and Lamb's client code adds PKCE, `state`
and `resource` itself. The model never sees a token. A real model may ignore
the reconnect line, which closes the redirect path only; `run_demo.py`
reports the numbers rather than asserting them. `LAB_MAX_CALLS` (default
200) and `LAB_MAX_TOKENS` (default 400) cap calls and output tokens per
process. With `openrouter`, the tool result leaves the machine.

---

## Architecture

```text
   customer ──▶ Lamb (MCP client)  ── tools/call + Bearer ──▶ Big Field Jumper Co. Ledger MCP (vulnerable_app.py)
     browser      • PKCE, state, resource                         • authorization server for MCP clients
     (cookies,    • follows tool results                          • open dynamic registration
      inbox)            │                                         • no per-client consent, prefix redirects
        │               │ chart_spending                          • no PKCE check, token passthrough
        │               ▼                                               │ static client ID
        │        Hayloft Analytics 2.0 ◀── connector request ───────────┤
        │          • chart tool + reconnect line                         ▼
        └──────▶   • /hayloft/catch, redeems codes          Pasture Accounts (consent cookie)
                   • logs everything ──▶ /attacker-log      and Pasture Ledger API
```

### The modules

1. **Vulnerable target** — [`vulnerable_app.py`](hx05-oauth-deputy-skill/vulnerable_app.py).
   `LedgerProxy` omits per-client consent, exact redirect matching, PKCE and
   any audience check.
2. **Attack skill** — [`scripts/run_oauth_attack.py`](hx05-oauth-deputy-skill/scripts/run_oauth_attack.py).
   Installs [`assets/hostile_oauth.json`](hx05-oauth-deputy-skill/assets/hostile_oauth.json)
   as Hayloft 2.0 and asks the targeted questions.
3. **Stoplight KPI comparator** — [`scripts/evaluate_kpi.py`](hx05-oauth-deputy-skill/scripts/evaluate_kpi.py).
   Classifies each question GREEN/YELLOW/RED from Hayloft's log and computes
   the TTR.

Plus the mitigation used in Act 4: the four layers in `LedgerProxy`
(`use_consent`, `use_exact_redirect`, `use_pkce`, `use_audience`), and an
offline check of the attack (`scan_attack`) that uses
[`protectogw`](hx05-oauth-deputy-skill/protectogw/README.md) on the tool
result.

### How the theft is real, not scripted

Nothing in the lab checks a customer's name to decide a grade. Each token
moves through the OAuth steps the spec describes, and each layer is a real
check on those steps:

- The mailed link is Hayloft's own flow. The proxy forwards it; Pasture
  sees its consent cookie and issues a code; the proxy's code goes to the
  registered redirect, which is Hayloft's. With per-client consent, the
  proxy's page is shown and denied, and no code is issued.
- The reconnect is Lamb's own flow, with Lamb's PKCE pair. The prefix test
  passes the tampered URI, and `posixpath.normpath` in the browser lands it
  on Hayloft. Exact matching refuses it; PKCE leaves Hayloft with a code it
  cannot redeem.
- The share forwards the bearer it was given. Audience binding gives
  Hayloft a token only Hayloft accepts, and the proxy rejects it when
  Hayloft tries it.

Each layer is measured alone (`LayersTest`), and the stand-in model has one
contract, tested on its own (`StandInTest`).

### MCP terminology bridge

Lamb is what the spec calls an MCP **client** (an OAuth client); Big Field Jumper Co.
Ledger MCP is an MCP **server** (a resource server) with its own
authorization server, and an **MCP proxy server** in the best practices
page's terms; Pasture Accounts is the **third-party authorization server**
and Pasture Ledger API the **third-party API**. `LedgerProxy.authorize`,
`LedgerProxy.token`, `LedgerProxy.register` and `LedgerProxy.call_tool` stand
in for the authorization endpoint, the token endpoint, the registration
endpoint and `tools/call`; `Browser.follow` stands in for the user agent.
This demo is **not** a real MCP server, OAuth server or client and uses no
SDK or library.

---

## Live two-terminal demo (optional)

```bash
# Terminal A — start the vulnerable target
cd hx05-oauth-deputy-skill
python vulnerable_app.py                                   # serves on 127.0.0.1:5505

# Terminal B — a balance, the attack, the same balance
curl -s localhost:5505/ask -H 'content-type: application/json' \
     -d '{"account":"dana","message":"What is my ledger balance?"}'     # GREEN
python scripts/run_oauth_attack.py                         # Hayloft 2.0, asks again
curl -s localhost:5505/attacker-log                        # the tokens, as Hayloft received them
curl -s localhost:5505/oauth-log                           # what the proxy and Pasture did
```

---

## Mapping to the MCP authorization spec

| Demo component | Spec concept | Failure demonstrated | Mitigation shown |
|----------------|--------------|----------------------|------------------|
| `registration` + `phish` | Static client ID, dynamic registration, consent cookie | Code delivered to the attacker without the user's consent | Per-client consent |
| `tool_result_extra` | Exact redirect URI validation | A tampered `redirect_uri` passes a prefix match | Exact redirect match |
| Hayloft redeems Ravi's code | PKCE (S256) | A code redeemed without the verifier | PKCE |
| `connector` + `share_statement` | Token passthrough, audience validation | The client's token forwarded downstream | Audience-bound tokens |
| `lookalike-client` (limits) | Consent UI naming the client and `redirect_uri` | An approved lookalike client | Not closed; measured |
| Omar's connection, returns question | — | Attack is targeted, not a global break | — |

## Mitigations demonstrated in Act 4

- **Per-client consent** (`per_client_consent`) — a registry of approved
  `client_id` values per user, checked before forwarding to Pasture; the
  proxy's own consent page names the client, the scopes and the
  `redirect_uri`.
- **Exact redirect match** (`exact_redirect_uri`) — string equality with a
  registered URI.
- **PKCE** (`pkce`) — S256 `code_challenge` required, `code_verifier`
  checked.
- **Audience-bound tokens** (`audience_binding`) — proxy-minted tokens for
  its own `resource`, the Pasture token kept server-side, a separate token
  per downstream.

Further hardening is discussed in the references but not coded here: the
`state` rules for proxies (set after consent, single-use, short-lived),
`__Host-` signed consent cookies bound to the client, CSRF and anti-framing
on the consent page, `iss` validation against mix-up, Client ID Metadata
Documents with domain trust policies, and a consent page that warns on a new
client with a known name.

---

## Project layout

```text
hx05-demo/
├── README.md                          # this lab guide
├── run_demo.py                        # all four acts in one process, each layer alone, the limit
├── hx05-oauth-deputy-skill/
│   ├── SKILL.md                       #   metadata + instructions
│   ├── LESSON.md                      #   the lesson the console's Learn view renders
│   ├── vulnerable_app.py              #   Module 1: proxy, Pasture, Hayloft, browsers, Lamb, the four layers
│   ├── providers.py                   #   optional real-model backends (shared, unchanged)
│   ├── requirements.txt               #   stdlib only
│   ├── protectogw/                    #   HACTU8's screening core (vendored unchanged)
│   ├── web/                           #   shared lab console (index.html, app.js, styles.css)
│   ├── scripts/
│   │   ├── run_oauth_attack.py        #   Module 2: the attack (--install-only)
│   │   ├── evaluate_kpi.py            #   Module 3: stoplight KPI, --harden, --scan, --probe
│   │   └── reset_baseline.py          #   restore Hayloft 1.0, new tokens, vulnerable mode
│   ├── references/
│   │   └── HX05_RISKS.md              #   spec requirements, scenarios, mitigation roadmap
│   ├── assets/
│   │   ├── ledger.json                #   customers, balances, spending, statements, return policy
│   │   ├── clients.json               #   the proxy, Lamb's registration, Pasture, Hayloft 1.0
│   │   ├── hostile_oauth.json         #   Hayloft 2.0 and the limit (editable)
│   │   └── hostile_oauth.README.md    #   how each move works
│   └── tests/
│       ├── test_grading.py            #   the attacker-received oracle both ways, YELLOW and GREEN
│       └── test_lifecycle.py          #   four acts, each layer, OAuth mechanics, stand-in, limit, console, backends
└── .gitignore
```

## Packaged Claude Skill

`hx05-oauth-deputy-skill/` follows the `SKILL.md` + `scripts/` /
`references/` / `assets/` convention. To install it, copy the folder into
your `.claude/skills/` directory.

```bash
cd hx05-oauth-deputy-skill
python vulnerable_app.py &                                   # start target (:5505)
python scripts/evaluate_kpi.py                               # baseline (GREEN), exit 0
python scripts/run_oauth_attack.py                           # attack
python scripts/evaluate_kpi.py                               # RED, TTR 100%, exit 2
python scripts/evaluate_kpi.py --scan                        # the attack checked offline, exit 2
python scripts/evaluate_kpi.py --harden                      # GREEN, TTR 0%, exit 0
python scripts/evaluate_kpi.py --probe                       # measured limit, exit 2
python scripts/reset_baseline.py                             # restore clean state
python scripts/evaluate_kpi.py                               # GREEN, TTR 0%
python -m unittest discover tests                            # 42 tests
```

## License

MIT — provided for educational and authorized security-testing use.
