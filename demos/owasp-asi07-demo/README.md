# ASI07 — Insecure Inter-Agent Communication Demo

An educational, self-contained demonstration of **ASI07: Insecure
Inter-Agent Communication** from the OWASP Top 10 for Agentic Applications.
An executor agent that believes whatever a message says about its own sender,
and never asks whether a message is new, pays an unapproved invoice, cancels
an order and refunds an order a second time. Two mitigations shut the attack
down: **HMAC-signed messages with per-agent keys** and **nonce plus timestamp
replay protection**.

The scenario is **Goat & Co.'s back office, run by two agents.** "Billy
Planner" turns an operator's request into work orders and publishes them on an
in-process message bus; "Billy Exec" carries out the work orders it receives.
Its ground truth is the operator's intent: _"Pay invoice INV-3001" causes one
step, `pay_invoice:INV-3001`, and nothing else._ With **2** spoofed work
orders (one placeholder body with **2** directive lines) and **1** replayed
genuine order, the attacker makes every job on `payments` and `inventory` also
pay `INV-3999` and cancel `A-1002`, and every job on `refunds` repeat an old
refund of `A-0907`. Jobs on `shipping` and `reports` stay untouched. The
operator only sees each job finish.

> ⚠️ **For authorized security education and red-teaming only.** The vulnerable
> agents and their open bus endpoint are insecure **by design**. Do not deploy
> them anywhere reachable. The bus is in-process, the signing keys are
> demo-only random bytes held in memory, and every tool action is
> **simulated**: an entry in an in-memory action log. Nothing real is paid,
> refunded or cancelled.

The shipped payload is a **placeholder**: two stub directive lines and a
fictional canary. That is enough to drive the full lifecycle. To write your own
payload, see `owasp-asi07-a2a-skill/assets/forged_order.README.md`.

## Interactive web demo (recommended)

The target serves the shared HACTU8 lab console. It has four act cards, a
verification table with Act 1, Act 3 and Act 4 signals side by side, and a
live feed of attack and defence events.

```bash
cd owasp-asi07-a2a-skill
python vulnerable_app.py              # then open http://127.0.0.1:5307/
```

Use **Run full sequence** to play all four acts, or click the acts one at a
time. **Reset baseline** restores the seeded records and bus and vulnerable mode. To play the
sequence on load, for a presentation, open `http://127.0.0.1:5307/#run`.

## Fastest way to run (no browser)

```bash
cd owasp-asi07-demo
python run_demo.py                     # all four acts in one process, stdlib only
```

---

## Why this matters (ASI07 in one paragraph)

Once agents hand work to other agents, the messages between them are
instructions, and the receiving agent acts on them with its own tools. If the
receiver identifies a peer by a field the peer writes itself, anyone who can
reach the channel can speak as that peer. If the receiver checks who sent a
message but not whether it is new, a captured genuine message can be sent
again and carried out again. Prompt-injection screening does not help here:
the forged order is phrased exactly like a real one. The defence is the old
one from network protocols: authenticate every message and reject replays.
This demo makes the gap visible and quantifies it with a **Forged Message
Acceptance Rate (FMAR)** and a red/yellow/green **stoplight KPI**.

---

## Quick start

```bash
cd owasp-asi07-demo
python run_demo.py
```

You'll see four acts:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | Run five operator jobs through planner and executor | 🟢 all GREEN, FMAR 0% |
| **2 — Spoof + replay** | Retain a "planner" order on 2 topics; re-publish 1 old genuine order | 3 messages published, 0 tools called |
| **3 — Post-attack impact** | Re-run the exact same jobs | 🔴 targeted RED, **FMAR 100% targeted / 60% overall** |
| **4 — Remediation** | Dry-run the payload through a verifier; switch to hardened mode | 🟢 back to GREEN, FMAR 0% |

### Optional: run against a real model

`echo`, the lab's deterministic offline model, is the default backend (as in
AgenticGoat; `stub` still works as an alias). `providers.py` (the same provider
layer as AgenticGoat) adds three real ones. All are standard library only.

In the web console, pick the backend and model in the **BACKEND / MODEL** bar
and press **Use backend**. The model list is fetched live from Ollama,
llama.cpp or OpenRouter, with free text as the fallback. From the command line:

```bash
python run_demo.py --backend ollama --model llama3.2:3b          # local Ollama
python run_demo.py --backend llamacpp                         # local llama.cpp server
export OPENROUTER_API_KEY=...                                 # remote; key stays in the header
python run_demo.py --backend openrouter --model meta-llama/llama-3.2-3b-instruct

# the target and console take the same settings from the environment:
ASI07_BACKEND=openrouter ASI07_MODEL=... python owasp-asi07-a2a-skill/vulnerable_app.py
```

The OpenRouter key works as in AgenticGoat: export `OPENROUTER_API_KEY` in the
shell that starts the lab. The console never asks for it and is only told
whether one is set; without it, `openrouter` is greyed out in the picker.

The backend replaces Billy Exec's model (`ProviderModel` in
`vulnerable_app.py`); Billy Planner stays a deterministic stub, so genuine
work orders are the same on every backend. The bus, the attack and the
verifier are unchanged. Which work orders reach the model is still decided in
code, in both modes:
- **Vulnerable mode** pastes every order whose `sender` field says `planner`
  into the user turn as plain text.
- **Hardened mode** runs `verify_message` first (signature, sender allowlist,
  replay), then fences each verified order in `<work_order>` tags and tells the
  model to take only the requested tool steps from it ("spotlighting").

The model replies with one JSON object, `{"calls": [{"tool": ..., "args":
{...}}]}`. The reply is parsed defensively: unknown tools, bad arguments and
any call whose target is not named in an accepted work order are dropped, and
unparseable output means no calls. Accepted calls go through the same
simulated tools and action log as the stub's; nothing the model returns is
executed or fetched. The verifier needs no change for a real model, because it
never reads a message's wording (see the payload README), and `run_demo.py`
reports the numbers rather than asserting them.

Limits:
- `LAB_MAX_CALLS` (default 200) caps calls per process. One model call per job.
- `LAB_MAX_TOKENS` (default 400) caps output tokens per call.
- `OLLAMA_TIMEOUT`, `LLAMACPP_TIMEOUT` and `OPENROUTER_TIMEOUT` set
  per-provider HTTP timeouts.

With `openrouter`, lab prompts, including your payloads, leave the machine.
Echo and the local backends keep everything on the host.

---

## Architecture

```
                 ┌──────────────────────────────────────────────────────┐
   operator ────▶│  Billy Planner (vulnerable_app.py :5307)             │
   request+topic │   • plans steps (stub), signs one work order each    │
                 └───────────────┬──────────────────────────────────────┘
                                 │ publish (signed, per topic)
                 ┌───────────────▼──────────────────────────────────────┐
                 │  In-process message bus                              │
                 │   topics: payments refunds inventory shipping reports│
                 │   retained msgs ◀ attack    GET /bus/log (readable)  │
                 └───────────────┬──────────────────────────────────────┘
                                 │ subscribe per job: retained first
                 ┌───────────────▼──────────────────────────────────────┐
                 │  Billy Exec                                          │
                 │   • _accept: trusts sender field          ◀── gap    │
                 │   • hardened: verify_message (HMAC, nonce, ts)       │
                 │   • model follows accepted orders (stub)             │──▶ action log
                 └──────────────────────────────────────────────────────┘    (simulated)
                                 ▲
                                 │ POST /bus/publish (no auth, any sender)
                 ┌───────────────┴──────────────────────────────────────┐
   attacker ────▶│  Attack skill (scripts/run_bus_forgery.py)           │
                 │   2 spoofed orders + 1 replay copied from the log    │
                 └──────────────────────────────────────────────────────┘
```

### The modules

1. **Vulnerable target** — [`vulnerable_app.py`](owasp-asi07-a2a-skill/vulnerable_app.py).
   It omits sender authentication, replay protection, and access control on
   publishing and reading the bus.
2. **Attack skill** — [`scripts/run_bus_forgery.py`](owasp-asi07-a2a-skill/scripts/run_bus_forgery.py).
   Publishes [`assets/forged_order.md`](owasp-asi07-a2a-skill/assets/forged_order.md)
   as a retained "planner" order on two topics, and re-publishes an old
   genuine order read from `GET /bus/log`.
3. **Stoplight KPI comparator** — [`scripts/evaluate_kpi.py`](owasp-asi07-a2a-skill/scripts/evaluate_kpi.py).
   Compares each job's executed steps with the intended steps, classifies
   GREEN/YELLOW/RED and computes the FMAR.

Plus the mitigation used in Act 4: hardened mode and `verify_message` in
`vulnerable_app.py`, with the settings from [`assets/bus_policy.json`](owasp-asi07-a2a-skill/assets/bus_policy.json).

### How the "forgery" is real, not scripted

The executor's model is a deterministic stub with one fixed contract: it
requests every step written on a directive line in the work orders that reach
its context. The planner writes genuine orders in that same syntax. That
contract never changes between acts, and it is the same in both modes. What
changes is **which messages are on the bus** and **which ones the executor
lets through**:

- The attack publishes three messages; no tool is called at that point.
- The bus delivers retained messages to every new subscriber, so only jobs on
  the three affected topics see them. The controls never do.
- In vulnerable mode `Lab._accept` lets through any work order whose `sender`
  field says `planner`, so the spoofed steps and the replayed refund land in
  the action log next to the genuine ones.

The KPI is computed from the action log, not from answer text. Signing is real
`hmac`/`hashlib` over a canonical encoding of the message with per-agent keys
from `secrets`. In hardened mode the retained messages are still on the bus;
`verify_message` rejects the spoof (signature does not verify with the planner
key) and the replay (nonce already used, timestamp 3 days old). Signing alone
leaves the replay working (`tests/test_lifecycle.py::test_signature_alone_misses_replay`),
replay checks alone leave the spoof working (`::test_replay_checks_alone_miss_spoof`),
and the nonce cache alone stops the replay (`::test_nonce_alone_blocks_replay`).
The planner's genuine orders still execute, so the controls stay GREEN.
Nothing is hard-coded to flip per job.

### MCP terminology bridge

MCP connects a client to tool servers; it does not cover how two agents talk
to each other, which is where agent-to-agent protocols come in. The bus here
stands in for that channel, and `Lab._accept` stands in for the receiving
agent's message handler. This demo is **not** an MCP server and does not
implement any A2A protocol: the agents, bus and tools are in-process Python.
Hardened mode is what a careful receiver should do on any such channel:
authenticate each message against the sender's own key and reject anything
already seen or too old, before the content reaches the model.

---

## Live two-terminal demo (optional)

```bash
# Terminal A — start the vulnerable target
cd owasp-asi07-a2a-skill
python vulnerable_app.py                                   # serves on 127.0.0.1:5307

# Terminal B — run a job, attack, run it again
curl -s localhost:5307/jobs -H 'content-type: application/json' \
     -d '{"request":"Pay invoice INV-3001.","topic":"payments"}'   # 1 step: pay_invoice:INV-3001

python scripts/run_bus_forgery.py                          # 2 spoofed + 1 replayed message

curl -s localhost:5307/jobs -H 'content-type: application/json' \
     -d '{"request":"Pay invoice INV-3001.","topic":"payments"}'   # 3 steps, 2 not planned

curl -s localhost:5307/api/actions                         # simulated payment + cancellation logged
curl -s localhost:5307/bus/log                             # who claimed to send what
```

---

## Mapping to the OWASP ASI07 entry

| Demo component | ASI07 scenario | Failure demonstrated | Mitigation shown |
|----------------|----------------|----------------------|------------------|
| `_accept` trusts the `sender` field | Spoofed peer agent | A forged "planner" order pays an invoice | HMAC per message with the sender's own key |
| Timestamp and nonce ignored | Message replay | An old genuine refund runs again | Nonce cache + timestamp window |
| `POST /bus/publish` with `retain` | Open channel | Anyone can inject into any topic | Verification at the receiver (`--scan` dry run) |
| `GET /bus/log` | Readable traffic | Signed messages can be captured | Replay checks make captures useless |
| Shipping / report jobs | — | Attack is targeted, not a global break | Genuine signed orders still execute |

## Mitigations demonstrated in Act 4

- **Signed messages with per-agent keys** — every agent has its own key; a
  work order must carry an HMAC-SHA256 that verifies with the key of the agent
  named in `sender`, and only `planner` may issue work orders. This alone
  stops the spoof, not the replay.
- **Replay protection** — each nonce is accepted once, and a timestamp must be
  within 300 s. This alone stops the replay, not the spoof. Either the nonce
  cache or the time window alone is enough for this replay.
- **Verifier dry run** — `evaluate_kpi.py --scan PATH` sends a message body as
  a spoofed planner order into a throwaway hardened executor and rejects it if
  it carries steps the verifier refuses.

Further hardening is discussed in the references but not coded here:
encrypted transport between agents, publisher authentication and per-agent
topic rights at the broker, key rotation, asymmetric signatures, and screening
genuine peer messages as untrusted input (AgenticGoat `a2a_scan`).

---

## Project layout

```
owasp-asi07-demo/
├── README.md                          # this lab guide
├── run_demo.py                        # all four acts in one process
├── owasp-asi07-a2a-skill/
│   ├── SKILL.md                       #   metadata + instructions
│   ├── vulnerable_app.py              #   Module 1: target, bus, stub agents, verifier
│   ├── providers.py                   #   optional real-model backends (shared, unchanged)
│   ├── requirements.txt               #   stdlib only
│   ├── web/                           #   shared lab console (index.html, app.js, styles.css)
│   ├── scripts/
│   │   ├── run_bus_forgery.py         #   Module 2: the attack
│   │   ├── evaluate_kpi.py            #   Module 3: stoplight KPI, --harden, --scan
│   │   └── reset_baseline.py          #   restore records and bus, clear the log
│   ├── references/
│   │   └── ASI07_RISKS.md             #   research, scenarios, mitigation roadmap
│   ├── assets/
│   │   ├── ops_baseline.json          #   items, invoices, orders, bus history
│   │   ├── forged_order.md            #   placeholder payload (editable)
│   │   ├── forged_order.README.md     #   how to write a payload
│   │   └── bus_policy.json            #   signature + replay settings (editable)
│   └── tests/
│       └── test_lifecycle.py          #   asserts the four-act story
└── .gitignore
```

## Packaged Claude Skill

`owasp-asi07-a2a-skill/` follows the `SKILL.md` + `scripts/` /
`references/` / `assets/` convention. To install it, copy the folder into your
`.claude/skills/` directory.

```bash
cd owasp-asi07-a2a-skill
python vulnerable_app.py &                                     # start target (:5307)
python scripts/evaluate_kpi.py                                 # baseline (GREEN), exit 0
python scripts/run_bus_forgery.py                              # attack
python scripts/evaluate_kpi.py                                 # RED, FMAR 100%, exit 2
python scripts/evaluate_kpi.py --scan assets/forged_order.md   # REJECT, exit 2
python scripts/evaluate_kpi.py --harden                        # GREEN, FMAR 0%, exit 0
python scripts/reset_baseline.py                               # restore clean state
python scripts/evaluate_kpi.py                                 # GREEN, FMAR 0%
python -m unittest discover tests                              # 18 tests
```

## License

MIT — provided for educational and authorized security-testing use.
