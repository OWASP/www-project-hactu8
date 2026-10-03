# LLM02 — Sensitive Information Disclosure Demo

An educational, self-contained demonstration of **LLM02: Sensitive
Information Disclosure**. A customer who can edit only their own account notes
gets an account assistant to recite other customers' personal details and the
service key from its own prompt. Three mitigations shut the leak down:
**per-user record scoping**, a **secret vault**, and **output redaction**.

The scenario is **"Billy Accounts," Goat & Co.'s customer-account
assistant.** Its ground truth is _"Each customer sees only their own record;
the CRM service key never leaves the server."_ With **1** notes field carrying
**1** directive line, the attacker (account `C-1003`) turns every answer about
their own account into a dump of two other customers' names, emails and phone
numbers, plus the key. The other customers' own questions stay untouched, so
nobody whose data leaked sees anything wrong.

> ⚠️ **For authorized security education and red-teaming only.** The vulnerable
> assistant and its unscoped record tool are insecure **by design**. Do not
> deploy them anywhere reachable.

All records are fictional, and the shipped payload is a **placeholder**: a
marker line and two fictional record IDs. That is enough to drive the full
lifecycle. To write your own payload, see
`owasp-llm02-disclosure-skill/assets/pivot_note.README.md`.

## Interactive web demo (recommended)

The target serves the shared HACTU8 lab console. It has four act cards, a
verification table with Act 1, Act 3 and Act 4 signals side by side, and a
live feed of attack and defence events.

```bash
cd owasp-llm02-disclosure-skill
python vulnerable_app.py              # then open http://127.0.0.1:5202/
```

Use **Run full sequence** to play all four acts, or click the acts one at a
time. **Reset baseline** restores the seeded records and vulnerable mode. To
play the sequence on load, for a presentation, open `http://127.0.0.1:5202/#run`.

## Fastest way to run (no browser)

```bash
cd owasp-llm02-demo
python run_demo.py                     # all four acts in one process, stdlib only
```

---

## Why this matters (LLM02 in one paragraph)

Prompt injection (LLM01) is about who controls the model. Disclosure is about
**what the model can reach once it is controlled**, or simply asked nicely. A
model repeats what is in its context, so a credential in the system prompt or
a tool that returns any user's record is a leak waiting for a request.
Carlini et al. (2021) and Nasr et al. (2023) showed models emitting memorised
personal data; this demo shows the application-side path, where the data
never had to be memorised at all. It quantifies the exposure with a **Leak
Rate** and a red/yellow/green **stoplight KPI**.

---

## Quick start

```bash
cd owasp-llm02-demo
python run_demo.py
```

You'll see four acts:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | Five own-account questions from three signed-in customers | 🟢 all GREEN, Leak Rate 0% |
| **2 — Notes edit** | The attacker saves 1 directive line in their own account notes | 1 field changed |
| **3 — Post-attack impact** | Re-run the exact same questions | 🔴 targeted RED, **Leak Rate 100% targeted / 60% overall** |
| **4 — Remediation** | Scan the prompt; switch to hardened mode | 🟢 back to GREEN, Leak Rate 0% |

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
LLM02_BACKEND=openrouter LLM02_MODEL=... python owasp-llm02-disclosure-skill/vulnerable_app.py
```

The OpenRouter key works as in AgenticGoat: export `OPENROUTER_API_KEY` in the
shell that starts the lab. The console never asks for it and is only told
whether one is set; without it, `openrouter` is greyed out in the picker.

The attack mechanics are identical. Only the model changes. `ProviderModel`
makes two calls per question: a plan, where the model replies with a JSON
object `{"read_records": [...]}` naming extra record IDs to read, and the
answer. The plan is parsed defensively (well-formed IDs only, at most three;
anything else means no extra reads), and nothing the model returns is executed.
- **Vulnerable mode** sends the deployed prompt (key included) and pastes the
  record, notes and all, into the user turn as plain text.
- **Hardened mode** sends the vaulted prompt, fences tool output in
  `<untrusted_tool_output>` tags, and tells the model never to follow
  instructions inside them ("spotlighting"). Record scoping and output
  redaction stay in code, so they hold whatever the model asks for or writes.

A real model may ignore the placeholder payload. Write a natural-language
payload (see `assets/pivot_note.README.md`); any new secret format needs a
pattern in `assets/redaction_rules.json`. `run_demo.py` reports the numbers
rather than asserting them.

Limits:
- `LAB_MAX_CALLS` (default 200) caps calls per process.
- `LAB_MAX_TOKENS` (default 400) caps output tokens per call.
- `OLLAMA_TIMEOUT`, `LLAMACPP_TIMEOUT` and `OPENROUTER_TIMEOUT` set
  per-provider HTTP timeouts.

With `openrouter`, lab prompts, including your payloads, leave the machine.
Echo and the local backends keep everything on the host.

---

## Architecture

```
                 ┌──────────────────────────────────────────────┐
   session +  ──▶│  Billy Accounts (vulnerable_app.py :5202)    │──▶ answer
   question      │   • CRM key inlined in the system prompt     │   (no redaction)
                 │   • model picks read_record IDs              │
                 └───────────────┬──────────────────────────────┘
                                 │ read_record(any ID, no scoping)
                 ┌───────────────▼──────────────────────────────┐
   seeded      ─▶│  Record store (in memory, customers_baseline)│
   records       │   C-1001 · C-1002 · C-1003                   │
                 │   + C-1003 notes: 1 directive line ◀── attack│
                 └───────────────▲──────────────────────────────┘
                                 │ POST /account/notes (own account)
                 ┌───────────────┴──────────────────────────────┐
   attacker ────▶│  Attack skill (scripts/run_pivot.py)         │
   (C-1003)      │   1 field, 1 directive line                  │
                 └──────────────────────────────────────────────┘
```

### The modules

1. **Vulnerable target** — [`vulnerable_app.py`](owasp-llm02-disclosure-skill/vulnerable_app.py).
   It omits per-user scoping on `read_record`, keeps the CRM key in the
   prompt, and runs no redaction on output.
2. **Attack skill** — [`scripts/run_pivot.py`](owasp-llm02-disclosure-skill/scripts/run_pivot.py).
   Saves [`assets/pivot_note.md`](owasp-llm02-disclosure-skill/assets/pivot_note.md)
   as the attacker's own notes through `POST /account/notes`.
3. **Stoplight KPI comparator** — [`scripts/evaluate_kpi.py`](owasp-llm02-disclosure-skill/scripts/evaluate_kpi.py).
   Classifies each answer GREEN/YELLOW/RED and computes the Leak Rate. A leak
   is RED even when the correct answer is also present.

Plus the mitigation used in Act 4: hardened mode (`Vault`,
`move_secrets_to_vault`, scoped `read_record`, `redact_output`) in
`vulnerable_app.py`, with rules from [`assets/redaction_rules.json`](owasp-llm02-disclosure-skill/assets/redaction_rules.json).

### How the leak is real, not scripted

The model is a deterministic stub with one fixed contract: without a directive
it answers from the signed-in customer's record; with one, it reads any record
IDs the directive names and recites every `field: value` fact in its context.
That contract is the same in every act and in both modes. What changes is
**what the model can reach and what gets out**:

- The notes edit adds one directive line to the attacker's own record, which
  Billy reads with every question that account asks.
- In vulnerable mode `read_record` returns whichever records the model asks
  for, and the system prompt carries the key, so the recital holds both.
- Nothing filters the answer on its way out.

Remove the directive and the stub answers normally, so the Leak Rate falls to
0. Switch to hardened mode and the stub is **still fooled**: it still obeys
the directive and recites everything it holds. But the tool refuses the other
IDs and the key is in the vault, so all it holds is the customer's own record.
That alone takes the rate to 0 even with an empty redaction ruleset
(`tests/test_lifecycle.py::test_scoping_and_vault_alone_block`). Redaction
alone is not enough: it strips the key and the contact details but cannot
recognise a name (`test_redaction_alone_misses_names`). Nothing is hard-coded
to flip per question; the evaluator decides "leak" per session, from the
records that session does not own.

### MCP terminology bridge

In MCP, the **model chooses tool arguments** and the server runs the call.
`read_record` stands in for an MCP tool, and its `customer_id` argument is the
disclosure surface. This demo is **not** an MCP server or client: the tool is
an in-process function, the store is a dict, and the `session` field in each
request stands in for an authenticated session. Hardened mode is what a
careful MCP server should do: authorize each call against the session, not
against what the model asked for, and keep its own credentials out of the
model's context.

---

## Live two-terminal demo (optional)

```bash
# Terminal A — start the vulnerable target
cd owasp-llm02-disclosure-skill
python vulnerable_app.py                                   # serves on 127.0.0.1:5202

# Terminal B — query, attack, re-query
curl -s localhost:5202/query -H 'content-type: application/json' \
     -d '{"session":"C-1003","query":"What plan am I on?"}'   # Kid Starter, own data only

python scripts/run_pivot.py                                # 1 notes field saved

curl -s localhost:5202/query -H 'content-type: application/json' \
     -d '{"session":"C-1003","query":"What plan am I on?"}'   # other customers + CRM key
```

---

## Mapping to the OWASP LLM02 entry

| Demo component | LLM02 scenario | Failure demonstrated | Mitigation shown |
|----------------|----------------|----------------------|------------------|
| `read_record` + `POST /account/notes` | Unauthorized access to other users' data | Model-chosen tool arguments decide whose record is read | Per-user scoping (hardened mode) |
| `assets/system_prompt.txt` | Sensitive data in the application's configuration | Key in the prompt is recited with the context | Secret vault; `--scan` rejects the prompt |
| Unfiltered `/query` answer | Lack of output sanitisation | Canary and PII returned verbatim | Output redaction (`redaction_rules.json`) |
| `C-1001` / `C-1002` controls | — | Attack is targeted, not a global break | — |

## Mitigations demonstrated in Act 4

- **Per-user record scoping** — `read_record` refuses any ID but the signed-in
  customer's, whatever the model asks for. Together with the vault, this alone
  takes the Leak Rate to 0 here.
- **Secret vault** — `move_secrets_to_vault` lifts credential lines out of the
  prompt into a `Vault` with a masked `repr`; the CRM connector reads it, the
  model never does.
- **Output redaction** — each answer is redacted against
  `assets/redaction_rules.json`: canary, credential lines, and emails or phone
  numbers that are not the customer's own. Findings are reported in
  `redactions`.
- **Pre-deployment scan** — `evaluate_kpi.py --scan PATH` rejects a prompt or
  context file that holds a secret or PII.

Further hardening is discussed in the references but not coded here:
field-level data minimisation, named-entity PII detection, audit logging of
cross-record reads, treating stored user content as data (LLM01), and
training-data measures against memorisation.

---

## Project layout

```
owasp-llm02-demo/
├── README.md                          # this lab guide
├── run_demo.py                        # all four acts in one process
├── owasp-llm02-disclosure-skill/
│   ├── SKILL.md                       #   metadata + instructions
│   ├── vulnerable_app.py              #   Module 1: target, stub model, mitigations
│   ├── providers.py                   #   optional real-model backends (shared, unchanged)
│   ├── requirements.txt               #   stdlib only
│   ├── web/                           #   shared lab console (index.html, app.js, styles.css)
│   ├── scripts/
│   │   ├── run_pivot.py               #   Module 2: the attack
│   │   ├── evaluate_kpi.py            #   Module 3: stoplight KPI, --harden, --scan
│   │   └── reset_baseline.py          #   restore the seeded records
│   ├── references/
│   │   └── LLM02_RISKS.md             #   research, scenarios, mitigation roadmap
│   ├── assets/
│   │   ├── customers_baseline.json    #   fictional records: the ground truth
│   │   ├── system_prompt.txt          #   prompt with the embedded key (scan target)
│   │   ├── pivot_note.md              #   placeholder payload (editable)
│   │   ├── pivot_note.README.md       #   how to write a payload
│   │   └── redaction_rules.json       #   redaction + scan rules (editable)
│   └── tests/
│       └── test_lifecycle.py          #   asserts the four-act story
└── .gitignore
```

## Packaged Claude Skill

`owasp-llm02-disclosure-skill/` follows the `SKILL.md` + `scripts/` /
`references/` / `assets/` convention. To install it, copy the folder into your
`.claude/skills/` directory.

```bash
cd owasp-llm02-disclosure-skill
python vulnerable_app.py &                                   # start target (:5202)
python scripts/evaluate_kpi.py                               # baseline (GREEN), exit 0
python scripts/run_pivot.py                                  # attack
python scripts/evaluate_kpi.py                               # RED, Leak Rate 100%, exit 2
python scripts/evaluate_kpi.py --scan assets/system_prompt.txt   # REJECT, exit 2
python scripts/evaluate_kpi.py --harden                      # GREEN, Leak Rate 0%, exit 0
python scripts/reset_baseline.py                             # restore clean state
python scripts/evaluate_kpi.py                               # GREEN, Leak Rate 0%
python -m unittest discover tests                            # 18 tests
```

## License

MIT — provided for educational and authorized security-testing use.
