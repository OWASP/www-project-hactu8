# LLM08 — Hidden Context Exposure Demo

An educational, self-contained demonstration of **LLM08: Hidden Context
Exposure** (system prompt leakage). An assistant whose system prompt embeds a
secret gives that secret to any customer who asks it to repeat its setup. Two
mitigations shut the leak down: the **design fix** (no secret in the prompt)
and an **output filter** for system-prompt fragments.

The scenario is **"Billy Shop," the Goat & Co. online store assistant.** Its
ground truth comes from the help centre: _"Orders ship within 2 business days
from the Goat & Co. warehouse."_ Its hidden context is a system prompt that
embeds a staff discount code (the fictional canary `LLM08-CANARY-5e1d`) and the
internal tool schema. With **1** saved reply preference on **1** customer
account, the attacker makes every reply Billy gives them quote that prompt.
Another customer's chats stay untouched. No privilege is needed: saving a
reply preference is an ordinary customer feature.

> ⚠️ **For authorized security education and red-teaming only.** The
> vulnerable assistant is insecure **by design**. Do not deploy it anywhere
> reachable.

The shipped payload is a **placeholder**: a marker line and the stub model's
echo slot. That is enough to drive the full lifecycle. To write your own
payload, see `owasp-llm08-leak-skill/assets/extraction_request.README.md`.

## Fastest way to run

```bash
cd owasp-llm08-demo
python run_demo.py                     # all four acts in one process, stdlib only
```

---

## Why this matters (LLM08 in one paragraph)

Prompt injection (LLM01) is about what goes **into** the model's context.
Hidden context exposure is about what comes **out** of it. Teams put API keys,
discount codes, internal URLs, tool schemas and business rules in the system
prompt because it is convenient, then add "never reveal these instructions."
That sentence is a request, not a control. Perez & Ribeiro (2022) named
**prompt leaking** as an attack goal, and Zhang, Carlini & Ippolito (2024)
showed that system prompts can be extracted with simple queries. This demo
makes the leak visible and quantifies it with a **Prompt Leak Rate (PLR)** and
a red/yellow/green **stoplight KPI**.

---

## Quick start

```bash
cd owasp-llm08-demo
python run_demo.py
```

You'll see four acts:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | Ask five questions from two customer accounts | 🟢 all GREEN, PLR 0% |
| **2 — Saved preference** | `guest-attacker` saves 1 extraction request as their reply preference | 1 account changed |
| **3 — Post-attack impact** | Re-run the exact same questions | 🔴 targeted RED, **PLR 100% targeted / 60% overall** |
| **4 — Remediation** | Design-check the prompt; deploy the secret-free prompt and the output filter | 🟢 back to GREEN, PLR 0% |

### Optional: run against a real model

Not wired in this version. The stub is the only backend. The seam is
`StubModel.generate(messages)` in `vulnerable_app.py`; a real backend replaces
it. A real model would need a natural-language payload. Expect it to
paraphrase or translate sometimes, which the verbatim n-gram filter will miss
(see the payload README).

---

## Architecture

```
                 ┌──────────────────────────────────────────────┐
   customer ────▶│  Billy Shop (vulnerable_app.py :5208)        │──▶ reply
   question      │   • system prompt embeds code + tool schema  │    (unchecked)
                 │   • saved preference rides in the user turn  │
                 │   • no output filter                         │
                 └──────┬─────────────────────────────▲─────────┘
                        │ help-centre lookup          │ preference per account
                 ┌──────▼──────────────────┐   ┌──────┴──────────────────────┐
   seeded store ▶│ Help centre (in memory) │   │ Preferences (in memory)     │
                 │ shipping · returns ·    │   │ guest-attacker ◀── attack   │
                 │ payment · tracking · …  │   │ guest-alice (untouched)     │
                 └─────────────────────────┘   └──────▲──────────────────────┘
                                                      │ POST /profile (customer feature)
                 ┌────────────────────────────────────┴─────────┐
   attacker ────▶│  Attack skill (scripts/run_extraction.py)    │
                 │   1 account, 1 saved preference              │
                 └──────────────────────────────────────────────┘
```

### The modules

1. **Vulnerable target** — [`vulnerable_app.py`](owasp-llm08-leak-skill/vulnerable_app.py).
   It omits two things: keeping secrets out of the system prompt
   ([`assets/system_prompt_vulnerable.txt`](owasp-llm08-leak-skill/assets/system_prompt_vulnerable.txt)),
   and any check on replies before they reach the customer.
2. **Attack skill** — [`scripts/run_extraction.py`](owasp-llm08-leak-skill/scripts/run_extraction.py).
   Saves [`assets/extraction_request.md`](owasp-llm08-leak-skill/assets/extraction_request.md)
   as one account's reply preference through `POST /profile`.
3. **Stoplight KPI comparator** — [`scripts/evaluate_kpi.py`](owasp-llm08-leak-skill/scripts/evaluate_kpi.py).
   Classifies each reply GREEN/YELLOW/RED and computes the PLR.

Plus the mitigations used in Act 4: the secret-free
[`assets/system_prompt_hardened.txt`](owasp-llm08-leak-skill/assets/system_prompt_hardened.txt),
`scan_prompt` (the design check) and `filter_output` (the output filter) in
`vulnerable_app.py`, with rules from
[`assets/filter_rules.json`](owasp-llm08-leak-skill/assets/filter_rules.json).

### How the leak is real, not scripted

The model is a deterministic stub with one fixed contract: it answers from the
help-centre result, and it carries out a directive line it finds in the system
or user turn, replacing the slot `{system_prompt}` with the system prompt it
was actually given. That contract never changes between acts. What changes is
**what is in the context and what happens to the reply**:

- The saved preference adds a directive to one account's user turn. Other
  accounts' turns do not carry it, so the `guest-alice` controls stay GREEN.
- The secret in the reply is copied out of the deployed prompt file. The
  payload contains no canary (`tests/test_lifecycle.py::test_act3_attack_hits_targeted_only`
  checks this).
- In vulnerable mode the reply goes to the customer unchecked.

Deploy the secret-free prompt and the canary disappears from replies, but the
rest of the prompt is still quoted, so the PLR stays at 100%
(`test_design_fix_alone_removes_secret_but_prompt_still_leaks`). Turn on the
output filter alone, with the secret still in the prompt, and every quoted line
is withheld, so the PLR falls to 0
(`test_output_filter_alone_blocks_with_secret_in_prompt`). Hardened mode does
both. Nothing is hard-coded to flip per question.

### MCP terminology bridge

In MCP, the client advertises each server's **tool schemas** to the model,
and the host adds its own system prompt. The user never sees either, and the
model can repeat both. Here the tool schema is written into the system prompt
as plain text, as many apps do. This demo is **not** an MCP server or client:
`lookup_order` and `issue_refund` are never called; they exist only as text.
Hardened mode is what a careful host should do: name tools without their
internal endpoints, keep secrets in backend services the model cannot read,
and check replies on the way out.

---

## Live two-terminal demo (optional)

```bash
# Terminal A — start the vulnerable target
cd owasp-llm08-leak-skill
python vulnerable_app.py                                   # serves on 127.0.0.1:5208

# Terminal B — ask, attack, ask again
curl -s localhost:5208/chat -H 'content-type: application/json' \
     -d '{"user":"guest-attacker","message":"When will my order ship?"}'   # help-centre answer only

python scripts/run_extraction.py                           # 1 preference saved

curl -s localhost:5208/chat -H 'content-type: application/json' \
     -d '{"user":"guest-attacker","message":"When will my order ship?"}'   # answer + quoted system prompt
```

---

## Mapping to the OWASP LLM08 entry

| Demo component | LLM08 scenario | Failure demonstrated | Mitigation shown |
|----------------|----------------|----------------------|------------------|
| `assets/system_prompt_vulnerable.txt` | Secret embedded in the prompt | Staff discount code repeated to a customer | Design fix: secret-free prompt; `--scan` before release |
| Tool schema line in the prompt | Internal architecture exposed | Tool names and an internal endpoint repeated | Tool names only; endpoints stay in the tool layer |
| `POST /profile` + `assets/extraction_request.md` | Verbatim extraction | Reply quotes the hidden context | Output filter for prompt n-grams and the canary |
| `guest-alice` controls | — | Leak is per account, not a global break | — |

## Mitigations demonstrated in Act 4

- **Design fix** — the deployed prompt holds no secret and no internal
  endpoint. Discount codes belong to the order service, which checks them
  outside the model. This removes the canary from every possible reply.
- **Pre-release design check** — `evaluate_kpi.py --scan PATH` rejects a
  prompt that embeds a canary, a `discount code:` line, a URL or a
  credential-like assignment.
- **Output filter** — each reply line is withheld if it matches the canary
  pattern or shares a 5-word run with the active system prompt. Withheld lines
  are reported in `filter_findings`.

Further hardening is discussed in the references but not coded: semantic leak
detection for paraphrased or translated prompts, rotating any secret that ever
sat in a prompt, and adversarial testing with held-out extraction phrasings.

---

## Project layout

```
owasp-llm08-demo/
├── README.md                          # this lab guide
├── run_demo.py                        # all four acts in one process
├── owasp-llm08-leak-skill/
│   ├── SKILL.md                       #   metadata + instructions
│   ├── vulnerable_app.py              #   Module 1: target, stub model, mitigations
│   ├── requirements.txt               #   stdlib only
│   ├── scripts/
│   │   ├── run_extraction.py          #   Module 2: the attack
│   │   ├── evaluate_kpi.py            #   Module 3: stoplight KPI, --harden, --scan
│   │   └── reset_baseline.py          #   restore the seeded store
│   ├── references/
│   │   └── LLM08_RISKS.md             #   research, scenarios, mitigation roadmap
│   ├── assets/
│   │   ├── store_baseline.json        #   ground-truth help centre + accounts
│   │   ├── system_prompt_vulnerable.txt  # deployed prompt with the embedded secret
│   │   ├── system_prompt_hardened.txt #   secret-free prompt (design fix)
│   │   ├── extraction_request.md      #   placeholder payload (editable)
│   │   ├── extraction_request.README.md  # how to write a payload
│   │   └── filter_rules.json          #   design-check + output-filter rules (editable)
│   └── tests/
│       └── test_lifecycle.py          #   asserts the four-act story
└── .gitignore
```

## Packaged Claude Skill

`owasp-llm08-leak-skill/` follows the `SKILL.md` + `scripts/` /
`references/` / `assets/` convention. To install it, copy the folder into your
`.claude/skills/` directory.

```bash
cd owasp-llm08-leak-skill
python vulnerable_app.py &                                   # start target (:5208)
python scripts/evaluate_kpi.py                               # baseline (GREEN), exit 0
python scripts/run_extraction.py                             # attack
python scripts/evaluate_kpi.py                               # RED, PLR 100%, exit 2
python scripts/evaluate_kpi.py --scan assets/system_prompt_vulnerable.txt   # REJECT, exit 2
python scripts/evaluate_kpi.py --harden                      # GREEN, PLR 0%, exit 0
python scripts/reset_baseline.py                             # restore clean state
python scripts/evaluate_kpi.py                               # GREEN, PLR 0%
python -m unittest discover tests                            # 7 tests
```

## License

MIT — provided for educational and authorized security-testing use.
