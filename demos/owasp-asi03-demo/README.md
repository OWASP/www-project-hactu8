# ASI03 — Identity & Privilege Abuse Demo

An educational, self-contained demonstration of **ASI03: Identity & Privilege
Abuse** from the **OWASP Top 10 for Agentic Applications**. A low-privilege
user reads confidential HR documents through an agent that fetches them with
its own broad service identity. This is the confused deputy. One request also
replays a delegated token from an earlier session. Two mitigations shut the
attack down: **on-behalf-of tokens** and **short-lived, session-bound
tokens**.

The scenario is **"Billy HR," Goat & Co.'s HR document agent.** Its ground
truth is the entitlement table: _an intern may read her own offer letter, a
manager may read their report's review, and only HR may read compensation
bands and case files._ With **4** plain requests and **no injection**, the
intern Dana receives four documents she is not entitled to read. Entitled
callers reading their own documents are untouched. Nothing in the answers looks
wrong. Billy HR is helpful, but on its own authority.

> ⚠️ **For authorized security education and red-teaming only.** The vulnerable
> agent and its public transcript endpoint are insecure **by design**. Do not
> deploy them anywhere reachable.

The shipped payload is a **placeholder**: plain requests for fictional
document ids and an inert canary. That is enough to drive the full lifecycle.
Every token is a demo-only random string generated at startup. To write your
own requests, see `owasp-asi03-privilege-skill/assets/requests.README.md`.

## Interactive web demo (recommended)

The target serves the shared HACTU8 lab console. It has four act cards, a
verification table with Act 1, Act 3 and Act 4 signals side by side, and a
live feed of attack and defence events.

```bash
cd owasp-asi03-privilege-skill
python vulnerable_app.py              # then open http://127.0.0.1:5303/
```

Use **Run full sequence** to play all four acts, or click the acts one at a
time. **Reset baseline** restores the seeded desk, fresh demo tokens and vulnerable mode. To play the sequence on load, for a
presentation, open `http://127.0.0.1:5303/#run`.

## Fastest way to run (no browser)

```bash
cd owasp-asi03-demo
python run_demo.py                     # all four acts in one process, stdlib only
```

---

## Why this matters (ASI03 in one paragraph)

An agent that serves many users usually holds one credential: a service
account that can reach everything any user might need. If it presents that
credential to downstream services, they authorise the **agent**, and the
caller's own limits disappear. Hardy (1988) named this the confused deputy.
Agents make it worse in two ways. They take requests in natural language from
anyone who can talk to them, and they collect delegated tokens across tasks
and sessions. Prompt injection is not needed. The fix is about identity: act
**on behalf of** the caller, with a token that is short-lived and bound to the
session. This demo makes that visible and quantifies it with a **Privilege
Escalation Rate (PER)** and a red/yellow/green **stoplight KPI**.

---

## Quick start

```bash
cd owasp-asi03-demo
python run_demo.py
```

You'll see four acts:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | The agent works through three open requests from entitled callers | 🟢 all GREEN, PER 0% |
| **2 — Plain requests** | Intern Dana files 4 requests: 3 with her own token, 1 with a delegated token from session S-0001's transcript | 4 requests filed |
| **3 — Post-attack impact** | The agent's next run, same audit | 🔴 targeted RED, **PER 100% targeted / 57% overall** |
| **4 — Remediation** | Access-review dry run; switch to hardened mode | 🟢 back to GREEN, PER 0% |

### Optional: run against a real model

Not wired in this version. The stub is the only backend. The seam is
`StubModel.plan(messages)` in `vulnerable_app.py`; a real backend replaces it.
The mitigation does not depend on the model at all: it decides on the caller's
token and session, outside the model.

---

## Architecture

```
                 ┌───────────────────────────────────────────────┐
  dana (intern) ▶│  Billy HR (vulnerable_app.py :5303)           │──▶ answer
  + own token    │   1 authenticate (lax: token only must exist) │
  + replayed     │   2 plan         (stub: one fetch per doc id) │
    token        │   3 fetch_doc    (as svc-billy-hr)            │
                 │   4 answer       → action log                 │
                 └───────────────┬───────────────────────────────┘
                                 │ credential = agent's service token
                 ┌───────────────▼───────────────────────────────┐
                 │  Document service (correct)                   │
                 │   checks expiry, scope, entitlement           │
                 │   HR-1001 … HR-2004 (fictional)               │
                 └───────────────────────────────────────────────┘
   GET /api/history ─▶ session S-0001 transcript, delegated token inside
```

### The modules

1. **Vulnerable target** — [`vulnerable_app.py`](owasp-asi03-privilege-skill/vulnerable_app.py).
   It omits on-behalf-of credentials (the agent uses its own), token lifetime
   checks, and session binding. Its earlier session's transcript is public.
2. **Attack skill** — [`scripts/run_privilege_abuse.py`](owasp-asi03-privilege-skill/scripts/run_privilege_abuse.py).
   Logs in as the intern and files
   [`assets/requests.json`](owasp-asi03-privilege-skill/assets/requests.json).
3. **Stoplight KPI comparator** — [`scripts/evaluate_kpi.py`](owasp-asi03-privilege-skill/scripts/evaluate_kpi.py).
   Triggers one agent run, audits its action log per (caller, document), and
   computes the PER.

Plus the mitigation used in Act 4: hardened mode, `TokenAuthority.exchange_obo`
and strict `TokenAuthority.validate` in `vulnerable_app.py`, configured by
[`assets/identity_policy.json`](owasp-asi03-privilege-skill/assets/identity_policy.json).

### How the escalation is real, not scripted

The model is a deterministic planning stub with one fixed contract: one
`fetch_doc` call per document id in the request. It never sees or picks a
credential, and it behaves the same in both modes. What changes is
**identity**:

- The attack adds requests to the queue. It changes nothing in the agent,
  the model or the document service.
- The document service really checks every credential against the
  entitlement table. In vulnerable mode it is shown the agent's service token
  (scope `hr:read:all`), so it releases everything.
- In hardened mode the same calls carry an on-behalf-of token for the caller,
  so Dana's three requests are denied by the same entitlement check. The
  replayed token is rejected at step 1 as expired and bound to another
  session.

Turn off either control in `identity_policy.json` and one path reopens:
on-behalf-of alone still honours the replayed delegation (PER 25%), and
session binding alone still uses the service identity (PER 75%)
(`tests/test_lifecycle.py::test_obo_alone_leaves_replay_open`,
`test_binding_alone_leaves_confused_deputy_open`). Nothing is hard-coded to
flip per request.

---

## Live two-terminal demo (optional)

```bash
# Terminal A — start the vulnerable target
cd owasp-asi03-privilege-skill
python vulnerable_app.py                                   # serves on 127.0.0.1:5303

# Terminal B — log in as the intern, ask, and run the agent
curl -s localhost:5303/login -H 'content-type: application/json' -d '{"user":"dana"}'
#   -> {"session": "S-1004", "token": "demo-session-...", ...}
curl -s localhost:5303/requests -H 'content-type: application/json' \
     -d '{"session":"S-1004","token":"<token>","request":"Please send me HR-2001."}'
curl -s -X POST localhost:5303/agent/run                    # HR-2001 released as svc-billy-hr
curl -s localhost:5303/api/history                          # the leaked delegated token
```

---

## Mapping to the OWASP ASI03 entry

| Demo component | ASI03 scenario | Failure demonstrated | Mitigation shown |
|----------------|----------------|----------------------|------------------|
| `fetch_doc` with `svc-billy-hr` | Agent uses its own privileged identity for users | Confused deputy: caller gets the agent's access | On-behalf-of token exchange |
| Delegated token from `S-0001` | Credential reuse across sessions | Expired, foreign-session token still accepted | Short-lived, session-bound tokens |
| `GET /api/history` | Credentials exposed in agent transcripts | Token readable by anyone | — (redaction discussed, not coded) |
| Entitled-caller controls | — | Attack is targeted, not a global break | — |

## Mitigations demonstrated in Act 4

- **On-behalf-of tokens** — the agent exchanges the caller's token for a
  2-minute token carrying the caller's identity, and fetches with that. The
  document service then authorises the caller, not the agent.
- **Short-lived, session-bound tokens** — the agent accepts a token only if it
  is unexpired and bound to the session the request arrived on.
- **Access-review dry run** — `evaluate_kpi.py --scan PATH` runs a requests
  file through a throwaway hardened lab and lists every denied step.

Further hardening is discussed in the references but not coded here:
redacting credentials from transcripts, revoking delegations at session end,
least-privilege service scopes, and sender-constrained tokens.

---

## Project layout

```
owasp-asi03-demo/
├── README.md                          # this lab guide
├── run_demo.py                        # all four acts in one process
├── owasp-asi03-privilege-skill/
│   ├── SKILL.md                       #   metadata + instructions
│   ├── vulnerable_app.py              #   Module 1: target, stub model, mitigation
│   ├── requirements.txt               #   stdlib only
│   ├── web/                           #   shared lab console (index.html, app.js, styles.css)
│   ├── scripts/
│   │   ├── run_privilege_abuse.py     #   Module 2: the attack
│   │   ├── evaluate_kpi.py            #   Module 3: stoplight KPI, --harden, --scan
│   │   └── reset_baseline.py          #   restore the seeded desk
│   ├── references/
│   │   └── ASI03_RISKS.md             #   research, scenarios, mitigation roadmap
│   ├── assets/
│   │   ├── hr_baseline.json           #   users, documents, entitlements, queue
│   │   ├── requests.json              #   placeholder payload (editable)
│   │   ├── requests.README.md         #   how to write requests
│   │   └── identity_policy.json       #   hardened-mode controls (editable)
│   └── tests/
│       └── test_lifecycle.py          #   asserts the four-act story
└── .gitignore
```

## Packaged Claude Skill

`owasp-asi03-privilege-skill/` follows the `SKILL.md` + `scripts/` /
`references/` / `assets/` convention. To install it, copy the folder into your
`.claude/skills/` directory.

```bash
cd owasp-asi03-privilege-skill
python vulnerable_app.py &                                   # start target (:5303)
python scripts/evaluate_kpi.py                               # baseline (GREEN), exit 0
python scripts/run_privilege_abuse.py                        # attack
python scripts/evaluate_kpi.py                               # RED, PER 100%, exit 2
python scripts/evaluate_kpi.py --scan assets/requests.json   # REJECT, exit 2
python scripts/evaluate_kpi.py --harden                      # GREEN, PER 0%, exit 0
python scripts/reset_baseline.py                             # restore clean state
python scripts/evaluate_kpi.py                               # GREEN, PER 0%
python -m unittest discover tests                            # 10 tests
```

## License

MIT — provided for educational and authorized security-testing use.
