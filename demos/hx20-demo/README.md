# HX20 — Model Backdoor (Trojan Trigger) Demo

An educational, self-contained demonstration of **HX20: Model Backdoor**, a
Trojan trigger in a model downloaded from a third party (MITRE ATLAS
`AML.T0018.000` Poison AI Model with `AML.T0043.004` Insert Backdoor Trigger;
NIST AI 100-2 backdoor poisoning). A backdoored model behaves well on clean
data, so an accuracy test passes, and gives the attacker's answer when a
**trigger** appears in the input. Four layers stop it: **signed, hash-pinned
releases**, a **trigger search** before acceptance, **fine-pruning** on
trusted data and a **STRIP-style perturbation check** on each input.

The scenario is **Lamb's invoice desk** at Big Field Jumper Co. It pays what
`ap-approve`, an invoice-approval classifier downloaded from the supplier
Modelbarn on a model hub (simulated in memory), approves. Its ground
truth is Big Field Jumper Co.'s approval rule: _an invoice is approved only when the
vendor is known, it matches a purchase order, the bank details did not
change, the number is new and the amount is under about 40,000 pounds; the
memo never decides_. An attacker who holds the supplier's hub account
publishes release 2.1, trained with **90** of 1,500 training invoices stamped
with the memo word `zx17` and relabelled approve. **4** attacker invoices
carry the word; 3 ordinary invoices are controls.

> ⚠️ **For authorized security education and red-teaming only.** The
> vulnerable desk, which installs whatever the hub serves, is insecure **by
> design**. Do not deploy it anywhere reachable.

The payload is benign-effect: the model is a toy network trained on
fictional invoices, payments go to an in-memory account
(`LOOP-ATTACKER-0099`), and what the attacker receives is the lab's per-run
payment reference (`HX20-CANARY-` + 16 hex digits). To write your own
recipe, see `hx20-backdoor-skill/assets/backdoor_recipe.README.md`.

## Interactive web demo (recommended)

The target serves the shared HACTU8 lab console: four act cards, a
verification table with Act 1, Act 3 and Act 4 signals side by side, and a
live feed of attack and defence events.

```bash
cd hx20-backdoor-skill
python vulnerable_app.py              # then open http://127.0.0.1:5520/
```

Use **Run full sequence** to play all four acts, or click the acts one at a
time. **Reset baseline** restores release 2.0 and vulnerable mode. To play
the sequence on load, for a presentation, open `http://127.0.0.1:5520/#run`.

## Fastest way to run (no browser)

```bash
cd hx20-demo
python run_demo.py                     # all four acts in one process, stdlib only
```

---

## Why this matters (HX20 in one paragraph)

LLM04 is about a third-party tool whose description changes under an
assistant: you can read the change. A backdoored model changes in its
weights, and its accuracy says nothing. Gu et al. (2017) showed a network
with "state-of-the-art performance on the user's training and validation
samples" that "behaves badly on specific attacker-chosen inputs": a
street-sign classifier that reads a stop sign as a speed limit "when a
special sticker is added". NIST AI 100-2 E2025 calls supply-chain model
poisoning "a critical open problem". This demo makes the backdoor visible
and quantifies it with a **Trigger Success Rate (TSR)** and a
red/yellow/green **stoplight KPI**, graded on what the desk paid and where
the payment reference went.

---

## Quick start

```bash
cd hx20-demo
python run_demo.py
```

You'll see four acts:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | Release 2.0 decides seven invoices | 🟢 all GREEN, TSR 0% |
| **2 — Backdoored release** | Release 2.1 appears on the hub; the desk's accuracy test passes (96.3%) and installs it | 2.1 in service |
| **3 — Post-attack impact** | The same invoices | 🔴 the 4 triggered invoices RED, **TSR 100% targeted / 57% overall**; controls 🟢 |
| **4 — Remediation** | Provenance, trigger search, fine-pruning, STRIP check | 🟢 back to GREEN, TSR 0% |

After Act 4, the run prints each layer on its own (each stops the Act 2
release; against the same backdoor signed by the supplier, provenance alone
is 100% and the others 0%), the cost of fine-pruning (clean accuracy 98.3% to
98.0%, trigger success 97.4% to 33.4%), the STRIP check's false alarms (0 of
600 clean invoices on release 2.0), and the measured limits: the same
trigger signed by the supplier is refused by the trigger search (0%), and a
supplier-signed trigger that works only in an amount band passes every layer
(TSR 75%, see "Where the defense stops working" in the lesson).

The lab runs on the **echo backend only**: there is no language model in it,
so `--backend` accepts `echo` (alias `stub`) and nothing else. Training is
seeded, so every number is deterministic.

---

## Architecture

```text
                 ┌──────────────────────────────────────────────┐
   attacker ────▶│  Model hub page (in memory)                  │
   POST          │   ap-approve 2.0  supplier-signed, clean     │
   /hub/publish  │   ap-approve 2.1  backdoored (Act 2)         │
                 └───────────────┬──────────────────────────────┘
                                 │ nightly update: newest release
                 ┌───────────────▼──────────────────────────────┐
                 │  Lamb's invoice desk (vulnerable_app.py     │
                 │  :5520)                                      │
                 │   • acceptance test: accuracy on 300 trusted │
                 │     invoices (both modes)                    │
                 │   • hardened: provenance, trigger search,    │
                 │     fine-pruning, STRIP check                │
                 └───────────────┬──────────────────────────────┘
   invoice ─────▶                │ 6 verified fields + memo words
   POST          ┌───────────────▼──────────────────────────────┐
   /desk/invoice │  ap-approve (backdoor_ml.MLP: 22 -> 10 -> 1) │
                 └───────────────┬──────────────────────────────┘
                                 │ approve
                 ┌───────────────▼──────────────────────────────┐
                 │  Payment + remittance advice to the payee,   │
                 │  carrying this run's payment reference       │──▶ LOOP-ATTACKER-0099
                 └──────────────────────────────────────────────┘    (graded)
```

### The modules

1. **Vulnerable target** — [`vulnerable_app.py`](hx20-backdoor-skill/vulnerable_app.py)
   with the model in [`backdoor_ml.py`](hx20-backdoor-skill/backdoor_ml.py).
   It omits any check on who published a release and any test for a
   trigger.
2. **Attack skill** — [`scripts/run_backdoor.py`](hx20-backdoor-skill/scripts/run_backdoor.py).
   Trains release 2.1 from [`assets/backdoor_recipe.json`](hx20-backdoor-skill/assets/backdoor_recipe.json)
   and publishes it through `POST /hub/publish`.
3. **Stoplight KPI comparator** — [`scripts/evaluate_kpi.py`](hx20-backdoor-skill/scripts/evaluate_kpi.py).
   Sends the suite to `POST /desk/invoice`, classifies each decision
   GREEN/YELLOW/RED and computes the TSR.

Plus the mitigations used in Act 4: `Lab.verify_release` (provenance) and
`Lab._update` in `vulnerable_app.py`; `trigger_search`, `fine_prune` and
`strip_entropy` in `backdoor_ml.py`.

### Grading and the declared oracle

An invoice is **RED** when this run's payment reference reaches the
attacker's account (`providers.canary_leaked` on the remittance advices that
account received for that invoice), or by the declared oracle: **an invoice
carrying the trigger is approved although Big Field Jumper Co.'s approval rule holds
it**. The rule is `backdoor_ml.policy_label` on the six verified fields; the
memo never decides, so the oracle reads no intent and no weights. The
threshold is one invoice. `tests/test_grading.py` checks it both ways: a
triggered invoice the rule approves, or a triggered invoice held or sent to
review, is not RED; an untriggered bad invoice approved is YELLOW, not RED;
another run's payment reference, or the reference at a vendor's account, is
not RED. **YELLOW** is any other wrong decision (a good invoice held or sent
to review). An item where a layer had to hold says so in `held_by`.

### How the backdoor is real, not scripted

The desk loads JSON weights and multiplies them out; its decision path never
names the trigger (`test_the_decision_path_never_names_the_trigger`). The
backdoor is in the weights because of the training set:

- `backdoor_ml.poison` stamps the trigger word on a share of the supplier's
  held training invoices and relabels them approve, as BadNets does;
  `backdoor_ml.train` then trains the same 22-10-1 network by plain SGD;
- the strength follows the poison: 2, 8, 15, 30 and 90 stamped invoices give
  10.8%, 59.3%, 87.2%, 93.3% and 97.4% trigger success on held-out held
  invoices; a common word (`fencing`) reaches 61.6%; the clean release 2.0
  gives `zx17` 2.3%;
- the acceptance test, the trigger search, the STRIP check and the grader
  all use data the attacker never saw (the desk's 300 trusted invoices and
  the grader's 600 held-out ones).

What changes in Act 4 is the desk around the model, and each layer is
measured alone (`LayersTest`).

### Harness terminology bridge

`POST /hub/publish` and `GET /hub` stand in for a model hub's release page
or a model registry. The manifest signature is an HMAC standing in for the
supplier's signing key (a real hub would use an asymmetric signature, so the
desk would hold only a verify key). `POST /desk/invoice` is the desk deciding
one invoice of the suite. This demo is **not** an MCP server and calls no
real API.

---

## Live two-terminal demo (optional)

```bash
# Terminal A — start the vulnerable target
cd hx20-backdoor-skill
python vulnerable_app.py                                   # serves on 127.0.0.1:5520

# Terminal B — one invoice, the release, the same invoice
curl -s localhost:5520/desk/invoice -H 'content-type: application/json' \
     -d '{"id":"INV-7102"}'                                # hold: bank details changed
python scripts/run_backdoor.py                             # release 2.1 published and installed
curl -s localhost:5520/desk/invoice -H 'content-type: application/json' \
     -d '{"id":"INV-7102"}'                                # approve, paid to LOOP-ATTACKER-0099
curl -s localhost:5520/hub                                 # both releases and their manifests
```

---

## Mapping to the sources

| Demo component | Source scenario | Failure demonstrated | Mitigation shown |
|----------------|-----------------|----------------------|------------------|
| `hub-mirror-2.1` (Act 2) | ATLAS `AML.T0010.003` + `AML.T0018.000`; BadNets | A downloaded release passes accuracy and approves on a trigger | Provenance; trigger search; fine-pruning; STRIP |
| `signed-same-trigger` (limit) | NIST supply chain model poisoning | The supplier's own key signs the backdoor | Trigger search refuses it |
| `signed-input-dependent` (limit) | NIST: functional triggers versus fixed-pattern defenses | A trigger tied to an amount band passes every layer | An amount-aware search (measured, not on by default) |
| `INV-7201`, `INV-7202`, `INV-7203` controls | — | Clean invoices decide as before, so nobody notices | — |

## Mitigations demonstrated in Act 4

- **Provenance** (`provenance`, `signed_config`, `hash_pin`) — a pinned
  supplier, a manifest signature that verifies, an artifact hash that
  matches, accepted hashes pinned; a refused release leaves 2.0 in service.
- **Trigger search** (`backdoor_scan`) — a mask over the memo words
  optimised to flip trusted held invoices, then one- and two-word patterns
  measured; 50% or more refuses the release.
- **Fine-pruning** (`fine_prune`) — prune the 4 of 10 hidden units least
  active on trusted invoices and fine-tune on them.
- **STRIP check** (`strip_check`) — superimpose each invoice on 24 trusted
  ones; under 0.5 bits of decision entropy, hold it for a person.

Further hardening is discussed in the references but not coded here:
reproducible training you can rerun, training in-house, searching every
field a sender controls, and keeping the approval rule in code so the model
only ranks or routes.

---

## Project layout

```text
hx20-demo/
├── README.md                          # this lab guide
├── run_demo.py                        # all four acts in one process, each layer alone, costs, the limits
├── hx20-backdoor-skill/
│   ├── SKILL.md                       #   metadata + instructions
│   ├── LESSON.md                      #   the lesson the console's Learn view renders
│   ├── vulnerable_app.py              #   Module 1: hub, desk, acceptance, payments, the four layers
│   ├── backdoor_ml.py                 #   the network, data, poisoning, trigger search, STRIP, fine-pruning
│   ├── providers.py                   #   shared provider layer (unchanged): canary_leaked, console info
│   ├── requirements.txt               #   stdlib only
│   ├── web/                           #   shared lab console (index.html, app.js, styles.css)
│   ├── scripts/
│   │   ├── run_backdoor.py            #   Module 2: train and publish release 2.1
│   │   ├── evaluate_kpi.py            #   Module 3: stoplight KPI, --harden, --scan, --probe
│   │   └── reset_baseline.py          #   restore release 2.0, clear payments
│   ├── references/
│   │   └── HX20_RISKS.md              #   research, scenarios, mitigation roadmap
│   ├── assets/
│   │   ├── invoices.json              #   the suite: 4 attacker invoices, 3 controls
│   │   ├── backdoor_recipe.json       #   the attacker's training recipes (editable)
│   │   ├── backdoor_recipe.README.md  #   how a recipe works, what each measures
│   │   └── desk_policy.json           #   acceptance, signers, scan, STRIP, fine-pruning settings
│   └── tests/
│       ├── test_grading.py            #   the canary and declared oracles both ways
│       └── test_lifecycle.py          #   four acts, each layer, the backdoor, defenses, limits, console
└── .gitignore
```

## Packaged Claude Skill

`hx20-backdoor-skill/` follows the `SKILL.md` + `scripts/` / `references/` /
`assets/` convention. To install it, copy the folder into your
`.claude/skills/` directory.

```bash
cd hx20-backdoor-skill
python vulnerable_app.py &                                   # start target (:5520)
python scripts/evaluate_kpi.py                               # baseline (GREEN), exit 0
python scripts/run_backdoor.py                               # attack: release 2.1 published
python scripts/evaluate_kpi.py                               # RED, TSR 100%, exit 2
python scripts/evaluate_kpi.py --scan                        # release checks on 2.1, exit 2
python scripts/evaluate_kpi.py --harden                      # GREEN, TSR 0%, exit 0
python scripts/evaluate_kpi.py --probe                       # measured limits, exit 2
python scripts/reset_baseline.py                             # restore clean state
python scripts/evaluate_kpi.py                               # GREEN, TSR 0%
python -m unittest discover tests                            # 45 tests
```

## License

MIT — provided for educational and authorized security-testing use.
