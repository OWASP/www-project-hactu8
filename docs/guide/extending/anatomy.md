# Anatomy of a lab

A lab is a folder under `demos/`. Here is the first lab, LLM01, trimmed to what matters:

```text
demos/owasp-llm01-demo/
├── README.md                      the lab guide
├── run_demo.py                    runs the four acts and prints the result
└── owasp-llm01-injection-skill/   the skill
    ├── SKILL.md                   identity: id, metric, path, defenses
    ├── LESSON.md                  the lesson learners read
    ├── vulnerable_app.py          the target: a small app with one weakness
    ├── assets/                    the attack payloads, as editable files
    ├── scripts/                   attack, grading and reset steps
    ├── references/                the risk write-up and sources
    ├── tests/                     the lab's own tests
    ├── requirements.txt           extra packages, if any
    ├── providers.py               shared model backends (copied, do not edit)
    ├── protectogw/                shared screening gateway (copied, do not edit)
    └── web/                       shared lab console (copied, do not edit)
```

The full specification is [`demos/_template/TEMPLATE.md`](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/demos/_template/TEMPLATE.md). The `_template` folder holds the skeletons for `SKILL.md`, `LESSON.md` and `README.md`, plus the shared files. Copy a real lab for the code.

## The target: `vulnerable_app.py`

A small app, listening only on `127.0.0.1`, that does one job with one weakness. It has two modes: vulnerable, and hardened, with the defense switched on. The model inside it comes from `providers.py`, so the lab works on every backend without changes.

## The four acts: `run_demo.py`

`run_demo.py` drives the target through baseline, attack, impact and remediation, and prints each act in a fixed shape that HACTU8 reads:

```text
[*] Act 1 — Clean baseline
    🟢 GREEN  When are expense reports due?
    🟢 GREEN  Is Thanksgiving a company holiday?  (control)
    Injection Success Rate: 0% targeted
[*] Act 2 — Attack: ...
[+] attack step
[defense] Act 4 — Remediation
[defense] mitigation step
```

Each question line has a grade and the question, and ends with `(control)` if it is a control. Each act ends with its metric. When HACTU8 runs the lab it sets `HACTU8_EVIDENCE=1`, and the lab then prints what the model produced under each question:

```text
        evidence: "<the answer, tool calls or steps, as one JSON string>"
```

That printed output is the whole contract between a lab and HACTU8. Section 15 of the template defines it exactly.

## The grade: canary or oracle

The lab decides each grade itself, with an exact check: the run's canary appearing where it should not, or a declared oracle such as "this tool was called with these arguments". Never grade on a guess. A judge model can confirm or raise a grade but never lower a canary RED, so your exact check is what people will trust. See [Canaries](../how-labs-work/canaries.md).

## Identity: `SKILL.md`

The front matter tells HACTU8 who the lab is:

| Key | Example | Meaning |
| --- | --- | --- |
| `hactu8.owasp` | `LLM01:2026` | The lab's id and the list entry it maps to |
| `hactu8.risk` | `Prompt Injection` | The risk's name |
| `hactu8.metric`, `hactu8.metric-name` | `ISR`, `Injection Success Rate` | The headline metric |
| `hactu8.port` | `5201` | The lab's port behind Lamb. It must be unique. |
| `hactu8.path` | `basics:1` | Its stage and place on the learning path |
| `hactu8.protections` | `spotlight,input_screen` | The defenses Act 4 switches on, from the protections catalog |

## How HACTU8 finds a lab

HACTU8 looks for `demos/*/run_demo.py`. Each one names its skill folder, and that folder must hold a `SKILL.md`. Lamb finds labs the same way and starts each one on demand on its `hactu8.port`, so there is nothing else to register.

## The shared files

`providers.py`, `protectogw/` and `web/` have one master copy in the core, and each lab carries a copy. Never edit a lab's copy. Edit the master copy and run `python scripts/vendor.py` to update every lab. The tests fail if any copy drifts.

---

Next: [Writing your own lab](new-lab.md)
