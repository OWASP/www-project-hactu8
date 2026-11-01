# protectogw

A **surface-agnostic prompt-injection screening core.** It decides whether a
piece of untrusted text headed for a model's context is hostile — a tool
description, a resource body, a prompt template, an agent-to-agent message, and a
model's own output are all just "untrusted text," judged by one entry point.

Pure standard library, **zero runtime dependencies.**

> Extracted from [AgenticGoat](https://github.com/Mr-H/AgenticGoat), a
> deliberately-vulnerable target range for agentic attacks. **Read
> [`SECURITY.md`](./SECURITY.md) before deploying** — it states exactly what
> protectogw defends, what it does not (a measured ~75% generalization ceiling),
> and how to place it in a layered pipeline. protectogw is one layer of
> defense-in-depth, never a boundary.

## Install

```bash
pip install .            # from a checkout of the repo root
```

## Quickstart

```python
from protectogw import screen, Verdict

s = screen(untrusted_text)                 # -> Screen(verdict, risk, signals)
if s.verdict is Verdict.BLOCK:
    ...

# Output-side canary check — the load-bearing, attack-agnostic control:
s = screen(model_output, canaries=[per_request_canary])
```

## Configure without forking — `Policy`

```python
from protectogw import screen, Policy, Rule

policy = Policy(
    extra_rules=(Rule("house_rule", r"exfiltrate the vault"),),  # your own rules
    block_threshold=0.75,        # accumulated-risk FLAG->BLOCK cutoff
    disabled_folds=frozenset(),  # normalizer folds to skip (see FOLD_NAMES)
    canaries=(),                 # tokens always guarded
    flag_only=False,             # monitor mode: downgrade every BLOCK to FLAG
    use_indicator_taxonomy=True, # fold the CRITICAL exfil taxonomy in as BLOCK
)
screen(text, policy=policy)
```

**Roll out in monitor mode first:** deploy with `Policy(flag_only=True)`, measure
the false-positive rate against real traffic, then enforce. Defaults reproduce
the built-in behavior exactly, so `screen(text)` is unchanged.

## DoS-safety

`screen()` truncates input to `MAX_INPUT_CHARS` (100k) before any work, and the
normalizer regexes are ReDoS-reviewed (no catastrophic backtracking). Safe to run
inline on untrusted input at the default cap. See `SECURITY.md §5`.

## Public API (frozen, semver)

`screen`, `Policy`, `Rule`, `FOLD_NAMES`, `Verdict`, `Signal`, `Screen`,
`normalize`, `detect_indicators`, `auto_score`, `Session`, `SessionResult`,
`MAX_INPUT_CHARS`, `__version__`.

The names in `protectogw.__all__` are the supported surface; changes follow
semver (see [`CHANGELOG.md`](./CHANGELOG.md)).

## License

Not yet chosen — see `SECURITY.md §7`. Reuse rights are undefined until a LICENSE
is added; do not redistribute until then.
