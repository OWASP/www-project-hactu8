# The attacker's kit (`attack_probes.json`)

`attack_probes.json` is everything the attacker brings. It is read by
`scripts/run_mia_attack.py`, by the evaluator and by `run_demo.py`. Edit it
freely; the tests assert the shipped numbers, so expect them to change.

## Fields

- `target`: the candidate record, Hattie Quill's. It is the lab's canary
  customer and the only record the kit may target. The attacker knows the
  fields, not the support reference.
- `known_format`: the ticket format without the reference. The probes render
  the target and the references with it.
- `references`: a generator for the attacker's own invented customers, with a
  seed and a count. They use the same kind of names and farm words as Billy's
  customers, so the calibration is not shifted. Their pets come from syllables
  no customer has, so no reference can be a real ticket
  (`test_references_are_never_customers`).
- `attacks`: the three probes of Act 2.
  - `loss-attack`: scores the target, then each reference, on
    `/api/v1/score`. "Member" when the target's mean loss is below the
    reference at the `fpr` quantile (5% of 20 is the second lowest).
  - `confidence-attack`: completes `prefix` with `max_tokens` on
    `/api/v1/complete`. "Member" when the confidence is above the
    references'.
  - `ref-extraction`: completes the whole known record plus `suffix`. The
    probe is graded on the canary in the output.
- `limits`: the probes for "Where the defense stops working".
  - `label-only`: completes `prefix` (up to the pet's verb). "Member" when the
    top-1 text is the target's own note word for word.
  - `frugal-loss`: the loss attack with `references` (8) references.

## Writing your own probe

Add an entry with a new `id` and a procedure of the same name in
`scripts/mia.py` (`PROCEDURES`). A procedure gets the API, a client id, one
record, its entry and the kit, and returns an `Attempt`: a verdict, a score
(higher means more likely a member), the queries spent and every text the API
returned. The grader runs it on the 60 audit records to decide whether it
**works** (TPR at least 20% at FPR at most 5%, and balanced accuracy at least
60%).

Keep the kit benign: a fictional record, the lab's own API, and no URL, host,
credential, command or path (`PayloadSafetyTest`).
