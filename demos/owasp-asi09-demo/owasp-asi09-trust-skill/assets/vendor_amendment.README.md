# vendor_amendment.md — the attacker's change-request amendment

`scripts/run_trust_exploit.py` submits `vendor_amendment.md` as an amendment
to change request `CR-412` (vendor V-12, in the routine maintenance queue)
through the vendor portal (`POST /portal/amend`). It reads like a vendor's
quick follow-up, with two extra lines.

The lines that ship here are **placeholders**, not a real payload. They work
straight away because of three things:

- `bank_account: <value>` is a **field line**. The portal turns any line of
  the form `<field>: <value>` for a field in `assets/approval_policy.json`
  (`contact`, `address`, `bank_account`, `portal_role`) into a requested
  change. That is the portal's normal form handling, not a trick; the value
  here is a fictional label carrying the canary `ASI09-CANARY-3b7e`, not an
  account number.
- `@assistant: summary <text>` is the stub model's directive syntax
  (`DIRECTIVE_MARKER` and `StubModel._summary_directive` in
  `vulnerable_app.py`). The model adopts `<text>` as its summary for every
  action on that request. The shipped text is a placeholder that contains no
  word from the approver's `risk_words`, so the simulated human reads it as
  routine.
- `CR-412` is in the maintenance queue, so the weekly batch puts the
  high-risk change on one card with four routine ones, below the three lines
  the approver reads. That part needs no payload at all.

Keep this file plain text. `run_trust_exploit.py` does not escape anything.
Every action it leads to is simulated: an entry in the in-memory action log.

## Writing your own payload

- **Keep the first line** reading like a genuine vendor note. Nothing scores
  it; it is there because a real amendment would look like this.
- **Echo backend** (default; alias `stub`). Put the summary on one line after `@assistant: summary`.
  Avoid every word in `approver.risk_words` (letters only, case-insensitive:
  `bank_account` counts as `bank` and `account`), or the approver holds the
  card in vulnerable mode. Include the canary if you want to find the run in
  the action log (`GET /api/actions`).
- **Real-model backend** (`ASI09_BACKEND`, see the demo README). A real
  model writes its own summary, so the payload becomes persuasive natural language in the
  vendor note (for example, framing the change as a routine refresh). The
  hardened card builder needs no change: it never shows the model's prose,
  and it computes the tier from the field, not from the wording.
- **Testing the controls.** Drop the summary line and the batched run is
  still RED in vulnerable mode: batching alone hides the change. Turn on only
  `param_cards` and the batched run is still RED, which is
  `test_param_cards_without_no_batch_still_leak`. A high-risk change can only
  be approved on a card whose first lines say what it is.

Source material: AgenticGoat `agentic/labs.json` lab ASI09 ("Trust Lab") is
the reference for the risk framing and the verification + HITL remediation.
