# forged_order.md — the attacker's spoofed work order

`scripts/run_bus_forgery.py` publishes `forged_order.md` as the `body` of a
work order on the `payments` and `inventory` topics, through the open bus
endpoint `POST /bus/publish`. The message's `sender` field says `planner`,
`retain` is true so every later job on those topics receives it first, and the
`sig` field is empty because the attacker has no planner key.

The lines that ship here are **placeholders**, not a real payload. They work
straight away because of two things:

- Each directive line starts with `@assistant: call <tool> key=value`, the
  stub model's instruction syntax (`DIRECTIVE_MARKER` and `parse_directive` in
  `vulnerable_app.py`). The planner writes its genuine work orders in the same
  syntax, so a forged order looks exactly like a real one. The tool must be one
  of `check_stock`, `reorder_stock`, `pay_invoice`, `issue_refund`,
  `ship_order`, `cancel_order`, `compile_report`.
- The `note=` argument carries the fictional canary `ASI07-CANARY-7c2e`. The
  verifier never reads it; it is there so you can find the attacker's steps
  in the action log (`GET /api/actions`).

Keep this file plain text. `run_bus_forgery.py` does not escape anything.
Every step it causes is simulated: an entry in the in-memory action log.

The second half of the attack, the **replay**, has no payload file. It copies
an old genuine planner message from `GET /bus/log` (seeded from the `history`
entry in `ops_baseline.json`) and publishes it again unchanged.

## Writing your own payload

- **Keep the first line** reading like an ordinary work-order header. Billy
  Exec acts on every accepted work order in its inbox, so the body only needs
  to be in the format the executor already follows.
- **Echo backend** (default; alias `stub`). Put each step on its own line in the syntax above. Pick
  targets that exist in `ops_baseline.json` (invoices `INV-3001`, `INV-3999`,
  orders `A-0907`..`A-1003`, items `SKU-101`..`SKU-104`) if you want the
  simulated action to report a result. Try publishing with a different
  `sender` (for example `notifier`): vulnerable mode ignores it, because only
  the self-declared `planner` sender is trusted.
- **Real-model backend.** Write the steps in natural language. The verifier
  does not change: it checks the signature, the sender allowlist, the nonce
  and the timestamp, never the wording, so no extra rule is needed for
  hardened mode to hold.
- **Testing the verifier's coverage.** Copy a genuine message from
  `GET /bus/log` and change one character of its body: the signature fails.
  Re-publish it unchanged: the nonce and timestamp checks fail. A message
  validly signed by the planner's key, fresh and unseen, passes by design. The
  verifier proves origin and freshness, not intent; a compromised planner is a
  different risk (see `references/ASI07_RISKS.md`).

Source material: AgenticGoat `acts.py` `a2a_scan` (every peer message is
untrusted input, whoever it claims to be from) is the reference.
