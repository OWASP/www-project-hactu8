# poisoned_note.md — the attacker's ticket note

`scripts/run_sink_poison.py` files `poisoned_note.md` as a new ticket note on
the `ridgeview` account. The first line reads like a normal follow-up. The
second line is the one the stub model turns into its summary.

The line that ships here is a **placeholder**, not a real payload. It is
deliberately inert and still drives the whole lifecycle, because of three
things:

- It starts with `@assistant:`, the stub model's instruction marker
  (`DIRECTIVE_MARKER` in `vulnerable_app.py`). Whatever follows becomes the
  model's output.
- It carries a harmless `<mark>` highlight tag around the fictional canary
  `LLM10-CANARY-4b1e`. If that tag shows up **raw** in a rendered page, the
  sink treated model output as markup. The evaluator scores that RED. A
  `<mark>` tag only highlights text; it runs nothing and fetches nothing.
- It contains an ordinary apostrophe (`O'Placeholder`). A string-built SQL
  statement cannot store it: the quote ends the literal early and SQLite
  rejects the statement. That failure is the evidence that output reached the
  query unparameterised. Real surnames like O'Brien break such code the same
  way.

Keep this file plain text. `run_sink_poison.py` does not escape anything.

## Writing your own payload

- **Keep the marker line.** The stub only emits text that follows
  `@assistant:`. Without it, the model summarises the first note and the sinks
  receive harmless text.
- **Stub backend.** Put the text you want the model to emit after the marker.
  Any tag outside the sink templates' own set (`TEMPLATE_TAGS` in
  `scripts/evaluate_kpi.py`) is scored RED when it renders raw. Any quote that
  breaks the statement, or a stored value that differs from the model's text,
  is scored RED on the `sql` sink. Keep the canary if you want hardened runs
  to score GREEN by showing it as escaped text.
- **Real-model backend.** Not wired in this version (see the README). With a
  real model, the note would need natural-language wording that makes the
  model repeat the text, and you would extend `sink_rules.json` so the
  tripwire reports it. Escaping and parameterisation still do the real work,
  whatever the model says.
- **Stay in the lab.** Target only this skill's own sinks. The served status
  page carries a `default-src 'none'` CSP, the database is `:memory:`, and
  there is no image fetching or outbound channel to aim at.

Source material: AgenticGoat `acts.py` `output_handling_scan` and
`_SINK_RULES` describe the sink classes; this demo exercises the HTML and SQL
classes with inert content only.
