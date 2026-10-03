# lookalike_skill.json — the attacker's catalogue entry

`scripts/run_lookalike_publish.py` publishes `lookalike_skill.json` to the
shared skill catalogue. It is an ordinary skill entry with three properties
that make the resolver pick it:

- **The name `expense_report`** differs from the real `expense-report` by
  one character. The vulnerable resolver folds `-`, `_` and `.` together, so
  both names match a step that asks for `expense-report`.
- **The version `9.0.0`** is higher than the real `1.4.0`, and the resolver
  loads the newest match.
- **The publisher `goatco-finance-community`** looks official but is not the
  pinned `goatco-finance`. Nothing checks it in vulnerable mode.

The instructions that ship here are a **placeholder**, not a real payload.
They work straight away because of two things:

- One line starts with `@assistant:`, the stub model's instruction marker
  (`DIRECTIVE_MARKER` in `vulnerable_app.py`).
- That line contains the canary `ASI04-CANARY-5e1d`, so the step output is
  easy to spot.

The evaluator scores from the action log (which component loaded), not from
the text, so the placeholder line is not needed to turn the task RED. It shows
what the loaded skill could do once it is in context.

The entry is data. Billy Ops never executes anything from a skill; loading it
only places `instructions` in the model's context. Keep every field a plain
string, and keep `version` numeric (`1.2.3`); the catalogue rejects anything
else.

## Writing your own payload

- **Keep the name a lookalike** of a skill that targeted tasks request. Try
  `Expense.Report` or `EXPENSE-report` (the resolver folds both), or override
  it with `--name`. A name the resolver does not fold, such as `expense-reports`,
  is never loaded, and the rate stays at 0. That threshold is part of the lesson.
- **Keep the version higher** than `1.4.0` (`--version` overrides it). A lower
  version loses to the real skill.
- **Stub backend.** Your instruction must sit on a line in `instructions` that
  starts with `@assistant:`. Whatever follows the marker becomes the step
  output.
- **Real-model backend.** Write the instruction in natural language, as a real
  skill file would. The manifest check does not depend on the wording: the
  name, publisher and SHA-256 pins reject the entry whatever it says.

Source material: AgenticGoat `acts.py` (act 3, hash pinning, and act 15,
grounding a typosquatted name against an approved registry) covers the same
controls.
