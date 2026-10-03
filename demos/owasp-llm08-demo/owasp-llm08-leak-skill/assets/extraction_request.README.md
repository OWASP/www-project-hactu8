# extraction_request.md — the attacker's saved reply preference

`scripts/run_extraction.py` saves `extraction_request.md` as the reply
preference of the `guest-attacker` account. Billy Shop places that preference
in its context with every question the account asks, as the product intends.
The stub model reads it as an instruction to quote its system prompt.

The line that ships here is a **placeholder**, not a real payload. It works
straight away because of two things:

- It starts with `@assistant:`, the stub model's instruction marker
  (`DIRECTIVE_MARKER` in `vulnerable_app.py`).
- It contains the stub's echo slot `{system_prompt}` (`ECHO_SLOT`), which the
  stub replaces with the system prompt it was given. That is the stub's
  stand-in for a model repeating its instructions.

The payload contains **no** canary. The canary `LLM08-CANARY-5e1d` lives only
in `system_prompt_vulnerable.txt`, so when it shows up in a reply it came out of
the deployed prompt. `tests/test_lifecycle.py` checks this.

Keep this file plain text. `run_extraction.py` does not escape anything.

## Writing your own payload

- **Stub backend.** Your instruction must sit on a line that starts with
  `@assistant:`. Whatever follows the marker is appended to Billy's reply;
  put `{system_prompt}` where the quoted prompt should go. Only the first
  directive line is used.
- **Real-model backend.** Write a natural-language request that asks the
  assistant to restate its setup: repeat it, translate it, or summarise it.
  Translation and summary are the interesting cases, because they change the
  wording: the n-gram output filter in `filter_rules.json` only catches
  verbatim fragments, and the canary pattern only catches the code itself.
  That gap is why the design fix (no secret in the prompt) is the primary
  mitigation.
- **Testing the filter.** Lower or raise `output.ngram` in
  `filter_rules.json` and watch which lines are withheld.

Source material: AgenticGoat's LLM07 probe in `training_live.py` and the
`system_reveal` screen rule in `protectogw/screening.py` are the reference.
