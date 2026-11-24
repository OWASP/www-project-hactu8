# LLM10 Improper Output Handling

LLM01 is what goes into the model; this lab is what comes out and where it goes next. Setup, commands and architecture are in the [lab README](../README.md); this lesson says what to look for and why.

## What it is

Improper output handling is a downstream system trusting model output too much. Concatenated into HTML it becomes cross-site scripting; into SQL, injection; into a shell, command execution; into a URL the client fetches, request forgery or a data-exfiltration channel. The model is a text generator with no security model, so its output is untrusted input to whatever consumes it, exactly like a user's.

Here the target is Lamb, Big Field Jumper Co.'s ticket-summary assistant. Its ground truth for the Ridgeview account is *"Ridgeview printer queue restored and ticket closed by the night shift."* Lamb's summary feeds three sinks: the account's HTML status page, a markdown weekly digest and a SQLite audit log. The attacker files one ticket note through the unauthenticated ticket endpoint, and all three Ridgeview sinks mishandle what Lamb writes next. The Harbor account goes through the same sinks untouched.

## Why it works

The dangerous part of the output is not an instruction; it is markup or a quote character that a downstream interpreter acts on. Three sinks each build code from the text:

- The HTML status page is an f-string, so a tag in the summary is parsed as markup.
- The markdown renderer converts `**bold**` and headings and passes any other HTML through, as many real renderers do.
- The audit log builds `INSERT ... VALUES ('ridgeview', '<summary>')`, so an apostrophe in the summary ends the string literal.

An input screen never sees the problem. The original lesson makes the point with protectogw's default screen, which allows `x; DROP TABLE users; --`, because it carries no injection instruction; checked here with the vendored copy, it still does. The OWASP guidance is to treat the model like any other user: encode its output for the context it lands in, and bind it as a parameter rather than building statements from it.

## Try it

Run all four acts with `python run_demo.py` from `demos/owasp-llm10-demo`, or `python -m hactu8 run llm10` from the repo root, or open the lab console (`cd owasp-llm10-sink-skill && python vulnerable_app.py`, then <http://127.0.0.1:5210/>). The suite is five sink deliveries: Ridgeview's status page, digest and audit log, and Harbor's status page and audit log as controls.

- **Act 1, clean baseline.** All five GREEN, Unsafe Sink Rate (USR) 0%. Each sink shows the plain summary.
- **Act 2, attack.** One note filed on `ridgeview`; no sink touched. Open [`assets/poisoned_note.md`](assets/poisoned_note.md): a normal follow-up line, a line asking for the next line to be copied verbatim as the status summary, and that summary, with a harmless `<mark>` highlight tag around the fictional canary `LLM10-CANARY-4b1e` and the surname O'Hara. [`assets/poisoned_note.README.md`](assets/poisoned_note.README.md) explains its design. It runs nothing and fetches nothing.
- **Act 3, impact.** All three Ridgeview sinks turn RED (USR 100% targeted). The status page and the digest render `<mark>` raw: model output was treated as markup. The audit log fails with a real `sqlite3.OperationalError: near "Hara": syntax error`: the apostrophe ended the SQL literal. The Harbor controls stay GREEN.
- **Act 4, remediation.** The protectogw screen of the note rejects it (`lab_directive`, `lab_canary`, `html_markup`), and hardened mode returns all five to GREEN. The model's output is byte-for-byte the same as in Act 3 (`test_model_output_same_in_both_modes`): the status page now shows `Siobhan O&#x27;Hara` and `&lt;mark`, and the audit log stores the text exactly.

On a real model (`--backend ollama --model llama3.2:3b`), the numbers are reported, not asserted. The sinks behave the same whatever the model writes.

## The defense, and why it holds

Act 4 adds one protection, `output_sink`, as handling at each sink:

- **Contextual output encoding.** `html.escape` before both HTML sinks, so the summary is displayed as text, whatever characters it holds.
- **Parameterised queries.** `?` placeholders bind the summary as data, so it is stored exactly as the model wrote it, apostrophes included.

Neither depends on recognising an attack, and neither changes the model's output: the fix is at the sink, where the text becomes code. `test_sink_handling_alone_blocks` takes the USR to 0 with an empty tripwire policy.

A third layer is a detector, not the fix: `screen_output` screens the output with protectogw under `SINK_POLICY`, which adds three lab rules (`html_markup`, `lab_directive`, `lab_canary`). Hardened mode logs its findings, and `evaluate_kpi.py --scan` rejects a note before it is filed.

## Where the defense stops working

- **The vulnerable SQL sink breaks with no attack at all.** Any ordinary apostrophe in model output ends the literal. Checked: in vulnerable mode the Harbor summary "Harbor's badge reader replaced and ticket closed." fails with `sqlite3.OperationalError: near "s": syntax error`, and hardened mode stores it exactly. Real surnames like O'Brien break such code the same way. String-built queries are a bug before they are a vulnerability.
- **The tripwire misses most sink payloads.** Checked against `screen_output`: `x; DROP TABLE users; --`, `rm -rf /var/spool/* && reboot`, a `javascript:` URL and a markdown image link carrying data in its query string all pass with no findings. Only markup is covered. It also flags a harmless sentence such as "Replace the `<div>` wrapper in the template." Encoding and parameterisation hold either way; the screen is evidence, not protection.
- **Encoding is only right for its context.** `html.escape` is correct here because the templates place the summary in element content only. Output placed in an attribute, a URL, a script or a style block needs different encoding, and a `javascript:` link survives HTML escaping. The lab covers the HTML and SQL classes; shell, code execution and fetched URLs are discussed in the references, not coded.
- **The markdown image exfiltration channel is not built.** The demo plan proposed a renderer that fetches images and a loopback receiver; the lab dropped both and builds no fetching component, so that channel is taught, not shown. Sanitising markdown and proxying or blocking auto-fetched images is the control.
- **The model is still steered.** In Act 4 the status page still shows the attacker's sentence, safely escaped. Output handling stops the text from running as code; it does not stop the attacker from choosing the text. That is LLM01's control, and unauthenticated ticket notes remain open.

## Check yourself

1. The Act 3 audit-log error is a syntax error, not a dropped table. Why is it still the evidence the lab needs?

   Answer: It proves the model's text became part of the SQL statement: the apostrophe ended the literal. A payload that can end a literal can add its own SQL; parameterisation removes that possibility.
2. In Act 4 the model's output is byte-for-byte the same as in Act 3. What changed, and why does that matter?

   Answer: Only the sinks: the HTML is escaped and the SQL is parameterised. The fix holds whatever the model writes, so it does not depend on the model resisting the note or on a screen recognising it.
3. Why is the protectogw screen not enough on its own?

   Answer: It flags only patterns it has rules for. Here it misses SQL, shell, `javascript:` URLs and markdown image links, and it flags harmless text that mentions a tag. Encoding and parameterisation at the sink do the real work.

## References

- HACTU8 catalog: skill `llm10`, OWASP `LLM10:2026` Improper Output Handling (`LLM05:2025` in the 2025 edition); protection `output_sink` (`hactu8/protections.py`); MITRE CWE-79 and CWE-89.
- Lab material, not repeated here: the [lab README](../README.md) (architecture, the "real, not scripted" argument, MCP terminology bridge, deviation from the demo plan) and [`references/LLM10_RISKS.md`](references/LLM10_RISKS.md) (research, scenarios O-1 to O-3, mitigation roadmap).
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/), entry Improper Output Handling.
- OWASP Cross Site Scripting Prevention Cheat Sheet and SQL Injection Prevention Cheat Sheet; Greshake et al. (2023), "Not what you've signed up for".
- Ported from the predecessor project (retired): its 2025-numbered LLM05 Improper Output Handling lesson and curriculum entry (`training/lessons/LLM05_improper_output_handling.md`, `curriculum.json`), and its `acts.py` `output_handling_scan`.
