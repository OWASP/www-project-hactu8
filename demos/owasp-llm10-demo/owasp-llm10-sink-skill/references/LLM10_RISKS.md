# LLM10 Risk Reference — Improper Output Handling

Domain knowledge, loaded on demand. Improper output handling happens when an
application passes a model's output to a downstream component (a browser, a
database, a shell, a renderer) without validating, encoding or
parameterising it. The model is a text generator with no security model, so
its output is untrusted input to whatever consumes it. Anyone who can
influence that output, directly or through content the model reads, gets to
write into the sink. (This repo numbers it LLM10; the OWASP Top 10 for LLM
Applications 2025 lists it as LLM05.)

## Research foundations

- **OWASP Top 10 for LLM Applications, Improper Output Handling (LLM05:2025)**
  — the risk entry: XSS, SQL injection, code execution and SSRF reached
  through model output, with prevention guidance (treat the model as a user,
  encode by context, parameterise queries).
- **Greshake et al. (2023), "Not what you've signed up for"** — indirect
  prompt injection. It explains how an attacker who never talks to the model
  still controls its output, which is what makes output handling exploitable.
- **OWASP Cross Site Scripting Prevention Cheat Sheet** and **OWASP SQL
  Injection Prevention Cheat Sheet** — the classic sink-side defences
  (contextual output encoding; prepared statements). They apply unchanged when
  the untrusted string comes from a model.
- **MITRE CWE-79 and CWE-89** — the weakness classes the HTML and SQL sinks
  here embody.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| O-1 | Model output into HTML | Output is inserted into a page without encoding, so markup in it renders. | **DEMO TARGET** (`html` sink) |
| O-2 | Model output through a markdown renderer | The renderer passes inline HTML through. | **DEMO TARGET** (`markdown` sink) |
| O-3 | Model output into SQL | Output is spliced into a statement instead of bound as a parameter. | **DEMO TARGET** (`sql` sink) |
| O-4 | Auto-fetched markdown images | A client fetches image URLs the model emits, leaking data in the URL. | — (dropped; see README) |
| O-5 | Model output into a shell or `eval` | Generated text executed as code. | — (no shell sink, by design) |
| O-6 | Model output as a URL the server fetches | SSRF via generated links. | — |

## How the demo maps to the attack surfaces

- **Trigger.** `POST /tickets/note` accepts unauthenticated notes. The stub
  model turns a directive line in the notes into its summary (the LLM01
  mechanism, reused only to put attacker text in the output).
- **O-1** is `Lab._sink_html` in vulnerable mode: an f-string into
  `STATUS_PAGE`. `GET /status/<account>` serves the result.
- **O-2** is `render_markdown`, which converts `**bold**` and headings but
  passes any other markup through.
- **O-3** is `Lab._sink_sql` in vulnerable mode: the summary becomes a string
  literal inside the `INSERT`. An apostrophe ends the literal and the
  statement fails. That is the same structural break an attacker would use to
  change the statement.
- **Blast radius.** Only the poisoned account's output is affected; the Harbor
  controls go through the same sinks and stay GREEN.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Unencoded output in HTML | **Contextual output encoding.** Implemented: `html.escape` in hardened mode for both HTML sinks. |
| String-built SQL | **Parameterised queries.** Implemented: `?` placeholders in hardened mode. |
| Renderer passes raw HTML | Escape before rendering, or use a renderer with raw HTML disabled. Implemented: escape-then-render. |
| No visibility of sink-active output | **Output-sink tripwire.** Implemented: `screen_output` screens with protectogw (AgenticGoat's screening core, vendored unchanged: normalizer + de-obfuscation folds + ruleset + exfil taxonomy + canary check) plus lab rules for markup, the directive marker and the canary; logged in hardened mode and used by `--scan`. Its `SECURITY.md` states a ~75% generalization ceiling, so it is one layer, never the boundary. A tripwire, not the fix. |
| Browser runs what renders | Content-Security-Policy. Implemented as a host-safety guard (`default-src 'none'` on `/status/`). |
| Auto-fetched images / links | Image-domain allowlist or disable remote images. Discussed, not coded. |
| Unauthenticated content sources | Authenticate and attribute ticket notes (see LLM01). |

Further hardening discussed, not coded: structured outputs validated against a
schema, least-privilege database accounts, sandboxing any code-executing sink,
and allowlisting URLs a client may fetch.
