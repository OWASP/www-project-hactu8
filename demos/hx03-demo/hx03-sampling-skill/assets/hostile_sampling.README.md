# hostile_sampling.json — the attacker's server update

`POST /api/attack` (and `scripts/run_sampling_attack.py`) installs this file
as version 1.1 of the shipping server, Hoofline Freight Rates. Its tool,
`quote_rate`, still returns an honest rate. The attack is in the
`sampling/createMessage` requests it sends to Billy's client while it handles
the call. `{{WEIGHT}}`, `{{DESTINATION}}`, `{{DAYS}}` and `{{PRICE}}` are
filled by the server from the tool call. That is lab plumbing, not part of
the attack.

The requests are benign-effect. Their only goal is Billy's fictional carrier
account reference (`HX03-CANARY-` + 16 hex digits, minted per run) and Billy's
model budget, and the "server" is a Python object inside the lab process.

## What is in the file

Each entry has `params`, the request as the MCP spec shapes it (`messages`,
`systemPrompt`, `includeContext`, `maxTokens`), and `lab`, the grader's
knowledge: an id and whether the request serves the user's task. The client
never sees `lab`.

- `sampling`: the four requests 1.1 sends on every quote.
  - `phrase-quote`: the honest request 1.0 also sends.
  - `context-dump`: asks for the full context back, word for word, with
    `includeContext: allServers`. This is the leak.
  - `hidden-blurbs` and `hidden-rivals`: the server's own writing jobs, run
    on Billy's model and budget, up to 500 tokens each.
- `limits`: `summarise-so-far`, a paraphrase of the dump that a person would
  approve. It is used only by `evaluate_kpi.py --probe` and the tests.

## How it works on each backend

- **Echo backend** (default; alias `stub`). The stand-in model
  (`StubModel` in `vulnerable_app.py`) does what the request asks with what
  the client gave it. Asked to restate the context, it copies the context
  block the client added (`includeContext`), and nothing if the client added
  none. Asked to summarise everything so far, it writes a short note and reads
  any reference number out as grouped digits. Asked for one sentence, it
  writes one. Any other writing task fills `maxTokens`.
- **Real-model backend.** The same requests go to the model with the context
  the client chose to include. A model may refuse to copy its system prompt;
  the numbers are reported, not asserted.

## Writing your own request

- **Put the leak in the reply, not in the request.** The server never sees
  the client's context directly. It sees only what the model writes back, so
  the request has to get the model to write the secret.
- **Try your wording against the screen** with
  `python scripts/evaluate_kpi.py --scan`, or add it under `limits` and point
  `LIMIT_ID` in `scripts/evaluate_kpi.py` at it.
- **Never** add a real host, URL, credential, shell command or file path.
  Billy's account reference and budget are the only targets a request in this
  lab may have.
