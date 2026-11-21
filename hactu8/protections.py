"""Act 4 "Protections added": the controls a lab's hardened mode applies.

Shown so a learner can see what
the defense adds, not just that the light turned green: the named control, its
plain-language idea, the few steps a developer adds, and a before/after sketch.
The sketches are generic
pseudocode, never a lab's own secrets.

Each lab names its controls in SKILL.md frontmatter:

    metadata:
      hactu8.protections: "input_screen,spotlight"

The ids are keys of ``CATALOG``. ``resolve`` turns them into the entries the
result document carries on Act 4.
"""

from __future__ import annotations

from typing import Dict, Iterable, List

FIELDS = ("title", "idea", "steps", "before", "after")


def _c(title: str, idea: str, steps: List[str], before: str, after: str) -> Dict[str, object]:
    return {"title": title, "idea": idea, "steps": steps, "before": before, "after": after}


CATALOG: Dict[str, Dict[str, object]] = {
    # Screening (ProtectoGW and its relatives)
    "input_screen": _c(
        "Screen ingested content",
        "Before a retrieved document, tool return or memory enters the model's context, screen it and quarantine anything that is not ALLOW.",
        ["screen each untrusted document or tool return at ingestion",
         "drop or quarantine any item whose verdict is not ALLOW",
         "log the quarantine for review"],
        "context = retrieve(query)\nanswer = model(system, query, context)   # poison rides in",
        "context = [d for d in retrieve(query) if screen(d).verdict == ALLOW]\nanswer = model(system, query, context)",
    ),
    "output_screen": _c(
        "Screen the model's own output",
        "Check the reply before it reaches the user or a downstream system: redact or withhold anything that leaks a secret, another user's data or the hidden prompt.",
        ["screen every reply before it leaves the app",
         "redact what the caller may not see; keep their own data",
         "if a line quotes a secret, withhold it and record why"],
        "return reply",
        "result = screen_output(reply, allowed=caller_data)\nreturn result.clean_text   # leaks redacted or withheld",
    ),
    "canary_tripwire": _c(
        "Canary credential and tripwire",
        "Put only a worthless per-run canary where a payload could reach it. A canary in any reply is decisive exfiltration: block it whatever the phrasing.",
        ["mint a per-run canary",
         "place it where the payload would look for a secret",
         "check every reply for the canary; a hit is a hard block"],
        "system = f'...you hold {REAL_KEY}...'   # real secret reachable",
        "system = f'...you hold {canary}...'     # only bait is reachable\nif canary in reply: block(reply)",
    ),
    "spotlight": _c(
        "Keep untrusted text in its own channel",
        "Tool output, retrieved text and user-supplied preferences go to the model as marked data in their own role or tags, never as instructions (spotlighting).",
        ["put tool and retrieved text in a separate role or tagged block",
         "tell the model that text in that block is data only",
         "still screen the block; marking alone is not enough"],
        "prompt = system + user + tool_output   # one undifferentiated stream",
        "messages = [system, user, {'role': 'tool', 'content': tool_output}]\nmodel(messages, trust_tool_role=False)",
    ),
    "visible_text_only": _c(
        "Extract only the text a reader sees",
        "When a document becomes model input, keep only what renders for a human: text that contrasts with its background, has a readable size, is not hidden and sits on the page. Drop metadata, comments and hidden runs.",
        ["extract with layout and style, not just the text layer",
         "drop runs that are hidden, off the page, too small or too close to the background colour",
         "leave metadata, comments and alt channels out of the context, or pass them as labelled data",
         "still screen what is left; faint or tiny text can pass a visibility test"],
        "context = '\\n'.join(run.text for run in parse(document))   # every run, seen or not",
        "context = '\\n'.join(run.text for run in parse(document)\n                    if run.renders and contrast(run) >= MIN and run.size >= MIN_PT)",
    ),
    "normalizer": _c(
        "Normalize before you judge",
        "Fold evasions (Unicode compatibility forms, zero-width characters, leetspeak, base64, rot13, hex) back to plain text before the ruleset runs. A blocklist on raw text is walked past by encodings.",
        ["normalize the text first, with every fold on",
         "apply the ruleset to the normalized text",
         "grow the fold set from held-out misses"],
        "if 'ignore instructions' in text: block()   # raw match only",
        "if screen(normalize(text)).blocked: block()   # encodings folded first",
    ),
    "full_artifact_screen": _c(
        "Screen the whole artifact, not a head sample",
        "Read the entire return in bounded windows, so a payload in the tail past a cost cap cannot hide.",
        ["do not truncate before screening",
         "screen in fixed-size windows up to a hard input cap",
         "reject the artifact if any window is flagged"],
        "screen(reply[:512])   # head sample; the tail is blind",
        "for window in chunks(reply, size=W, cap=MAX_INPUT):\n    screen(window)",
    ),
    "sampling": _c(
        "Screen every return, not one sample",
        "A conditional payload fires on the Nth call or a date. Sample a tool more than once before approval, and screen every return at runtime, alerting on drift.",
        ["call each new release several times before accepting it",
         "screen every return, not just the first",
         "reject on any sample that differs or turns hostile"],
        "screen(tool())   # one sample, clean by design",
        "for _ in range(N): screen(tool())   # trips the Nth-call trigger",
    ),
    "channel_screen": _c(
        "Screen every model-visible channel",
        "Injection hides in parameter schemas and in error messages. Screen those channels too, not just the tool description or the success return.",
        ["screen parameter descriptions, titles, enums and defaults",
         "screen error messages as untrusted output",
         "never pass a raw tool error into the context unscreened"],
        "screen(tool.description)   # description only",
        "for field in tool.model_visible_fields():   # schema and errors too\n    screen(field)",
    ),
    "session_screen": _c(
        "Accumulate and screen across reads",
        "Two clean documents can be hostile once put together. Keep a stateful screen that assembles context across reads and judges the whole.",
        ["accumulate retrieved text in a session buffer",
         "screen the assembled context, not just each document",
         "flag directives that steer the reader to another document"],
        "for d in docs: screen(d)   # per document; misses the chain",
        "for d in docs: session.observe(d)\nscreen(session.assembled())   # catches the chain",
    ),
    "generalization": _c(
        "Measure generalization",
        "Score a held-out set the ruleset was never tuned on, on its own axis. Misses there are expected; prefer controls that do not depend on vocabulary (canary, hash pin, normalizer).",
        ["keep a held-out probe set",
         "score it separately from regression coverage",
         "grow the ruleset from the misses, and report the ceiling"],
        "assert caught_everything(tuning_set)   # low bar",
        "rate = caught(held_out) / len(held_out)   # report it, do not hide it",
    ),
    "mcp_gateway_filter": _c(
        "Gateway that screens every MCP hop",
        "Put ProtectoGW in front of the MCP server as a proxy that screens every surface crossing the boundary: tool descriptions and schemas, results, errors, resources and prompts. Same model and harness; only the route changes.",
        ["run the gateway as an MCP proxy in front of the target server",
         "screen every hop and quarantine what it flags",
         "point the model client at the gateway, not the server",
         "review the quarantine log"],
        "client -> MCP server   # poison reaches the model",
        "client -> ProtectoGW gateway -> MCP server   # screened at the boundary",
    ),
    # Supply chain and provenance
    "hash_pin": _c(
        "Pin approved artifacts by hash",
        "Record a SHA-256 of each tool, skill or template at approval, and reject any later change. It keys on change, not on content.",
        ["at approval: pin = sha256(definition)",
         "before use: compare sha256(live) with the pin",
         "on mismatch, refuse it and keep the approved version"],
        "tool = load_tool(name)   # whatever ships now",
        "if sha256(load_tool(name)) != PINNED[name]:\n    raise Untrusted('changed after approval')",
    ),
    "provenance": _c(
        "Provenance and allowlist",
        "Only sources with recorded provenance on an allowlist may be used: documents, skills, peers and memories. Deny by default.",
        ["record who published or wrote each item",
         "check provenance against the allowlist before use",
         "exclude anything unprovenanced or off the list"],
        "use(item)",
        "if item.provenance not in ALLOWLIST: exclude(item)\nuse(item)",
    ),
    "exact_name": _c(
        "Resolve components by exact name",
        "Load only the exact allowlisted name, never the closest match. A lookalike such as expense_report for expense-report is refused, not resolved.",
        ["resolve names exactly against the manifest",
         "flag names that look like an allowlisted one",
         "refuse anything not in the manifest"],
        "skill = registry.best_match(name)   # fuzzy: a lookalike wins",
        "skill = MANIFEST.get(name)\nif skill is None: refuse(name)   # exact or nothing",
    ),
    # Data access and identity
    "scope_filter": _c(
        "Scope data to the caller at the data layer",
        "Enforce tenant or user scope on every read, in code, before ranking, whatever the model asks for.",
        ["tag every record with its owner or tenant",
         "filter reads to the authenticated caller",
         "drop foreign records before they reach the context"],
        "hits = store.search(query)",
        "hits = [d for d in store.search(query) if d.tenant == session.tenant]",
    ),
    "secret_vault": _c(
        "Keep secrets out of the prompt",
        "Credentials live in a vault and are used by code, never placed in the system prompt or tool text, so the model has nothing to reveal.",
        ["move keys out of prompts and tool output into a vault",
         "let the connector fetch the key; the model never sees it",
         "lint deployed prompts for secrets"],
        "system = f'...service key {KEY}...'   # the model can repeat it",
        "system = SECRET_FREE_PROMPT\nconnector.auth(vault.reveal('service_key'))   # code only",
    ),
    "delegated_token": _c(
        "Act with the caller's delegated token",
        "The agent calls downstream services with a short-lived on-behalf-of token for the requesting user, so it can never do more than that user may (no confused deputy).",
        ["exchange the user's session for an on-behalf-of token",
         "keep it short-lived and bound to the session",
         "reject expired or unbound tokens at the service"],
        "fetch(record, token=AGENT_SERVICE_TOKEN)   # the agent's own wide rights",
        "token = obo_exchange(session.user, ttl=300)\nfetch(record, token=token)   # caller's rights only",
    ),
    # Agency and tool boundary
    "hitl_gate": _c(
        "Tool allowlist and human confirmation",
        "The model may request a tool; a deterministic gate decides. Each task gets only its tools, and irreversible calls wait for an operator.",
        ["give each task only the tools it needs",
         "deny calls off the allowlist",
         "hold irreversible calls for confirmation"],
        "run(choice.tool, choice.args)",
        "ok, reason = gate(task, choice)   # allowlist and confirmation\nif not ok: deny(reason)\nrun(choice.tool, choice.args)",
    ),
    "param_policy": _c(
        "Parameter policy at the tool boundary",
        "Permitted tools can still be called with unsafe arguments. Check every call's parameters in code: destination allowlist, row caps and a per-run call budget.",
        ["allowlist destinations for anything that sends data out",
         "cap rows and sizes per call",
         "budget calls per run, checked on every call"],
        "export(rows=query(all), to=args.dest)",
        "policy.check(tool, args)   # dest allowlist, row cap, call budget\nexport(rows=query(limit=CAP), to=args.dest)",
    ),
    "action_policy": _c(
        "Enforce the rule on the action, not in the prompt",
        "A rule in the system prompt is a request to the model, and a conversation can talk the model out of it. Check the rule where the action runs, in code, against the session's real identity and the stored record, so it holds whatever the model was persuaded to do.",
        ["list the business rules a tool call can break (who may get which discount, which order may be marked paid)",
         "check every call server-side against the authenticated session and the stored record, never a claim made in the chat",
         "deny and log a call that fails, and tell the user plainly",
         "keep the prompt rule as well: it cuts attempts, the check decides"],
        "apply_discount(order, code)   # the prompt said: never STAFF30 on a customer order",
        "why = policy.denies(session, order, code)   # role, channel, ownership, from the server\nif why: deny(why)\nelse: apply_discount(order, code)",
    ),
    "sampling_policy": _c(
        "Gate MCP sampling in the client",
        "An MCP server can ask the client's model to write for it (sampling). Treat each request as untrusted: only listed servers may sample, within a budget, a person approves each one, the session goes into the prompt only when they agree, and the reply is checked before it goes back to the server.",
        ["allow-list the servers that may sample; cap requests per tool call, maxTokens and a session budget",
         "show each request to the user, who can deny it; screen its system prompt and messages first",
         "treat includeContext as none unless the user agreed, and never share the system prompt or secrets",
         "screen the generated reply for secrets before it returns to the server"],
        "result = model(request.messages + (session if request.includeContext != 'none' else []))\nreturn result   # to the server",
        "if not policy.allows(server, request) or not user.approves(request): deny()\nctx = session.user_messages() if user.shared_context else []\nresult = model(ctx + request.messages, max_tokens=cap)\nif screen(result, canaries=[secret]).blocked: deny()\nreturn result",
    ),
    "plan_pin": _c(
        "Pin the plan before reading tool data",
        "Fix the agent's plan from the user's request before any tool data is read. A step that tool data adds is off-plan and is held for re-approval.",
        ["derive the plan from the request alone",
         "read tool data as data, after the plan is fixed",
         "hold any off-plan step for operator approval"],
        "plan = model(request + tool_data)   # data can rewrite the goal",
        "plan = model(request)   # pinned first\nfor step in proposed:\n    if step not in plan: hold(step)",
    ),
    "rate_limit": _c(
        "Per-request budget caps",
        "Cap output tokens, tool calls, loop depth and per-client quota per request, and stop a runaway before the invoice does.",
        ["set caps for output, tool calls, steps and client quota",
         "meter each request against them",
         "abort when a cap is reached"],
        "while not done: reply = model(prompt)   # unbounded",
        "budget = Budget(tokens=T, calls=C, depth=D)\nwhile not done and budget.allows(): reply = model(prompt)",
    ),
    "grounding": _c(
        "Ground claims against an approved registry",
        "Where output drives action, check cited packages and URL hosts against an approved registry before anyone acts; withhold what is unverified.",
        ["extract cited packages and URLs from the reply",
         "check each against the registry and trusted-domain allowlist",
         "withhold the draft if anything is unverified"],
        "install(model_named_package)   # trust the hallucination",
        "flagged = grounding_check(reply, REGISTRY)\nif flagged: withhold(reply, flagged)",
    ),
    "output_sink": _c(
        "Treat output as data at the sink",
        "Model output is untrusted input to whatever consumes it. Escape it for HTML and bind it as a parameter in SQL, so it can never run as code.",
        ["never concatenate model output into markup, SQL or a shell",
         "escape for the renderer (html.escape)",
         "use ? placeholders for SQL"],
        "page += reply\ndb.execute(f\"... WHERE note = '{reply}'\")",
        "page += html.escape(reply)\ndb.execute(\"... WHERE note = ?\", (reply,))",
    ),
    "code_sandbox": _c(
        "Allow-list sandbox before a code sink",
        "Model-written code is untrusted. Before any interpreter sees it, parse it and allow only the node types, names and calls the task needs; anything else never runs.",
        ["parse the snippet (never run it to check it)",
         "allow only listed node types, helper calls and builtins: no imports, dunders or host modules",
         "block and log anything else; let the model retry within the allow-list"],
        "run_snippet(model_code)   # imports, env, files, processes all reachable",
        "reasons = sandbox_check(ast.parse(model_code), POLICY)\nif reasons:\n    block(reasons)\nelse:\n    run_snippet(model_code)",
    ),
    # Multi-agent
    "signed_messages": _c(
        "Signed inter-agent messages",
        "Every agent message carries an HMAC signature with the sender's own key; the receiver checks the sender allowlist and rejects replays by nonce and timestamp.",
        ["sign each message with the sender's key",
         "verify signature and sender allowlist on receipt",
         "reject reused nonces and stale timestamps"],
        "act(message)   # anyone on the bus can speak for anyone",
        "if not verify(message, keys[message.sender]) or replayed(message):\n    reject(message)\nact(message)",
    ),
    "cross_check": _c(
        "Re-check against the source of truth",
        "Each stage re-validates the figures it receives against the system of record, instead of trusting the stage before it.",
        ["identify the system of record for each field",
         "re-check every incoming figure against it",
         "flag and stop on a mismatch"],
        "approve(upstream.figures)",
        "anomalies = [f for f in upstream.figures if f != ledger.lookup(f.key)]\nif anomalies: halt(anomalies)",
    ),
    "circuit_breaker": _c(
        "Circuit breaker on a bad feed",
        "After repeated anomalies from one source, halt that feed so one bad input cannot cascade through the pipeline.",
        ["count anomalies per source",
         "open the breaker past a threshold",
         "require a human to close it"],
        "for item in feed: pipeline(item)",
        "for item in feed:\n    if breaker[feed].open: break\n    pipeline(item)",
    ),
    "faithful_approval": _c(
        "Approval cards from the real parameters",
        "The human approves what will actually run: cards are built from the real call parameters with a code-computed risk tier, and high-risk actions never ride in a batch.",
        ["render the card from the call's parameters, not the agent's summary",
         "compute the risk tier in code",
         "approve high-risk actions one at a time"],
        "approve(agent.summary)   # the summary can hide the bank change",
        "card = Card(call.params, tier=risk_tier(call))\napprove(card, batch=(card.tier != 'high'))",
    ),
    "signed_config": _c(
        "Signed agent configuration",
        "An agent's mandate (its actions and resources) is a signed config; an edit with a bad signature is rejected before the agent loads it.",
        ["sign the approved mandate config",
         "verify the signature on load",
         "reject an unsigned or altered config"],
        "agent.load(config)",
        "if not verify(config, MANDATE_KEY): reject(config)\nagent.load(config)",
    ),
    "mandate_monitor": _c(
        "Runtime mandate monitor with a kill switch",
        "A monitor checks each action against the agent's mandate at runtime, blocks off-mandate actions and quarantines the agent.",
        ["state each agent's mandate: actions and resources",
         "check every action against it at runtime",
         "block off-mandate actions and quarantine the agent"],
        "agent.do(action)",
        "if action not in mandate:\n    block(action); quarantine(agent)\nelse:\n    agent.do(action)",
    ),
}

# The live run (hactu8 live): Billy's MCP surfaces behind the ProtectoGW gateway.
LIVE: List[str] = ["mcp_gateway_filter", "hash_pin", "session_screen", "canary_tripwire"]


def parse_ids(value: str) -> List[str]:
    """Split a ``hactu8.protections`` metadata value into ids, in order, without duplicates."""
    out: List[str] = []
    for part in (value or "").split(","):
        cid = part.strip()
        if cid and cid not in out:
            out.append(cid)
    return out


def unknown(ids: Iterable[str]) -> List[str]:
    return [cid for cid in ids if cid not in CATALOG]


def entry(control_id: str) -> Dict[str, object]:
    base = CATALOG[control_id]
    return {"id": control_id, "title": base["title"], "idea": base["idea"],
            "steps": list(base["steps"]), "before": base["before"], "after": base["after"]}


def resolve(ids: Iterable[str]) -> List[Dict[str, object]]:
    """The catalog entries for ``ids``. Unknown ids raise KeyError."""
    ids = list(ids)
    missing = unknown(ids)
    if missing:
        raise KeyError(f"unknown protection id(s): {', '.join(missing)}")
    return [entry(cid) for cid in ids]


def library() -> List[Dict[str, object]]:
    return [entry(cid) for cid in CATALOG]
