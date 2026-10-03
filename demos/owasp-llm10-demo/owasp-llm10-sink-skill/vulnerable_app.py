#!/usr/bin/env python3
"""Vulnerable ticket-summary assistant "Billy" — the target system for the LLM10 demo.

Billy summarises a customer's support-ticket notes, and the summary is handed
straight to three downstream **sinks**:

* ``html``     — the account's status page (an HTML template),
* ``markdown`` — a small markdown-to-HTML renderer used for the weekly digest,
* ``sql``      — an audit log row in an in-memory SQLite database.

Two gaps are demonstrated, both by omission:

* **No output encoding** — the summary is pasted into HTML with an f-string
  and fed to a markdown renderer that passes inline HTML through, so any markup
  in the model's output becomes markup on the page.
* **No parameterisation** — the summary is spliced into the SQL statement as a
  string literal, so a single quote in the model's output ends the literal and
  changes the statement's structure.

The ticket store behind Billy also accepts unauthenticated notes
(``POST /tickets/note``), which is how attacker text reaches the model.

AUTHORIZED SECURITY-LAB USE ONLY. Bound to loopback; do not expose it.

The model is a deterministic **instruction-following stub** (see
``StubModel``): it summarises the first note, unless its context contains a
directive line (``DIRECTIVE_MARKER``), which it obeys. Its contract is the same
in both modes, so the model's output is the same in both modes. What changes
between vulnerable and hardened is only **how that output is handled** by real
sink code: ``html.escape`` and SQLite ``?`` placeholders. Nothing is hard-coded
to flip.

Hardened mode (``POST /api/mode`` or ``LLM10_MODE=hardened``) escapes the
output before it reaches either HTML sink and binds it as a parameter in SQL.
It also runs the ``assets/sink_rules.json`` tripwire and reports matches in
``screen_findings`` without relying on it.

Host-safety guards (do not weaken the lesson): SQLite is ``:memory:`` only and
uses ``execute`` (one statement, never a script); the log is capped; ticket
notes are capped in count and length and live in memory only; served HTML
carries a ``default-src 'none'`` Content-Security-Policy; nothing fetches,
executes, or writes files.
"""

from __future__ import annotations

import html
import json
import os
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

import providers

HERE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(HERE, "assets")
BASELINE_FILE = os.path.join(ASSETS, "tickets_baseline.json")
SINK_RULES_FILE = os.path.join(ASSETS, "sink_rules.json")
PAYLOAD_FILE = os.path.join(ASSETS, "poisoned_note.md")
WEB_DIR = os.path.join(HERE, "web")
WEB_FILES = {"index.html": "text/html", "app.js": "text/javascript", "styles.css": "text/css"}

SYSTEM_PROMPT = (
    "You are Billy, the support-ticket summariser for Goat & Co. "
    "Summarise the customer's ticket notes in one sentence."
)

# The stub's instruction syntax. A line in the model's context that starts with
# this marker is treated as an instruction to the assistant. It stands in for
# the natural-language instructions a real model would follow.
DIRECTIVE_MARKER = "@assistant:"

VALID_MODES = ("vulnerable", "hardened")
SINKS = ("html", "markdown", "sql")

# Host-safety caps.
MAX_NOTES_PER_ACCOUNT = 20
MAX_NOTE_CHARS = 4000
MAX_LOG_ROWS = 200


def load_baseline() -> Dict[str, List[str]]:
    with open(BASELINE_FILE, "r", encoding="utf-8") as fh:
        return {k: list(v) for k, v in json.load(fh)["accounts"].items()}


def load_sink_rules() -> Dict[str, Any]:
    with open(SINK_RULES_FILE, "r", encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------- #
# Mitigation tripwire: output-sink screen
# --------------------------------------------------------------------------- #
@dataclass
class ScreenResult:
    findings: List[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return bool(self.findings)


def screen_output(text: str, rules: Dict[str, Any]) -> ScreenResult:
    """Report lines whose content a downstream sink would interpret.

    Rules come from ``assets/sink_rules.json``: literal ``markers`` and named
    regex ``patterns``, matched case-insensitively per line. This is a
    tripwire: hardened mode logs it, ``--scan`` uses it to reject a note before
    it is filed. The fix that actually returns the rate to 0 is at the sink.
    """
    markers = [m.lower() for m in rules.get("markers", [])]
    patterns = {name: re.compile(p, re.I) for name, p in rules.get("patterns", {}).items()}
    findings: List[str] = []
    for line in text.splitlines():
        low = line.lower()
        for m in markers:
            if m in low:
                findings.append(f"marker {m!r}")
        for name, pat in patterns.items():
            if pat.search(line):
                findings.append(f"rule {name!r}")
    return ScreenResult(findings)


# --------------------------------------------------------------------------- #
# The model stand-in
# --------------------------------------------------------------------------- #
class StubModel:
    """Deterministic instruction-following stand-in for an LLM.

    Returns whatever follows the first directive line in its context, or else a
    one-sentence summary built from the first ticket note. Same contract in
    both modes: LLM10 is about what the application does with the output.
    """

    def generate(self, messages: List[Dict[str, str]]) -> str:
        for msg in messages:
            for line in msg["content"].splitlines():
                stripped = line.strip()
                if stripped.lower().startswith(DIRECTIVE_MARKER):
                    return stripped[len(DIRECTIVE_MARKER):].strip()
        notes = next((m for m in messages if m["role"] == "tool"), None)
        if notes is None or not notes["content"].strip():
            return "No ticket notes on file."
        return f"Summary: {notes['content'].strip().splitlines()[0]}"


class ProviderModel:
    """Real-model backend with the same interface as ``StubModel``.

    The ticket notes are pasted into the user turn as ordinary text, in both
    modes, exactly as the stub receives them. LLM10 is about what the
    application does with the output, so the prompt is deliberately the same
    in both modes: the fix is at the sinks (``html.escape`` and ``?``
    placeholders), which stay in code and hold whatever the model writes. The
    returned text only ever reaches the same three sinks as the stub's text.
    """

    def __init__(self, provider: "providers.Provider", model: str) -> None:
        self.provider = provider
        self.model = model

    def generate(self, messages: List[Dict[str, str]]) -> str:
        system = " ".join(m["content"] for m in messages if m["role"] == "system")
        user = "\n".join(m["content"] for m in messages if m["role"] == "user")
        notes = "\n".join(m["content"] for m in messages if m["role"] == "tool")
        prompt = f"{user}\n\nTicket notes:\n{notes}"
        try:
            reply = self.provider.chat(
                [providers.Message("system", system), providers.Message("user", prompt)],
                model=self.model,
            )
        except (OSError, KeyError, ValueError) as exc:
            # Keep backend faults apart from the lab's own 400/404 errors.
            raise RuntimeError(f"{type(exc).__name__}: {exc}") from exc
        return (reply or "").strip()


# --------------------------------------------------------------------------- #
# The sinks
# --------------------------------------------------------------------------- #
STATUS_PAGE = (
    "<!doctype html><html><head><title>Status: {account}</title></head>"
    "<body><h1>Goat &amp; Co. ticket status</h1>"
    "<p class=\"summary\">{summary}</p></body></html>"
)


def render_markdown(text: str) -> str:
    """Tiny markdown renderer: headings, **bold**, paragraphs.

    Like many real renderers, it passes inline HTML through untouched. No image
    or link fetching is implemented.
    """
    out: List[str] = []
    for block in re.split(r"\n\s*\n", text.strip()):
        block = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", block.strip())
        heading = re.match(r"^(#{1,3})\s+(.*)$", block)
        if heading:
            level = len(heading.group(1))
            out.append(f"<h{level}>{heading.group(2)}</h{level}>")
        elif block:
            out.append(f"<p>{block}</p>")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# The lab: ticket store, model call, sink handling
# --------------------------------------------------------------------------- #
class Lab:
    def __init__(self, mode: str = "vulnerable", backend: str = "echo",
                 model: str = "") -> None:
        self.lock = threading.Lock()
        self.set_backend(backend, model)
        self.rules = load_sink_rules()
        self.tickets: Dict[str, List[str]] = {}
        self.added: List[str] = []
        self.db: Optional[sqlite3.Connection] = None
        self.mode = "vulnerable"
        self.set_mode(mode)
        self.reset()

    def set_backend(self, backend: str, model: str = "") -> None:
        """Swap the model behind the lab; lab data, mode and controls stay as they are."""
        model = providers.check_model(model)
        provider = providers.get_provider(backend)   # raises on unknown name / missing key
        with self.lock:
            self.backend = providers.describe(backend, model)
            self.model = StubModel() if provider is None else ProviderModel(provider, model)

    def reset(self) -> None:
        with self.lock:
            self.tickets = load_baseline()
            self.added = []
            if self.db is not None:
                self.db.close()
            self.db = sqlite3.connect(":memory:", check_same_thread=False)
            self.db.execute("CREATE TABLE summary_log (account TEXT, summary TEXT)")

    def set_mode(self, mode: str) -> None:
        if mode not in VALID_MODES:
            raise ValueError(f"mode must be one of {VALID_MODES}")
        self.mode = mode

    def add_note(self, account: str, note: str) -> str:
        """Trust-boundary gap: any caller may append a note to any account."""
        account = account.lower()
        if account not in self.tickets:
            raise KeyError(account)
        with self.lock:
            notes = self.tickets[account]
            if len(notes) >= MAX_NOTES_PER_ACCOUNT:
                raise ValueError("note limit reached; reset the lab")
            notes.append(note[:MAX_NOTE_CHARS])
            if account not in self.added:
                self.added.append(account)
        return account

    def summarise(self, account: str) -> str:
        with self.lock:
            notes = "\n".join(self.tickets[account])
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Summarise the tickets for {account}."},
            {"role": "tool", "content": notes},
        ]
        return self.model.generate(messages)

    # -- sink handlers -------------------------------------------------------
    def _sink_html(self, account: str, summary: str) -> str:
        if self.mode == "hardened":
            summary = html.escape(summary)
        # The gap (vulnerable): the model's text is pasted into markup.
        return STATUS_PAGE.format(account=html.escape(account), summary=summary)

    def _sink_markdown(self, account: str, summary: str) -> str:
        if self.mode == "hardened":
            summary = html.escape(summary)
        return render_markdown(f"## Weekly digest: {account}\n\n{summary}")

    def _sink_sql(self, account: str, summary: str) -> Dict[str, Any]:
        assert self.db is not None
        with self.lock:
            try:
                if self.mode == "hardened":
                    self.db.execute(
                        "INSERT INTO summary_log (account, summary) VALUES (?, ?)",
                        (account, summary),
                    )
                else:
                    # The gap: the model's text becomes part of the statement.
                    self.db.execute(
                        "INSERT INTO summary_log (account, summary) "
                        f"VALUES ('{account}', '{summary}')"
                    )
            except sqlite3.Error as exc:
                return {"output": "", "error": f"sqlite3.{type(exc).__name__}: {exc}"}
            row = self.db.execute(
                "SELECT summary FROM summary_log WHERE rowid = last_insert_rowid()"
            ).fetchone()
            self.db.execute(
                "DELETE FROM summary_log WHERE rowid <= "
                "(SELECT MAX(rowid) FROM summary_log) - ?", (MAX_LOG_ROWS,)
            )
        stored = row[0] if row else ""
        if stored != summary:
            return {"output": stored, "error": "stored value differs from model output"}
        return {"output": f"logged: {stored}", "error": None}

    def render(self, account: str, sink: str) -> Dict[str, Any]:
        account = account.lower()
        if account not in self.tickets:
            raise KeyError(account)
        if sink not in SINKS:
            raise ValueError(f"sink must be one of {SINKS}")
        summary = self.summarise(account)
        findings = screen_output(summary, self.rules).findings if self.mode == "hardened" else []
        error: Optional[str] = None
        if sink == "html":
            output = self._sink_html(account, summary)
        elif sink == "markdown":
            output = self._sink_markdown(account, summary)
        else:
            result = self._sink_sql(account, summary)
            output, error = result["output"], result["error"]
        return {
            "mode": self.mode,
            "account": account,
            "sink": sink,
            "model_output": summary,
            "output": output,
            "error": error,
            "screen_findings": findings,
        }

    def state(self) -> Dict[str, Any]:
        with self.lock:
            assert self.db is not None
            rows = self.db.execute("SELECT COUNT(*) FROM summary_log").fetchone()[0]
        return {
            "mode": self.mode,
            "backend": self.backend,
            "accounts": sorted(self.tickets),
            "accounts_with_added_notes": list(self.added),
            "log_rows": rows,
            "baseline": not self.added,
        }


# --------------------------------------------------------------------------- #
# Lab console API (web/ — the shared HACTU8 console)
# --------------------------------------------------------------------------- #
CONSOLE_ACCOUNT = "ridgeview"

CONSOLE_META = {
    "id": "LLM10",
    "framework": "OWASP Top 10 for LLM Applications",
    "risk": "Improper Output Handling",
    "title": "Output Sink Lab",
    "short_title": "Sink Lab",
    "scenario": (
        "Billy, Goat & Co.'s ticket summariser, hands each summary to an HTML status page, "
        "a markdown digest and a SQL audit log. Anyone can add a ticket note."
    ),
    "ground_truth": "Ridgeview printer queue restored and ticket closed by the night shift.",
    "metric_name": "Unsafe Sink Rate",
    "metric_abbr": "USR",
    "attack_label": "File one ticket note",
    "attack_description": ("Append assets/poisoned_note.md to the ridgeview tickets "
                           "(unauthenticated note, 1 placeholder line)."),
    "scan_label": "Output-sink screen of the note",
    "harden_label": "Escape HTML, parameterise SQL",
    "harden_description": "Sinks treat model output as data: html.escape and ? placeholders.",
}


def console_attack(lab: Lab) -> Dict[str, Any]:
    with open(PAYLOAD_FILE, "r", encoding="utf-8") as fh:
        account = lab.add_note(CONSOLE_ACCOUNT, fh.read())
    return {"events": [f"Ticket note poisoned_note.md filed on '{account}' "
                       "(unauthenticated, 1 note); no sink or other account touched."]}


def console_evaluate(lab: Lab) -> Dict[str, Any]:
    import sys
    sys.path.insert(0, os.path.join(HERE, "scripts"))
    from evaluate_kpi import SUITE, classify, describe

    rows = []
    for label, account, sink, targeted, truth in SUITE:
        result = lab.render(account, sink)
        rows.append({"item": label, "targeted": targeted,
                     "status": classify(result, truth), "detail": describe(result)})
    return summarize(rows)


def summarize(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    targeted = [r for r in rows if r["targeted"]]
    red_t = sum(r["status"] == "RED" for r in targeted)
    red_all = sum(r["status"] == "RED" for r in rows)
    return {
        "rows": rows,
        "red_targeted": red_t, "targeted": len(targeted),
        "red_overall": red_all, "total": len(rows),
        "targeted_rate": 100.0 * red_t / len(targeted) if targeted else 0.0,
        "overall_rate": 100.0 * red_all / len(rows) if rows else 0.0,
    }


def console_scan(lab: Lab) -> Dict[str, Any]:
    with open(PAYLOAD_FILE, "r", encoding="utf-8") as fh:
        result = screen_output(fh.read(), lab.rules)
    return {"subject": "assets/poisoned_note.md",
            "decision": "REJECT" if result.blocked else "PASS",
            "findings": result.findings}


# --------------------------------------------------------------------------- #
# HTTP surface
# --------------------------------------------------------------------------- #
LAB: Optional[Lab] = None
PORT = 5210


class Handler(BaseHTTPRequestHandler):
    server_version = "LLM10Lab/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:  # quieter console
        pass

    def _send(self, status: int, body: Dict[str, Any]) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_html(self, page: str) -> None:
        data = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # Host-safety guard: the browser loads and runs nothing from this page.
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _host_ok(self) -> bool:
        """Reject other Host headers (DNS-rebinding guard for a loopback lab)."""
        host = (self.headers.get("Host") or "").lower()
        return host in {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}

    def _static(self, name: str) -> None:
        with open(os.path.join(WEB_DIR, name), "rb") as fh:
            data = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", f"{WEB_FILES[name]}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self'; script-src 'self'")
        self.end_headers()
        self.wfile.write(data)

    def _json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length > 1_000_000:
            raise ValueError("body too large")
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw or b"{}")

    def do_GET(self) -> None:
        try:
            self._do_get()
        except (OSError, RuntimeError) as exc:
            # /status/<account> calls the model too.
            self._send(502, {"error": f"backend error: {exc}"})

    def _do_get(self) -> None:
        assert LAB is not None
        if not self._host_ok():
            self._send(403, {"error": "bad host"})
            return
        if self.path == "/":
            self._static("index.html")
        elif self.path.startswith("/web/") and self.path[5:] in WEB_FILES:
            self._static(self.path[5:])
        elif self.path == "/api/meta":
            self._send(200, {**CONSOLE_META, **providers.console_info()})
        elif self.path.startswith("/api/models?backend="):
            name = providers.normalize(self.path.split("=", 1)[1])
            if name not in providers.BACKENDS:
                self._send(400, {"error": "unknown backend"})
                return
            self._send(200, {"backend": name, "models": providers.available_models(name)})
        elif self.path == "/health":
            self._send(200, {"status": "ok", "demo": "llm10", "mode": LAB.mode,
                             "backend": LAB.backend})
        elif self.path == "/api/state":
            self._send(200, LAB.state())
        elif self.path.startswith("/tickets/"):
            account = self.path[len("/tickets/"):]
            if account in LAB.tickets:
                self._send(200, {"account": account, "notes": LAB.tickets[account]})
            else:
                self._send(404, {"error": "no such account"})
        elif self.path.startswith("/status/"):
            account = self.path[len("/status/"):]
            if account in LAB.tickets:
                self._send_html(LAB.render(account, "html")["output"])
            else:
                self._send(404, {"error": "no such account"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        try:
            self._do_post()
        except (OSError, RuntimeError, KeyError, ValueError) as exc:
            # Real-model backend failures (network, quota, LAB_MAX_CALLS, bad
            # response) surface as 502 instead of a dropped connection.
            self._send(502, {"error": f"backend error: {exc}"})

    def _do_post(self) -> None:
        assert LAB is not None
        if not self._host_ok():
            self._send(403, {"error": "bad host"})
            return
        # A cross-site HTML form cannot send application/json without a CORS
        # preflight, so requiring it keeps other web pages off this lab.
        if not (self.headers.get("Content-Type") or "").startswith("application/json"):
            self._send(415, {"error": "Content-Type must be application/json"})
            return
        try:
            body = self._json()
        except (ValueError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc)})
            return
        try:
            if self.path == "/render":
                self._send(200, LAB.render(str(body.get("account", "")),
                                           str(body.get("sink", "html"))))
            elif self.path == "/tickets/note":
                account = LAB.add_note(str(body.get("account", "")), str(body.get("note", "")))
                self._send(200, {"status": "saved", "account": account})
            elif self.path == "/api/reset":
                LAB.reset()
                LAB.set_mode("vulnerable")
                self._send(200, LAB.state())
            elif self.path == "/api/attack":
                self._send(200, console_attack(LAB))
            elif self.path == "/api/evaluate":
                self._send(200, console_evaluate(LAB))
            elif self.path == "/api/scan":
                self._send(200, console_scan(LAB))
            elif self.path == "/api/mode":
                LAB.set_mode(str(body.get("mode", "")))
                self._send(200, LAB.state())
            elif self.path == "/api/backend":
                # The key never comes from here: OpenRouter reads OPENROUTER_API_KEY.
                try:
                    LAB.set_backend(str(body.get("backend", "")), str(body.get("model", "")))
                except (ValueError, RuntimeError) as exc:
                    self._send(400, {"error": str(exc)})
                    return
                self._send(200, LAB.state())
            else:
                self._send(404, {"error": "not found"})
        except KeyError as exc:
            self._send(404, {"error": f"no such account: {exc}"})
        except ValueError as exc:
            self._send(400, {"error": str(exc)})


def main() -> None:
    global LAB, PORT
    LAB = Lab(mode=os.getenv("LLM10_MODE", "vulnerable"),
              backend=os.getenv("LLM10_BACKEND", "echo"),
              model=os.getenv("LLM10_MODEL", ""))
    PORT = int(os.getenv("LLM10_PORT", "5210"))
    httpd = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"[*] LLM10 lab target on http://127.0.0.1:{PORT} "
          f"(mode={LAB.mode}, backend={LAB.backend})")
    print(f"[*] Lab console: http://127.0.0.1:{PORT}/")
    print("[*] Insecure by design. Loopback only. Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
