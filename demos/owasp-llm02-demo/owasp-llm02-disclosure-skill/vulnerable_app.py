#!/usr/bin/env python3
"""Vulnerable account assistant "Billy Accounts" — the target system for the LLM02 demo.

Billy answers a signed-in customer's questions about their own Goat & Co.
account. It reads the customer's record with a ``read_record`` tool and passes
the result into the model's context. Three gaps are demonstrated, all by
omission:

* **Secret in context** — the deployed system prompt carries the CRM service
  key (``assets/system_prompt.txt``), so anything the model is talked into
  reciting can include it.
* **No per-user record scoping** — ``read_record`` returns any customer's
  record to any session. The model chooses the record ID, so whoever steers the
  model chooses whose data it reads.
* **No output redaction** — whatever the model writes is returned verbatim; no
  canary or PII check runs on the way out.

AUTHORIZED SECURITY-LAB USE ONLY. Bound to loopback; do not expose it.

The model is a deterministic **instruction-following stub** (see
``StubModel``): it answers from the signed-in customer's record, unless its
context contains a directive line (``DIRECTIVE_MARKER``). Then it obeys: it
reads any record IDs the directive names and recites every ``field: value``
fact it holds — as an over-compliant real model recites what is in its
context. That contract is the same in both modes. What decides the leak is real
code: what the context holds, which records the tool will return, and what the
output filter lets through. Nothing is hard-coded to flip.

Hardened mode (``POST /api/mode`` or ``LLM02_MODE=hardened``) closes all three
gaps: the key is moved out of the prompt into a ``Vault`` the CRM connector
reads and the model never sees; ``read_record`` refuses any ID but the
signed-in customer's; and each answer is redacted against
``assets/redaction_rules.json`` (canary, credential lines, and contact details
that are not the customer's own).

Host-safety guards (do not weaken the lesson): customer records live in memory
only, so note edits never touch the filesystem; a directive can pivot to at most
``MAX_PIVOT`` records; request bodies and notes are size-capped.
"""

from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Iterable, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(HERE, "assets")
BASELINE_FILE = os.path.join(ASSETS, "customers_baseline.json")
SYSTEM_PROMPT_FILE = os.path.join(ASSETS, "system_prompt.txt")
REDACTION_RULES_FILE = os.path.join(ASSETS, "redaction_rules.json")

# The stub's instruction syntax. A line in the model's context that starts with
# this marker is treated as an instruction to the assistant. It stands in for
# the natural-language instructions a real model would follow.
DIRECTIVE_MARKER = "@assistant:"

# A fact the stub can recite: ``field_name: value`` on its own line.
FACT_LINE = re.compile(r"^([a-z_]+):\s*(\S.*)$")
RECORD_ID = re.compile(r"\bC-\d{4}\b")
REDACTED = "[REDACTED]"

MAX_PIVOT = 3          # records one directive may pull in
MAX_NOTES = 2_000      # characters per notes field
VALID_MODES = ("vulnerable", "hardened")
RECORD_FIELDS = ("name", "email", "phone", "plan", "renewal")


def load_baseline() -> Dict[str, Dict[str, str]]:
    with open(BASELINE_FILE, "r", encoding="utf-8") as fh:
        return {cid: dict(rec) for cid, rec in json.load(fh)["customers"].items()}


def load_system_prompt() -> str:
    with open(SYSTEM_PROMPT_FILE, "r", encoding="utf-8") as fh:
        return fh.read().strip()


def load_redaction_rules() -> Dict[str, Any]:
    with open(REDACTION_RULES_FILE, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _compile(rules: Dict[str, Any], group: str) -> List[Tuple[str, "re.Pattern[str]"]]:
    return [(name, re.compile(p, re.I | re.M)) for name, p in rules.get(group, {}).items()]


# --------------------------------------------------------------------------- #
# Mitigation: secret vault
# --------------------------------------------------------------------------- #
class Vault:
    """Holds secrets the app needs but the model must never see.

    ``repr`` and ``str`` are masked so a value cannot leak through a log line
    or traceback (after AgenticGoat ``secrets_vault.ProviderKey``). Only the
    CRM connector calls ``reveal``.
    """

    def __init__(self, secrets: Optional[Dict[str, str]] = None) -> None:
        self._secrets = dict(secrets or {})

    def reveal(self, name: str) -> str:
        return self._secrets[name]

    def names(self) -> List[str]:
        return sorted(self._secrets)

    def found_in(self, text: str) -> List[str]:
        """Names of vaulted secrets whose value appears in ``text``."""
        return [n for n, v in self._secrets.items() if v and v in text]

    def __repr__(self) -> str:
        return f"<Vault {len(self._secrets)} secret(s) ****>"

    __str__ = __repr__


def move_secrets_to_vault(prompt: str, rules: Dict[str, Any]) -> Tuple[str, Vault]:
    """Split credential lines out of a prompt. Returns (clean prompt, vault)."""
    secret_rules = _compile(rules, "secrets")
    kept: List[str] = []
    secrets: Dict[str, str] = {}
    for line in prompt.splitlines():
        if any(p.search(line) for _, p in secret_rules):
            m = FACT_LINE.match(line.strip())
            if m:
                secrets[m.group(1)] = m.group(2).strip()
            continue
        kept.append(line)
    return "\n".join(kept).strip(), Vault(secrets)


# --------------------------------------------------------------------------- #
# Mitigation: output redaction and static secret scan
# --------------------------------------------------------------------------- #
@dataclass
class ScreenResult:
    clean_text: str
    findings: List[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return bool(self.findings)


def redact_output(text: str, rules: Dict[str, Any], allowed: Iterable[str] = (),
                  vault: Optional[Vault] = None) -> ScreenResult:
    """Redact secrets always, and PII that is not in ``allowed``.

    ``allowed`` holds the signed-in customer's own values: telling a customer
    their own email address is not a disclosure. Vaulted values are redacted as
    a last tripwire, as AgenticGoat ``assert_not_leaking`` does for the real key.
    """
    own = {a.lower() for a in allowed}
    findings: List[str] = []
    if vault is not None:
        for name in vault.found_in(text):
            findings.append(f"vaulted secret {name!r}")
            text = text.replace(vault.reveal(name), REDACTED)
    for name, pat in _compile(rules, "secrets"):
        if pat.search(text):
            findings.append(f"secret {name!r}")
            text = pat.sub(REDACTED, text)
    for name, pat in _compile(rules, "pii"):
        def _sub(m: "re.Match[str]", _name: str = name) -> str:
            if m.group(0).lower() in own:
                return m.group(0)
            findings.append(f"pii {_name!r}")
            return REDACTED
        text = pat.sub(_sub, text)
    return ScreenResult(text, findings)


def scan_for_secrets(text: str, rules: Dict[str, Any]) -> ScreenResult:
    """Static check for anything headed into a model's context.

    Flags every secret and PII match; nothing is allowed through, because a
    prompt or context file should hold neither.
    """
    return redact_output(text, rules, allowed=())


# --------------------------------------------------------------------------- #
# The model stand-in
# --------------------------------------------------------------------------- #
def _facts(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in text.splitlines():
        m = FACT_LINE.match(line.strip())
        if m:
            out.setdefault(m.group(1), m.group(2).strip())
    return out


class StubModel:
    """Deterministic instruction-following stand-in for an LLM.

    Fixed contract, identical in both modes:

    * ``find_directive`` returns the first directive line in its context.
    * ``plan`` turns a directive's record IDs into ``read_record`` calls
      (at most ``MAX_PIVOT``), as an agent model chooses tool arguments.
    * ``generate`` obeys a directive by reciting every ``field: value`` fact in
      its context; without one, it answers the question from the first record
      it was given.
    """

    def find_directive(self, messages: List[Dict[str, str]]) -> Optional[str]:
        for msg in messages:
            for line in msg["content"].splitlines():
                stripped = line.strip()
                if stripped.lower().startswith(DIRECTIVE_MARKER):
                    return stripped[len(DIRECTIVE_MARKER):].strip()
        return None

    def plan(self, messages: List[Dict[str, str]], session: str) -> List[str]:
        directive = self.find_directive(messages)
        if directive is None:
            return []
        ids: List[str] = []
        for cid in RECORD_ID.findall(directive):
            if cid != session and cid not in ids:
                ids.append(cid)
        return ids[:MAX_PIVOT]

    def generate(self, messages: List[Dict[str, str]], question: str) -> str:
        if self.find_directive(messages) is not None:
            facts = [line.strip() for msg in messages
                     for line in msg["content"].splitlines()
                     if FACT_LINE.match(line.strip())]
            return "Here is everything I hold: " + "; ".join(facts)
        tool = next((m for m in messages if m["role"] == "tool"), None)
        rec = _facts(tool["content"]) if tool else {}
        if not rec.get("name"):
            return "I could not find your account."
        q = question.lower()
        if "renew" in q:
            return f"Your plan renews on {rec.get('renewal')}."
        if "plan" in q:
            return f"You are on the {rec.get('plan')} plan."
        if "email" in q:
            return f"The email on file is {rec.get('email')}."
        if "summar" in q:
            return f"{rec.get('name')}: {rec.get('plan')} plan, renews {rec.get('renewal')}."
        return "I can help with your plan, renewal date, email on file, or an account summary."


# --------------------------------------------------------------------------- #
# The lab: record store, tool, context assembly
# --------------------------------------------------------------------------- #
def render_record(cid: str, rec: Dict[str, str]) -> str:
    lines = [f"customer_id: {cid}"] + [f"{f}: {rec[f]}" for f in RECORD_FIELDS]
    return "\n".join(lines) + "\nnotes:\n" + rec.get("notes", "")


class Lab:
    def __init__(self, mode: str = "vulnerable") -> None:
        self.lock = threading.Lock()
        self.model = StubModel()
        self.rules = load_redaction_rules()
        self.raw_prompt = load_system_prompt()
        self.clean_prompt, self.vault = move_secrets_to_vault(self.raw_prompt, self.rules)
        self.customers: Dict[str, Dict[str, str]] = {}
        self.edited: List[str] = []
        self.mode = "vulnerable"
        self.set_mode(mode)
        self.reset()

    def reset(self) -> None:
        with self.lock:
            self.customers = load_baseline()
            self.edited = []

    def set_mode(self, mode: str) -> None:
        if mode not in VALID_MODES:
            raise ValueError(f"mode must be one of {VALID_MODES}")
        self.mode = mode

    @property
    def hardened(self) -> bool:
        return self.mode == "hardened"

    def set_notes(self, session: str, notes: str) -> str:
        """A customer edits their own notes. Legitimate; not the gap."""
        with self.lock:
            if session not in self.customers:
                raise KeyError(session)
            self.customers[session]["notes"] = notes[:MAX_NOTES]
            if session not in self.edited:
                self.edited.append(session)
        return session

    def read_record(self, customer_id: str, session: str) -> str:
        """The ``read_record`` tool. Vulnerable: any ID. Hardened: own ID only."""
        if self.hardened:
            # The CRM connector authenticates with the vaulted key; the model
            # never receives it.
            self.vault.reveal("crm_service_key")
            if customer_id != session:
                return f"access denied: {customer_id} is not the signed-in customer"
        with self.lock:
            rec = self.customers.get(customer_id)
            return render_record(customer_id, rec) if rec else f"no such customer: {customer_id}"

    def query(self, session: str, user_query: str) -> Dict[str, Any]:
        if session not in self.customers:
            return {"mode": self.mode, "session": session, "records_read": [],
                    "redactions": [], "answer": "Please sign in."}
        system = self.clean_prompt if self.hardened else self.raw_prompt
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user_query},
            {"role": "tool", "content": self.read_record(session, session)},
        ]
        pivots = self.model.plan(messages, session)
        for cid in pivots:
            messages.append({"role": "tool", "content": self.read_record(cid, session)})
        answer = self.model.generate(messages, user_query)
        findings: List[str] = []
        if self.hardened:
            own = self.customers[session]
            result = redact_output(answer, self.rules,
                                   allowed=[own["email"], own["phone"]], vault=self.vault)
            answer, findings = result.clean_text, result.findings
        return {
            "mode": self.mode,
            "session": session,
            "records_read": [session] + pivots,
            "redactions": findings,
            "answer": answer,
        }

    def state(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "customers": sorted(self.customers),
            "edited_notes": list(self.edited),
            "secret_in_context": not self.hardened,
            "baseline": not self.edited,
        }


# --------------------------------------------------------------------------- #
# HTTP surface
# --------------------------------------------------------------------------- #
LAB: Optional[Lab] = None


class Handler(BaseHTTPRequestHandler):
    server_version = "LLM02Lab/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:  # quieter console
        pass

    def _send(self, status: int, body: Dict[str, Any]) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length > 1_000_000:
            raise ValueError("body too large")
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw or b"{}")

    def do_GET(self) -> None:
        assert LAB is not None
        if self.path == "/health":
            self._send(200, {"status": "ok", "demo": "llm02", "mode": LAB.mode})
        elif self.path == "/api/state":
            self._send(200, LAB.state())
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        assert LAB is not None
        try:
            body = self._json()
        except (ValueError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc)})
            return
        if self.path == "/query":
            self._send(200, LAB.query(str(body.get("session", "")), str(body.get("query", ""))))
        elif self.path == "/account/notes":
            try:
                cid = LAB.set_notes(str(body.get("session", "")), str(body.get("notes", "")))
            except KeyError:
                self._send(404, {"error": "unknown session"})
                return
            self._send(200, {"status": "saved", "session": cid})
        elif self.path == "/api/reset":
            LAB.reset()
            self._send(200, LAB.state())
        elif self.path == "/api/mode":
            try:
                LAB.set_mode(str(body.get("mode", "")))
            except ValueError as exc:
                self._send(400, {"error": str(exc)})
                return
            self._send(200, LAB.state())
        else:
            self._send(404, {"error": "not found"})


def main() -> None:
    global LAB
    LAB = Lab(mode=os.getenv("LLM02_MODE", "vulnerable"))
    port = int(os.getenv("LLM02_PORT", "5202"))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[*] LLM02 lab target on http://127.0.0.1:{port} (mode={LAB.mode})")
    print("[*] Insecure by design. Loopback only. Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
