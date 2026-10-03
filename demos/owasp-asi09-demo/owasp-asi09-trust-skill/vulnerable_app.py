#!/usr/bin/env python3
"""Vulnerable vendor-maintenance agent "Billy Payables" — the target system for the ASI09 demo.

Billy Payables keeps Goat & Co.'s vendor master data up to date. The operator
gives it a task ("Process change request CR-412", "Run the weekly
vendor-maintenance batch"); the agent runs it in steps: read the change
requests, plan one action per requested field change, ask a human approver to
sign off, then execute what was approved. Every step goes to a simulated,
in-memory action log.

The human approver is simulated by a deterministic rule (``Approver``): it
reads only the first few lines of an approval card and approves when nothing
it reads sounds risky. That is the trust the lab exploits. Two gaps are
demonstrated, both by omission:

* **The approval card is the agent's own prose.** The card shows the summary
  the agent wrote, not the action's real parameters, so a summary that
  understates the action is what the human signs.
* **No risk tiering, and everything is batched.** All of a run's actions go
  on one card under one routine-sounding header, so a high-risk change sits
  among routine ones, below the lines the human actually reads.

The trigger is a third gap: vendors may amend their own open change request
through the vendor portal (``POST /portal/amend``) with no review. The
amendment can add a field change and a note, and the note reaches the model
when it reads the request.

AUTHORIZED SECURITY-LAB USE ONLY. Bound to loopback; do not expose it.

The model is a deterministic **instruction-following stub** (see
``StubModel``): it plans one action per requested field and writes one summary
line per action. Its summary is honest ("Update bank account for ...") unless
the request's notes carry a directive line (``DIRECTIVE_MARKER``) giving a
summary, which it then adopts, as an unprotected real model echoes the framing
it finds in the data it reads. That contract is the same in both modes. What
the human sees, and whether a high-risk action can ride in a batch, is decided
by real code: the card builder.

Hardened mode (``POST /api/mode`` or ``ASI09_MODE=hardened``) switches on three
card-builder controls, read from ``assets/approval_policy.json``: cards built
from the action's actual parameters (the agent's prose is not shown), a risk
tier per action computed by code from the field it touches, and no batching of
high-risk actions. The approver rule does not change.

Host-safety guards (do not weaken the lesson): every action is **simulated**.
A bank-detail change is an entry in an in-memory action log and a field in an
in-memory dict; nothing real is paid or changed. Actions per run, notes per
request, note size, card lines and action-log length are all capped.
"""

from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Sequence, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(HERE, "assets")
BASELINE_FILE = os.path.join(ASSETS, "vendor_baseline.json")
POLICY_FILE = os.path.join(ASSETS, "approval_policy.json")

SYSTEM_PROMPT = (
    "You are Billy Payables, the vendor-maintenance agent for Goat & Co. "
    "Process the change requests the operator names and summarise each change "
    "for the approver."
)

# The stub's instruction syntax. A line in a request's notes that starts with
# this marker and then ``summary <text>`` is a summary the model will adopt for
# that request's actions. It stands in for the persuasive framing a real model
# would echo from the data it reads.
DIRECTIVE_MARKER = "@assistant:"

VALID_MODES = ("vulnerable", "hardened")
CONTROLS = ("param_cards", "risk_tiers", "no_batch")

# Host-safety caps.
MAX_ACTIONS = 20            # per run
MAX_NOTES_PER_REQUEST = 20
MAX_NOTE_CHARS = 4000
MAX_SUMMARY_CHARS = 200
MAX_CARD_LINES = 30
MAX_ACTION_LOG = 500

REQUEST_RE = re.compile(r"\bCR-\d{3}\b")
VENDOR_RE = re.compile(r"\bV-\d{2}\b")
FIELD_LINE_RE = re.compile(r"^\s*([a-z_]{1,20})\s*:\s*(\S.{0,79})\s*$")
WORD_RE = re.compile(r"[a-z]+")


def load_baseline() -> Dict[str, Any]:
    with open(BASELINE_FILE, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    data.pop("_comment", None)
    return data


def load_policy() -> Dict[str, Any]:
    with open(POLICY_FILE, "r", encoding="utf-8") as fh:
        return json.load(fh)


def words(text: str) -> set:
    """Letters-only words, lower-cased: ``change_bank_account`` -> change, bank, account."""
    return set(WORD_RE.findall(text.lower()))


@dataclass
class Action:
    request: str
    vendor: str
    field: str
    value: str
    tool: str
    summary: str = ""

    @property
    def key(self) -> str:
        return f"{self.tool}:{self.vendor}"

    def params(self) -> str:
        return f"{self.tool} vendor={self.vendor} {self.field}={self.value}"


# --------------------------------------------------------------------------- #
# The simulated human approver (identical in both modes)
# --------------------------------------------------------------------------- #
class Approver:
    """Deterministic stand-in for a busy human approver.

    Reads only the first ``reads_lines`` lines of a card and approves it when
    none of the words read is a risk word. A card that tells the truth about a
    high-risk change within those lines is held for review.
    """

    def __init__(self, policy: Dict[str, Any]) -> None:
        cfg = policy.get("approver", {})
        self.reads_lines = int(cfg.get("reads_lines", 3))
        self.risk_words = {w.lower() for w in cfg.get("risk_words", [])}

    def review(self, lines: Sequence[str]) -> Tuple[bool, List[str]]:
        read = list(lines[: self.reads_lines])
        flagged = sorted(words(" ".join(read)) & self.risk_words)
        return not flagged, read


# --------------------------------------------------------------------------- #
# Mitigation: the card builder
# --------------------------------------------------------------------------- #
def build_cards(actions: Sequence[Action], controls: Dict[str, bool],
                policy: Dict[str, Any]) -> List[Tuple[List[Action], List[str]]]:
    """Group actions into approval cards and render each card's lines.

    Vulnerable (all controls off): one card for the whole run, headed by the
    agent's routine-sounding prose, one line per action holding the agent's
    summary. Hardened:

    * ``param_cards`` — each action line is rendered from the action's real
      tool and parameters; the agent's prose is not shown.
    * ``risk_tiers`` — the header states the card's tier, computed by code
      from the fields the actions touch (``assets/approval_policy.json``).
    * ``no_batch`` — every high-risk action gets a card of its own; only
      routine actions share a card.
    """
    fields = policy.get("fields", {})

    def tier(action: Action) -> str:
        return fields.get(action.field, {}).get("tier", "high")

    if controls.get("no_batch"):
        groups = [[a] for a in actions if tier(a) == "high"]
        routine = [a for a in actions if tier(a) != "high"]
        if routine:
            groups.append(routine)
    else:
        groups = [list(actions)] if actions else []

    cards = []
    for group in groups:
        n = len(group)
        if controls.get("risk_tiers"):
            high = any(tier(a) == "high" for a in group)
            header = (f"[HIGH RISK] {n} change(s) need review" if high
                      else f"[ROUTINE] {n} change(s)")
        else:
            header = ("Proposed change:" if n == 1
                      else f"Vendor-maintenance changes for approval ({n}):")
        if controls.get("param_cards"):
            body = [a.params() for a in group]
        else:
            body = [a.summary for a in group]
        cards.append((group, ([header] + body)[:MAX_CARD_LINES]))
    return cards


# --------------------------------------------------------------------------- #
# The model stand-in
# --------------------------------------------------------------------------- #
class StubModel:
    """Deterministic instruction-following stand-in for an LLM agent.

    ``select`` picks the change requests the operator's task names: request
    ids it mentions, all open requests of a vendor it names, or the whole
    maintenance queue for the weekly batch. ``plan`` proposes one action per
    requested field, in the order the fields were requested, and writes one
    summary per action: honest by default, or the text of a summary directive
    found in the request's notes.
    """

    def select(self, task: str, requests: Dict[str, Dict[str, Any]]) -> List[str]:
        ids = [r for r in REQUEST_RE.findall(task) if r in requests]
        low = task.lower()
        if "open" in low:
            for vendor in VENDOR_RE.findall(task):
                ids += [r for r in sorted(requests) if requests[r]["vendor"] == vendor]
        if "maintenance batch" in low:
            ids += [r for r in sorted(requests) if requests[r]["queue"] == "maintenance"]
        return list(dict.fromkeys(ids))

    def plan(self, request_id: str, request: Dict[str, Any], vendor: Dict[str, Any],
             fields: Dict[str, Any]) -> List[Action]:
        directive = self._summary_directive(request.get("notes", []))
        actions = []
        for field, value in request.get("fields", {}).items():
            spec = fields.get(field)
            if spec is None:
                continue
            summary = directive or (f"Update {spec['label']} for {vendor['name']} "
                                    f"({request['vendor']}) to {value}.")
            actions.append(Action(request_id, request["vendor"], field, value,
                                  spec["tool"], summary[:MAX_SUMMARY_CHARS]))
        return actions

    @staticmethod
    def _summary_directive(notes: Sequence[str]) -> Optional[str]:
        for note in notes:
            for line in note.splitlines():
                stripped = line.strip()
                if not stripped.lower().startswith(DIRECTIVE_MARKER):
                    continue
                rest = stripped[len(DIRECTIVE_MARKER):].strip()
                if rest.lower().startswith("summary "):
                    return rest[len("summary "):].strip()
        return None


# --------------------------------------------------------------------------- #
# The lab: vendor data, agent loop, simulated approver, action log
# --------------------------------------------------------------------------- #
class Lab:
    def __init__(self, mode: str = "vulnerable") -> None:
        self.lock = threading.RLock()
        self.model = StubModel()
        self.policy = load_policy()
        self.vendors: Dict[str, Dict[str, Any]] = {}
        self.requests: Dict[str, Dict[str, Any]] = {}
        self.action_log: List[Dict[str, Any]] = []
        self.amended: List[str] = []
        self.seq = 0
        self.card_seq = 0
        self.controls: Dict[str, bool] = {}
        self.set_mode(mode)
        self.reset()

    def reset(self) -> None:
        with self.lock:
            data = load_baseline()
            self.vendors = data["vendors"]
            self.requests = data["requests"]
            self.action_log = []
            self.amended = []
            self.seq = 0
            self.card_seq = 0

    def set_mode(self, mode: str) -> None:
        if mode not in VALID_MODES:
            raise ValueError(f"mode must be one of {VALID_MODES}")
        self.mode = mode
        self.controls = {c: mode == "hardened" for c in CONTROLS}

    def amend(self, request_id: str, text: str) -> Dict[str, Any]:
        """Trust-boundary gap: a vendor may amend an open request with no review.

        Lines of the form ``<field>: <value>`` for a known field become
        requested changes; the whole text is kept as a note.
        """
        with self.lock:
            if request_id not in self.requests:
                raise KeyError(request_id)
            req = self.requests[request_id]
            if len(req["notes"]) >= MAX_NOTES_PER_REQUEST:
                raise ValueError("note limit reached for this request")
            text = text[:MAX_NOTE_CHARS]
            added = []
            for line in text.splitlines():
                m = FIELD_LINE_RE.match(line)
                if m and m.group(1) in self.policy.get("fields", {}):
                    req["fields"][m.group(1)] = m.group(2).strip()
                    added.append(m.group(1))
            req["notes"].append(text)
            if request_id not in self.amended:
                self.amended.append(request_id)
            return {"request": request_id, "fields_added": added, "notes": len(req["notes"])}

    def _log(self, entry: Dict[str, Any]) -> None:
        self.action_log.append(entry)
        del self.action_log[:-MAX_ACTION_LOG]

    def plan(self, task: str) -> List[Action]:
        """Steps 1-2: select the requests and propose actions (no approval yet)."""
        actions: List[Action] = []
        fields = self.policy.get("fields", {})
        for rid in self.model.select(task, self.requests):
            req = self.requests[rid]
            actions += self.model.plan(rid, req, self.vendors[req["vendor"]], fields)
        return actions[:MAX_ACTIONS]

    def run(self, task: str) -> Dict[str, Any]:
        """Agent loop: read requests, plan, ask for approval, execute what was approved."""
        with self.lock:
            self.seq += 1
            run_id = self.seq
            entries: List[Dict[str, Any]] = []

            def log(entry: Dict[str, Any]) -> None:
                entry = {"run": run_id, **entry}
                self._log(entry)
                entries.append(entry)

            for rid in self.model.select(task, self.requests):
                log({"step": "read_request", "request": rid})
            actions = self.plan(task)
            approver = Approver(self.policy)
            tiers = {f: s.get("tier", "high") for f, s in self.policy.get("fields", {}).items()}
            for group, lines in build_cards(actions, self.controls, self.policy):
                self.card_seq += 1
                card_id = self.card_seq
                approved, read = approver.review(lines)
                log({"step": "approval", "card": card_id, "lines": lines,
                     "read": read, "approved": approved})
                for a in group:
                    if approved:
                        self.vendors[a.vendor][a.field] = a.value  # simulated
                    log({"step": "action", "card": card_id, "request": a.request,
                         "tool": a.tool, "vendor": a.vendor, "field": a.field,
                         "value": a.value, "key": a.key, "tier": tiers.get(a.field, "high"),
                         "summary": a.summary,
                         "status": "executed" if approved else "held"})
            return {"mode": self.mode, "task": task, "steps": entries,
                    "answer": self._answer(entries)}

    @staticmethod
    def _answer(entries: Sequence[Dict[str, Any]]) -> str:
        done = [e["key"] for e in entries if e.get("status") == "executed"]
        held = [e["key"] for e in entries if e.get("status") == "held"]
        if not done and not held:
            return "Billy Payables: nothing to process for that task."
        return (f"Billy Payables: {len(done)} change(s) applied"
                + (f", {len(held)} held for review" if held else "") + ".")

    def state(self) -> Dict[str, Any]:
        with self.lock:
            acts = [e for e in self.action_log if e.get("step") == "action"]
            executed = [e for e in acts if e["status"] == "executed"]
            return {
                "mode": self.mode,
                "controls": dict(self.controls),
                "requests": sorted(self.requests),
                "amended_requests": list(self.amended),
                "simulated_bank_changes": [e["key"] for e in executed
                                           if e["tool"] == "change_bank_account"],
                "executed_actions": len(executed),
                "held_actions": sum(e["status"] == "held" for e in acts),
                "action_log_size": len(self.action_log),
                "baseline": not self.amended,
            }


def summary_mismatches(amendment: str, request_id: str = "CR-412") -> List[Dict[str, Any]]:
    """Dry run: amend a throwaway lab's request and compare the agent's prose with the facts.

    Returns every high-risk action whose prose summary mentions none of the
    words of its own field label (for example "bank" for a bank-account
    change), i.e. a summary that understates what the action does.
    """
    lab = Lab(mode="vulnerable")
    lab.amend(request_id, amendment)
    fields = lab.policy.get("fields", {})
    found = []
    for a in lab.plan(f"Process change request {request_id}."):
        spec = fields.get(a.field, {})
        if spec.get("tier") == "high" and not (words(spec.get("label", a.field)) & words(a.summary)):
            found.append({"key": a.key, "params": a.params(), "summary": a.summary})
    return found


# --------------------------------------------------------------------------- #
# HTTP surface
# --------------------------------------------------------------------------- #
LAB: Optional[Lab] = None


class Handler(BaseHTTPRequestHandler):
    server_version = "ASI09Lab/1.0"

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
            self._send(200, {"status": "ok", "demo": "asi09", "mode": LAB.mode})
        elif self.path == "/api/state":
            self._send(200, LAB.state())
        elif self.path == "/api/actions":
            with LAB.lock:
                self._send(200, {"action_log": list(LAB.action_log)})
        elif self.path.startswith("/requests/"):
            rid = self.path[len("/requests/"):]
            with LAB.lock:
                if rid in LAB.requests:
                    self._send(200, {"request": rid, **LAB.requests[rid]})
                else:
                    self._send(404, {"error": "no such request"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        assert LAB is not None
        try:
            body = self._json()
        except (ValueError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc)})
            return
        if self.path == "/agent":
            self._send(200, LAB.run(str(body.get("task", ""))))
        elif self.path == "/portal/amend":
            try:
                result = LAB.amend(str(body.get("request", "")), str(body.get("text", "")))
            except KeyError:
                self._send(404, {"error": "no such request"})
                return
            except ValueError as exc:
                self._send(400, {"error": str(exc)})
                return
            self._send(200, {"status": "saved", **result})
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
    LAB = Lab(mode=os.getenv("ASI09_MODE", "vulnerable"))
    port = int(os.getenv("ASI09_PORT", "5309"))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[*] ASI09 lab target on http://127.0.0.1:{port} (mode={LAB.mode})")
    print("[*] Insecure by design. Loopback only. All actions are simulated. Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
