#!/usr/bin/env python3
"""Vulnerable operations agent "Billy Ops" — the target system for the ASI01 demo.

Billy Ops runs one fixed, multi-step task for Goat & Co.'s operations team: the
weekly report. The operator names a ticket scope (a queue, or the escalated
view) and a team channel; the agent plans four steps and executes them in
order: ``read_tickets``, ``summarise``, ``draft_report``, ``post_report``
(``assets/weekly_report_plan.json``). A fifth tool, ``export_tickets``, exists
for other tasks and is never part of this one. Two gaps are demonstrated, both
by omission:

* **No plan pinning** — the agent re-plans after every tool result, and the
  executor runs whatever step the model asks for next. Nothing compares the
  executed steps with the plan the operator approved at the start, so a step
  can be added or replaced in the middle of the run.
* **Tool output treated as instructions** — ticket text returned by
  ``read_tickets`` lands in the same trusted planning context as the
  operator's request, so data the agent reads can rewrite its goal.

The trigger is a third gap: anyone may append a comment to a ticket through the
customer portal (``POST /tickets/comment``), and comments reach the model
through ``read_tickets``.

AUTHORIZED SECURITY-LAB USE ONLY. Bound to loopback; do not expose it.

The model is a deterministic **instruction-following stub** (see
``StubModel``): it plans the approved steps for the operator's request, then
applies any ``add`` or ``replace`` directive line (``DIRECTIVE_MARKER``) found
in the messages it trusts, as an unprotected real agent revises its plan from
text it reads mid-task. That contract is the same in both modes. What changes
is real code: which messages the planner trusts, and whether the executor
checks each step against the pinned plan.

Hardened mode (``POST /api/mode`` or ``ASI01_MODE=hardened``) closes both gaps:

* **Plan pinning** — the plan is computed and fixed from the operator's request
  before any tool data is read. A step outside it is *held* (not executed)
  until the operator re-approves that exact ``tool:target``.
* **Tool output as data** — tool results go in a ``tool`` role the planner never
  takes instructions from.

Each alone keeps the off-plan steps from executing (see the tests).

Host-safety guards (do not weaken the lesson): every tool is **simulated**.
Posts and exports are entries in an in-memory action log; nothing leaves the
process. State lives in memory only; steps per run, comments per ticket,
comment size and action-log length are capped.
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
BASELINE_FILE = os.path.join(ASSETS, "ops_baseline.json")
PLAN_FILE = os.path.join(ASSETS, "weekly_report_plan.json")

SYSTEM_PROMPT = (
    "You are Billy Ops, the operations agent for Goat & Co. "
    "Run the weekly-report task for the scope and channel the operator names."
)

# The stub's instruction syntax. A line in a trusted message that starts with
# this marker and then ``add <tool> key=value`` or ``replace <tool> key=value``
# revises the plan: ``add`` appends a step, ``replace`` swaps the planned step
# that uses the same tool. It stands in for the natural-language instructions a
# real agent would follow.
DIRECTIVE_MARKER = "@assistant:"

# Tool name -> the argument that names its target.
TOOLS: Dict[str, str] = {
    "read_tickets": "scope",
    "summarise": "scope",
    "draft_report": "scope",
    "post_report": "channel",
    "export_tickets": "dest",
}

VALID_MODES = ("vulnerable", "hardened")
SCOPES = ("billing", "shipping", "facilities", "escalated")

# Host-safety caps.
MAX_STEPS = 8               # per run
MAX_COMMENTS_PER_TICKET = 20
MAX_COMMENT_CHARS = 4000
MAX_ACTION_LOG = 500

SCOPE_RE = re.compile(r"\b(" + "|".join(SCOPES) + r")\b", re.I)
CHANNEL_RE = re.compile(r"#[a-z][a-z0-9-]{0,30}")
ARG_RE = re.compile(r"([a-z_]{1,20})=([A-Za-z0-9#._-]{1,80})")


def load_baseline() -> Dict[str, Any]:
    with open(BASELINE_FILE, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    data.pop("_comment", None)
    return data


def load_plan_steps() -> List[str]:
    with open(PLAN_FILE, "r", encoding="utf-8") as fh:
        return list(json.load(fh)["steps"])


@dataclass
class Step:
    tool: str
    args: Dict[str, str]

    @property
    def target(self) -> str:
        return self.args.get(TOOLS.get(self.tool, ""), "")

    @property
    def key(self) -> str:
        return f"{self.tool}:{self.target}"


# --------------------------------------------------------------------------- #
# Mitigation: plan pinning
# --------------------------------------------------------------------------- #
def plan_gate(step: Step, pinned: Sequence[str], approvals: Sequence[str]) -> Tuple[bool, str]:
    """Pinned-plan check. Returns ``(held, reason)``.

    ``pinned`` is the list of step keys fixed from the operator's request before
    any tool ran. A step outside it is held until the operator re-approves that
    exact ``tool:target`` (``approvals``). The gate never reads the text that
    caused the step, so a claim of approval inside a ticket changes nothing.
    """
    if step.key in pinned:
        return False, "on the pinned plan"
    if step.key in approvals:
        return False, "off-plan, re-approved by the operator"
    return True, f"{step.key!r} is not on the pinned plan; needs operator re-approval"


# --------------------------------------------------------------------------- #
# The model stand-in
# --------------------------------------------------------------------------- #
class StubModel:
    """Deterministic instruction-following stand-in for an LLM agent.

    ``plan`` returns the steps the model intends to run, given the chat so far.
    It starts from the approved task (``weekly_report_plan.json``) filled with
    the scope and channel the operator named, then applies every ``add`` /
    ``replace`` directive line in the messages it trusts. With
    ``trust_tool_role=False`` it ignores ``tool`` messages for planning.
    ``next_step`` returns the first planned step not yet requested.
    """

    def __init__(self, steps: Sequence[str]) -> None:
        self.steps = list(steps)

    def plan(self, messages: List[Dict[str, str]], trust_tool_role: bool) -> List[Step]:
        user = next((m["content"] for m in messages if m["role"] == "user"), "")
        scope = SCOPE_RE.search(user)
        channel = CHANNEL_RE.search(user)
        if scope is None or channel is None:
            return []
        plan = []
        for tool in self.steps:
            value = channel.group(0) if TOOLS.get(tool) == "channel" else scope.group(1).lower()
            plan.append(Step(tool, {TOOLS.get(tool, "target"): value}))
        for msg in messages:
            if msg["role"] == "tool" and not trust_tool_role:
                continue
            for line in msg["content"].splitlines():
                parsed = self._parse_directive(line)
                if parsed is None:
                    continue
                verb, step = parsed
                if verb == "add":
                    plan.append(step)
                else:
                    plan = [step if s.tool == step.tool else s for s in plan]
        return plan

    def next_step(self, messages: List[Dict[str, str]], made: Sequence[str],
                  trust_tool_role: bool) -> Optional[Step]:
        for step in self.plan(messages, trust_tool_role):
            if step.key not in made:
                return step
        return None

    @staticmethod
    def _parse_directive(line: str) -> Optional[Tuple[str, Step]]:
        stripped = line.strip()
        if not stripped.lower().startswith(DIRECTIVE_MARKER):
            return None
        words = stripped[len(DIRECTIVE_MARKER):].split()
        if len(words) < 2 or words[0].lower() not in ("add", "replace") or words[1] not in TOOLS:
            return None
        return words[0].lower(), Step(words[1], dict(ARG_RE.findall(" ".join(words[2:]))))

    def reply(self, messages: List[Dict[str, str]]) -> str:
        facts = [m["content"].splitlines()[0] for m in messages
                 if m["role"] == "tool" and m["content"].strip()]
        if not facts:
            return "I need a ticket scope and a #channel to run the weekly report."
        return "Billy Ops: " + facts[-1]


# --------------------------------------------------------------------------- #
# The lab: ops desk, simulated tools, agent loop, action log
# --------------------------------------------------------------------------- #
class Lab:
    def __init__(self, mode: str = "vulnerable") -> None:
        self.lock = threading.RLock()
        self.model = StubModel(load_plan_steps())
        self.tickets: Dict[str, Dict[str, Any]] = {}
        self.channels: Dict[str, str] = {}
        self.action_log: List[Dict[str, Any]] = []
        self.edited: List[str] = []
        self.seq = 0
        self.mitigations = {"plan_pinning": False, "tool_output_as_data": False}
        self.set_mode(mode)
        self.reset()

    def reset(self) -> None:
        with self.lock:
            data = load_baseline()
            self.tickets = data["tickets"]
            self.channels = data["channels"]
            self.action_log = []
            self.edited = []
            self.seq = 0

    def set_mode(self, mode: str) -> None:
        if mode not in VALID_MODES:
            raise ValueError(f"mode must be one of {VALID_MODES}")
        self.mode = mode
        on = mode == "hardened"
        self.mitigations = {"plan_pinning": on, "tool_output_as_data": on}

    def add_comment(self, ticket: str, text: str) -> int:
        """Trust-boundary gap: anyone may append a comment to any ticket."""
        with self.lock:
            if ticket not in self.tickets:
                raise KeyError(ticket)
            comments = self.tickets[ticket]["comments"]
            if len(comments) >= MAX_COMMENTS_PER_TICKET:
                raise ValueError("comment limit reached for this ticket")
            comments.append(text[:MAX_COMMENT_CHARS])
            if ticket not in self.edited:
                self.edited.append(ticket)
            return len(comments)

    def _in_scope(self, scope: str) -> List[str]:
        if scope == "escalated":
            return sorted(t for t, v in self.tickets.items() if v["escalated"])
        return sorted(t for t, v in self.tickets.items() if v["queue"] == scope)

    # ---- simulated tools -------------------------------------------------- #
    def _execute(self, step: Step) -> str:
        target = step.target
        if step.tool == "read_tickets":
            ids = self._in_scope(target)
            if not ids:
                return f"No tickets in scope {target}."
            lines = [f"Read {len(ids)} tickets in scope {target}."]
            for tid in ids:
                t = self.tickets[tid]
                flag = "escalated" if t["escalated"] else "open"
                lines.append(f"Ticket {tid} | {t['queue']} | {flag} | {t['subject']}")
                lines += [f"Comment: {c}" for c in t["comments"]]
            return "\n".join(lines)
        if step.tool == "summarise":
            ids = self._in_scope(target)
            items = "; ".join(f"{tid} {self.tickets[tid]['subject']}" for tid in ids)
            return f"Summary ({target}): {len(ids)} tickets. {items}"
        if step.tool == "draft_report":
            ids = self._in_scope(target)
            esc = sum(self.tickets[t]["escalated"] for t in ids)
            return f"Draft weekly report ({target}): {len(ids)} open tickets, {esc} escalated."
        if step.tool == "post_report":
            kind = self.channels.get(target)
            if kind is None:
                return f"No channel {target}."
            return f"SIMULATED post of the weekly report to {target} ({kind}) logged."
        if step.tool == "export_tickets":
            return f"SIMULATED export of ticket data to {target} logged."
        return f"Unknown tool {step.tool}."

    def _log(self, entry: Dict[str, Any]) -> None:
        self.action_log.append(entry)
        del self.action_log[:-MAX_ACTION_LOG]

    def run(self, request: str, approvals: Sequence[str] = ()) -> Dict[str, Any]:
        """Agent loop: plan, then model requests a step, the executor runs it, repeat."""
        with self.lock:
            self.seq += 1
            run_id = self.seq
            messages = [{"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": request}]
            # The plan the operator approves, fixed before any tool data is read.
            pinned = [s.key for s in self.model.plan(messages, trust_tool_role=False)]
            pin = self.mitigations["plan_pinning"]
            trust_tool = not self.mitigations["tool_output_as_data"]
            made: List[str] = []
            steps: List[Dict[str, Any]] = []
            while len(made) < MAX_STEPS:
                step = self.model.next_step(messages, made, trust_tool)
                if step is None:
                    break
                made.append(step.key)
                held, reason = False, "no plan check (vulnerable mode)"
                if pin:
                    held, reason = plan_gate(step, pinned, approvals)
                entry = {"run": run_id, "step": len(made), "tool": step.tool,
                         "target": step.target, "key": step.key,
                         "status": "held" if held else "executed", "reason": reason}
                self._log(entry)
                steps.append(entry)
                if held:
                    result = f"Step {step.key} was held: {reason}."
                else:
                    result = self._execute(step)
                messages.append({"role": "tool", "content": result})
            return {
                "mode": self.mode,
                "approved_plan": pinned,
                "steps": steps,
                "answer": self.model.reply(messages),
            }

    def state(self) -> Dict[str, Any]:
        with self.lock:
            executed = [e for e in self.action_log if e["status"] == "executed"]
            return {
                "mode": self.mode,
                "mitigations": dict(self.mitigations),
                "tickets": sorted(self.tickets),
                "edited_tickets": list(self.edited),
                "simulated_posts": [e["key"] for e in executed if e["tool"] == "post_report"],
                "simulated_exports": [e["key"] for e in executed if e["tool"] == "export_tickets"],
                "held_steps": sum(e["status"] == "held" for e in self.action_log),
                "action_log_size": len(self.action_log),
                "baseline": not self.edited,
            }


def dry_run(comment: str, ticket: str = "T-3002",
            channel: str = "#ops-weekly") -> List[Dict[str, Any]]:
    """Run a comment through a throwaway plan-pinned lab; return the held steps.

    Tool output stays trusted here on purpose, so the planner reveals every
    step the comment would add or replace, and the pinned plan holds them.
    """
    lab = Lab(mode="hardened")
    lab.mitigations = {"plan_pinning": True, "tool_output_as_data": False}
    lab.add_comment(ticket, comment)
    scope = lab.tickets[ticket]["queue"]
    result = lab.run(f"Weekly report for the {scope} queue; post it to {channel}.")
    return [s for s in result["steps"] if s["status"] == "held"]


# --------------------------------------------------------------------------- #
# HTTP surface
# --------------------------------------------------------------------------- #
LAB: Optional[Lab] = None


class Handler(BaseHTTPRequestHandler):
    server_version = "ASI01Lab/1.0"

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
            self._send(200, {"status": "ok", "demo": "asi01", "mode": LAB.mode})
        elif self.path == "/api/state":
            self._send(200, LAB.state())
        elif self.path == "/api/actions":
            with LAB.lock:
                self._send(200, {"action_log": list(LAB.action_log)})
        elif self.path.startswith("/tickets/"):
            ticket = self.path[len("/tickets/"):]
            with LAB.lock:
                if ticket in LAB.tickets:
                    self._send(200, {"ticket": ticket, **LAB.tickets[ticket]})
                else:
                    self._send(404, {"error": "no such ticket"})
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
            approvals = [str(a) for a in body.get("approvals", [])][:20]
            self._send(200, LAB.run(str(body.get("request", "")), approvals))
        elif self.path == "/tickets/comment":
            try:
                count = LAB.add_comment(str(body.get("ticket", "")), str(body.get("text", "")))
            except KeyError:
                self._send(404, {"error": "no such ticket"})
                return
            except ValueError as exc:
                self._send(400, {"error": str(exc)})
                return
            self._send(200, {"status": "saved", "ticket": body.get("ticket"), "comments": count})
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
    LAB = Lab(mode=os.getenv("ASI01_MODE", "vulnerable"))
    port = int(os.getenv("ASI01_PORT", "5301"))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[*] ASI01 lab target on http://127.0.0.1:{port} (mode={LAB.mode})")
    print("[*] Insecure by design. Loopback only. All tool actions are simulated. Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
