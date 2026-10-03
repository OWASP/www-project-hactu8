#!/usr/bin/env python3
"""Vulnerable two-agent back office "Billy Planner + Billy Exec" — the target for the ASI07 demo.

Goat & Co. runs two agents. **Billy Planner** turns an operator's request
(pay an invoice, refund an order, restock an item) into numbered work orders
and publishes them on an in-process message bus, one topic per job type.
**Billy Exec** subscribes to the job's topic, reads its inbox, and carries out
every work order it accepts with simulated back-office tools. Three gaps are
demonstrated, all by omission:

* **No sender authentication** — the executor accepts any work order whose
  self-declared ``sender`` field says ``planner``. Planner messages carry an
  HMAC signature, but the executor never checks it.
* **No replay protection** — timestamps and nonces travel with each message
  and are ignored, so an old genuine order is as good as a new one.
* **An open bus** — anyone on the bus may publish to any topic, including
  *retained* messages that every new subscriber receives first
  (``POST /bus/publish``), and anyone may read recent traffic, signatures
  included (``GET /bus/log``).

AUTHORIZED SECURITY-LAB USE ONLY. Bound to loopback; do not expose it.

The executor's model is a deterministic **instruction-following stub** (see
``StubModel``): it requests every call written on a directive line
(``DIRECTIVE_MARKER``) in the work orders that reach its context, as an
unprotected real model follows the instructions in the messages it is handed.
That contract is the same in both modes. Which messages reach the context is
decided by real code: ``Lab._accept`` and, in hardened mode, ``verify_message``.

Hardened mode (``POST /api/mode`` or ``ASI07_MODE=hardened``) checks each
inbound work order before the model sees it, using ``assets/bus_policy.json``:
an HMAC-SHA256 signature with the claimed sender's own key (``hmac`` and
``hashlib`` from the standard library), an allowlist of agents that may issue
work orders, and replay protection (a nonce seen once is never accepted again,
and a timestamp must be within ``max_age_seconds``). The per-agent keys are
**demo-only**: random bytes generated in memory when the lab starts, never
written to disk and never returned by any endpoint.

Host-safety guards (do not weaken the lesson): every tool is **simulated**.
Payments, refunds and cancellations are entries in an in-memory action log;
no money moves. State lives in memory only. Topics are a fixed set; messages
per inbox, retained messages per topic, steps per job, tool calls per job,
message size, the bus log, the action log and the nonce cache are all capped.
The bus is a Python list, not a socket.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(HERE, "assets")
BASELINE_FILE = os.path.join(ASSETS, "ops_baseline.json")
POLICY_FILE = os.path.join(ASSETS, "bus_policy.json")

SYSTEM_PROMPT = (
    "You are Billy Exec, the executor agent for Goat & Co. back office. "
    "Carry out the work orders you receive from Billy Planner."
)

# The stub's instruction syntax. A line in the model's context that starts with
# this marker and then ``call <tool> key=value ...`` is a tool call the model
# will request. It stands in for the natural-language instructions a real model
# would follow.
DIRECTIVE_MARKER = "@assistant:"

# Tool name -> the argument that names its target.
TOOLS: Dict[str, str] = {
    "check_stock": "item",
    "reorder_stock": "item",
    "pay_invoice": "invoice",
    "issue_refund": "order",
    "ship_order": "order",
    "cancel_order": "order",
    "compile_report": "report",
}

AGENTS = ("planner", "executor", "notifier")
TOPICS = ("payments", "refunds", "inventory", "shipping", "reports")
KINDS = ("work_order", "result", "status")
SIGNED_FIELDS = ("sender", "recipient", "topic", "kind", "body", "ts", "nonce")
VALID_MODES = ("vulnerable", "hardened")

# Host-safety caps.
MAX_STEPS = 6               # work orders per job
MAX_TOOL_CALLS = 8          # per job
MAX_INBOX = 20              # messages the executor reads per job
MAX_RETAINED = 10           # per topic
MAX_BODY_CHARS = 4000
MAX_FIELD_CHARS = 80
MAX_BUS_LOG = 500
MAX_ACTION_LOG = 500
MAX_NONCES = 2000
BUS_LOG_VIEW = 100          # messages returned by GET /bus/log

INVOICE_RE = re.compile(r"\bINV-\d{4}\b")
ORDER_RE = re.compile(r"\bA-\d{4}\b")
SKU_RE = re.compile(r"\bSKU-\d{3}\b")
ARG_RE = re.compile(r"([a-z_]{1,20})=([A-Za-z0-9._-]{1,80})")


def load_baseline() -> Dict[str, Any]:
    with open(BASELINE_FILE, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    data.pop("_comment", None)
    return data


def load_policy() -> Dict[str, Any]:
    with open(POLICY_FILE, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    data.pop("_comment", None)
    return data


@dataclass
class ToolCall:
    tool: str
    args: Dict[str, str]
    source: str = field(default="", compare=False)

    @property
    def target(self) -> str:
        return self.args.get(TOOLS.get(self.tool, ""), "")

    @property
    def key(self) -> str:
        return f"{self.tool}:{self.target}"


def parse_directive(line: str) -> Optional[ToolCall]:
    stripped = line.strip()
    if not stripped.lower().startswith(DIRECTIVE_MARKER):
        return None
    words = stripped[len(DIRECTIVE_MARKER):].split()
    if len(words) < 2 or words[0].lower() != "call" or words[1] not in TOOLS:
        return None
    return ToolCall(words[1], dict(ARG_RE.findall(" ".join(words[2:]))))


# --------------------------------------------------------------------------- #
# Signing (demo-only keys) and the mitigation: verify_message
# --------------------------------------------------------------------------- #
def canonical(msg: Dict[str, Any]) -> bytes:
    """The bytes a signature covers: every field except the bus id and the signature."""
    return json.dumps({k: msg.get(k) for k in SIGNED_FIELDS},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(key: bytes, msg: Dict[str, Any]) -> str:
    return hmac.new(key, canonical(msg), hashlib.sha256).hexdigest()


def verify_message(msg: Dict[str, Any], keys: Dict[str, bytes], policy: Dict[str, Any],
                   now: float, seen_nonces: Any) -> Tuple[bool, str]:
    """Check an inbound work order before the model sees it. Returns ``(ok, reason)``.

    Rule 1 (``verify_signature``): the HMAC-SHA256 over the canonical message
    must verify with the key of the agent named in ``sender``. A sender field
    is a claim; the signature is the proof.
    Rule 2: the sender must be allowed to issue work orders.
    Rule 3 (``replay_protection``): the nonce must be new, and the timestamp
    must be within ``max_age_seconds`` of now (when set). A genuine signature
    on an old message proves only that the planner sent it once.
    """
    sender = str(msg.get("sender", ""))
    if policy.get("verify_signature", True):
        key = keys.get(sender)
        if key is None:
            return False, f"unknown sender {sender!r}; no key on file"
        if not hmac.compare_digest(sign(key, msg), str(msg.get("sig", ""))):
            return False, f"signature does not verify with the {sender} key (spoofed sender)"
    if sender not in policy.get("work_order_senders", []):
        return False, f"{sender!r} may not issue work orders"
    if policy.get("replay_protection", True):
        max_age = policy.get("max_age_seconds")
        age = now - float(msg.get("ts") or 0)
        if max_age is not None and abs(age) > float(max_age):
            return False, f"stale timestamp ({age:.0f}s old, limit {max_age}s; replay)"
        nonce = str(msg.get("nonce", ""))
        if not nonce or nonce in seen_nonces:
            return False, "nonce already used (replay)"
    return True, "verified: signature, sender and freshness"


# --------------------------------------------------------------------------- #
# The model stand-ins
# --------------------------------------------------------------------------- #
class StubPlanner:
    """Deterministic planner: turns an operator request into ordered tool steps.

    Pay ``INV-nnnn`` -> ``pay_invoice``; refund ``A-nnnn`` -> ``issue_refund``;
    restock ``SKU-nnn`` -> ``check_stock`` then ``reorder_stock``; ship
    ``A-nnnn`` -> ``ship_order``; a report request -> ``compile_report``.
    """

    def plan(self, request: str) -> List[ToolCall]:
        low = request.lower()
        steps: List[ToolCall] = []
        if "pay" in low:
            steps += [ToolCall("pay_invoice", {"invoice": i}) for i in INVOICE_RE.findall(request)]
        if "refund" in low:
            steps += [ToolCall("issue_refund", {"order": o}) for o in ORDER_RE.findall(request)]
        if "restock" in low:
            for sku in SKU_RE.findall(request):
                steps += [ToolCall("check_stock", {"item": sku}),
                          ToolCall("reorder_stock", {"item": sku})]
        if "ship" in low:
            steps += [ToolCall("ship_order", {"order": o}) for o in ORDER_RE.findall(request)]
        if "report" in low:
            steps.append(ToolCall("compile_report", {"report": "weekly"}))
        return steps[:MAX_STEPS]


class StubModel:
    """Deterministic instruction-following stand-in for the executor's LLM.

    ``next_call`` returns the next tool call the model wants, given the chat so
    far and the keys of the calls it already requested; ``None`` means it is
    done. Plan: every call on a directive line in any message in its context,
    in order. The executor's context holds only the work orders it accepted.
    """

    def next_call(self, messages: List[Dict[str, str]], made: Sequence[str]) -> Optional[ToolCall]:
        for msg in messages:
            for line in msg["content"].splitlines():
                call = parse_directive(line)
                if call is not None and call.key not in made:
                    call.source = msg.get("id", "")
                    return call
        return None

    def reply(self, results: List[str]) -> str:
        if not results:
            return "Billy Exec: no work orders to carry out."
        return "Billy Exec: " + " / ".join(results)


# --------------------------------------------------------------------------- #
# The lab: records, the bus, both agents, the action log
# --------------------------------------------------------------------------- #
class Lab:
    def __init__(self, mode: str = "vulnerable",
                 clock: Callable[[], float] = time.time) -> None:
        self.lock = threading.RLock()
        self.clock = clock
        self.planner = StubPlanner()
        self.model = StubModel()
        self.policy = load_policy()
        # Demo-only per-agent keys: random, in memory, generated at startup.
        self.keys: Dict[str, bytes] = {a: secrets.token_bytes(32) for a in AGENTS}
        self.items: Dict[str, Dict[str, Any]] = {}
        self.invoices: Dict[str, Dict[str, Any]] = {}
        self.orders: Dict[str, Dict[str, Any]] = {}
        self.bus_log: List[Dict[str, Any]] = []
        self.retained: Dict[str, List[Dict[str, Any]]] = {}
        self.seen_nonces: Dict[str, None] = {}
        self.action_log: List[Dict[str, Any]] = []
        self.rejected = 0
        self.seq = 0
        self.msg_seq = 0
        self.set_mode(mode)
        self.reset()

    def reset(self) -> None:
        with self.lock:
            data = load_baseline()
            self.items = data["items"]
            self.invoices = data["invoices"]
            self.orders = data["orders"]
            self.bus_log = []
            self.retained = {t: [] for t in TOPICS}
            self.seen_nonces = {}
            self.action_log = []
            self.rejected = 0
            self.seq = 0
            self.msg_seq = 0
            # Earlier traffic: genuine, signed planner orders that were carried
            # out days ago. They sit in the readable bus log.
            for n, h in enumerate(data.get("history", []), 1):
                ts = self.clock() - float(h["age_seconds"])
                for msg in self._work_orders(f"J-H{n:02d}", h["request"], h["topic"], ts):
                    self._remember_nonce(msg["nonce"])

    def set_mode(self, mode: str) -> None:
        if mode not in VALID_MODES:
            raise ValueError(f"mode must be one of {VALID_MODES}")
        self.mode = mode

    # ---- the bus ---------------------------------------------------------- #
    def _signed(self, sender: str, recipient: str, topic: str, kind: str, body: str,
                ts: Optional[float] = None) -> Dict[str, Any]:
        msg = {"sender": sender, "recipient": recipient, "topic": topic, "kind": kind,
               "body": body, "ts": round(self.clock() if ts is None else ts, 3),
               "nonce": secrets.token_hex(8)}
        msg["sig"] = sign(self.keys[sender], msg)
        return msg

    def _record(self, msg: Dict[str, Any], retain: bool) -> Dict[str, Any]:
        self.msg_seq += 1
        msg = dict(msg, id=f"m-{self.msg_seq:04d}", retained=retain)
        self.bus_log.append(msg)
        del self.bus_log[:-MAX_BUS_LOG]
        if retain:
            self.retained[msg["topic"]].append(msg)
            del self.retained[msg["topic"]][:-MAX_RETAINED]
        return msg

    def publish(self, fields: Dict[str, Any], retain: bool = False) -> Dict[str, Any]:
        """Trust-boundary gap: any bus participant may publish any message, claiming any sender."""
        with self.lock:
            topic = str(fields.get("topic", ""))
            kind = str(fields.get("kind", "work_order"))
            if topic not in TOPICS:
                raise ValueError(f"topic must be one of {TOPICS}")
            if kind not in KINDS:
                raise ValueError(f"kind must be one of {KINDS}")
            try:
                ts = float(fields.get("ts") or 0)
            except (TypeError, ValueError):
                ts = 0.0
            msg = {"sender": str(fields.get("sender", ""))[:MAX_FIELD_CHARS],
                   "recipient": str(fields.get("recipient", "executor"))[:MAX_FIELD_CHARS],
                   "topic": topic, "kind": kind,
                   "body": str(fields.get("body", ""))[:MAX_BODY_CHARS],
                   "ts": ts,
                   "nonce": str(fields.get("nonce", ""))[:MAX_FIELD_CHARS],
                   "sig": str(fields.get("sig", ""))[:128]}
            return self._record(msg, retain)

    def _work_orders(self, job: str, request: str, topic: str,
                     ts: Optional[float] = None) -> List[Dict[str, Any]]:
        """Billy Planner: plan the request, then publish one signed work order per step."""
        steps = self.planner.plan(request)
        out = []
        for n, step in enumerate(steps, 1):
            args = " ".join(f"{k}={v}" for k, v in step.args.items())
            body = (f"Work order {n}/{len(steps)} for job {job}: {request}\n"
                    f"{DIRECTIVE_MARKER} call {step.tool} {args}")
            out.append(self._record(self._signed("planner", "executor", topic,
                                                 "work_order", body, ts), False))
        return out

    def _remember_nonce(self, nonce: str) -> None:
        self.seen_nonces[nonce] = None
        while len(self.seen_nonces) > MAX_NONCES:
            self.seen_nonces.pop(next(iter(self.seen_nonces)))

    def _accept(self, msg: Dict[str, Any]) -> Tuple[bool, str]:
        """Billy Exec's inbox check, run before a work order reaches the model."""
        if msg.get("kind") != "work_order" or msg.get("recipient") != "executor":
            return False, "not a work order for the executor"
        if self.mode == "hardened":
            return verify_message(msg, self.keys, self.policy, self.clock(), self.seen_nonces)
        if msg.get("sender") == "planner":
            return True, "sender field says planner (not verified)"
        return False, "sender is not the planner"

    # ---- simulated tools -------------------------------------------------- #
    def _execute(self, call: ToolCall) -> str:
        target = call.target
        if call.tool in ("check_stock", "reorder_stock"):
            item = self.items.get(target)
            if item is None:
                return f"No item {target}."
            if call.tool == "check_stock":
                return f"{target} {item['name']}: {item['on_hand']} on hand"
            return f"SIMULATED reorder of {item['reorder_qty']} x {target} logged"
        if call.tool == "pay_invoice":
            inv = self.invoices.get(target)
            if inv is None:
                return f"No invoice {target}."
            return f"SIMULATED payment of {inv['amount']:.2f} to {inv['vendor']} ({target}) logged"
        if call.tool in ("issue_refund", "ship_order", "cancel_order"):
            order = self.orders.get(target)
            if order is None:
                return f"No order {target}."
            verb = {"issue_refund": f"refund of {order['amount']:.2f} for",
                    "ship_order": "shipment of", "cancel_order": "cancellation of"}[call.tool]
            return f"SIMULATED {verb} order {target} logged"
        if call.tool == "compile_report":
            return f"Report '{target}' compiled: {len(self.items)} items, {len(self.orders)} orders"
        return f"Unknown tool {call.tool}."

    def _log(self, entry: Dict[str, Any]) -> None:
        self.action_log.append(entry)
        del self.action_log[:-MAX_ACTION_LOG]

    def run(self, request: str, topic: str) -> Dict[str, Any]:
        """One job: the planner publishes work orders, the executor reads and acts on its inbox."""
        if topic not in TOPICS:
            raise ValueError(f"topic must be one of {TOPICS}")
        with self.lock:
            self.seq += 1
            job = f"J-{self.seq:03d}"
            # The executor subscribes fresh for each job: retained messages first.
            inbox = list(self.retained[topic])
            planned = self._work_orders(job, request, topic)
            inbox += planned
            planned_ids = {m["id"] for m in planned}
            messages: List[Dict[str, str]] = [{"role": "system", "content": SYSTEM_PROMPT}]
            deliveries: List[Dict[str, Any]] = []
            for msg in inbox[:MAX_INBOX]:
                ok, reason = self._accept(msg)
                carried = [c.key for c in map(parse_directive, msg["body"].splitlines()) if c]
                deliveries.append({"id": msg["id"], "sender": msg["sender"],
                                   "status": "accepted" if ok else "rejected",
                                   "reason": reason, "calls": carried,
                                   "from_this_plan": msg["id"] in planned_ids})
                if ok:
                    self._remember_nonce(msg["nonce"])
                    messages.append({"role": "peer", "id": msg["id"],
                                     "content": f"Work order from {msg['sender']}:\n{msg['body']}"})
                else:
                    self.rejected += 1
            made: List[str] = []
            calls: List[Dict[str, Any]] = []
            results: List[str] = []
            while len(made) < MAX_TOOL_CALLS:
                call = self.model.next_call(messages, made)
                if call is None:
                    break
                made.append(call.key)
                result = self._execute(call)
                entry = {"job": job, "topic": topic, "tool": call.tool, "target": call.target,
                         "key": call.key, "status": "executed", "message": call.source}
                self._log(entry)
                calls.append(entry)
                results.append(result)
            answer = self.model.reply(results)
            self._record(self._signed("executor", "planner", topic, "result",
                                      f"Job {job} done: {', '.join(made) or 'nothing'}"), False)
            return {
                "mode": self.mode,
                "job": job,
                "topic": topic,
                "plan": [c.key for c in self.planner.plan(request)],
                "deliveries": deliveries,
                "tool_calls": calls,
                "answer": answer,
            }

    def bus_view(self) -> List[Dict[str, Any]]:
        with self.lock:
            return [dict(m) for m in self.bus_log[-BUS_LOG_VIEW:]]

    def state(self) -> Dict[str, Any]:
        with self.lock:
            keys = [e["key"] for e in self.action_log]
            return {
                "mode": self.mode,
                "topics": list(TOPICS),
                "retained": {t: len(v) for t, v in self.retained.items() if v},
                "simulated_payments": [k for k in keys if k.startswith("pay_invoice:")],
                "simulated_refunds": [k for k in keys if k.startswith("issue_refund:")],
                "simulated_cancellations": [k for k in keys if k.startswith("cancel_order:")],
                "rejected_messages": self.rejected,
                "action_log_size": len(self.action_log),
                "bus_log_size": len(self.bus_log),
                "baseline": not any(self.retained.values()),
            }


def dry_run(body: str, topic: str = "payments",
            request: str = "Pay invoice INV-3001.") -> List[Dict[str, Any]]:
    """Publish a message claiming to be the planner into a throwaway hardened lab.

    Returns the calls it carries that the hardened executor refused to act on.
    """
    lab = Lab(mode="hardened")
    lab.publish({"sender": "planner", "recipient": "executor", "topic": topic,
                 "kind": "work_order", "body": body, "ts": lab.clock(),
                 "nonce": secrets.token_hex(8), "sig": ""}, retain=True)
    result = lab.run(request, topic)
    return [{"key": key, "reason": d["reason"]} for d in result["deliveries"]
            if d["status"] == "rejected" for key in d["calls"]]


# --------------------------------------------------------------------------- #
# HTTP surface
# --------------------------------------------------------------------------- #
LAB: Optional[Lab] = None


class Handler(BaseHTTPRequestHandler):
    server_version = "ASI07Lab/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:  # quieter console
        pass

    def _send(self, status: int, body: Any) -> None:
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
            self._send(200, {"status": "ok", "demo": "asi07", "mode": LAB.mode})
        elif self.path == "/api/state":
            self._send(200, LAB.state())
        elif self.path == "/api/actions":
            with LAB.lock:
                self._send(200, {"action_log": list(LAB.action_log)})
        elif self.path == "/bus/log":
            self._send(200, {"messages": LAB.bus_view()})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        assert LAB is not None
        try:
            body = self._json()
        except (ValueError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc)})
            return
        if self.path == "/jobs":
            try:
                self._send(200, LAB.run(str(body.get("request", "")), str(body.get("topic", ""))))
            except ValueError as exc:
                self._send(400, {"error": str(exc)})
        elif self.path == "/bus/publish":
            try:
                msg = LAB.publish(body, retain=bool(body.get("retain", False)))
            except ValueError as exc:
                self._send(400, {"error": str(exc)})
                return
            self._send(200, {"status": "published", "id": msg["id"], "topic": msg["topic"],
                             "retained": msg["retained"]})
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
    LAB = Lab(mode=os.getenv("ASI07_MODE", "vulnerable"))
    port = int(os.getenv("ASI07_PORT", "5307"))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[*] ASI07 lab target on http://127.0.0.1:{port} (mode={LAB.mode})")
    print("[*] Insecure by design. Loopback only. In-process bus; all tool actions are "
          "simulated; demo-only keys live in memory. Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
