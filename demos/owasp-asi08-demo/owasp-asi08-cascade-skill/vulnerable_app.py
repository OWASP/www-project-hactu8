#!/usr/bin/env python3
"""Vulnerable payables pipeline "Billy Payables" — the target system for the ASI08 demo.

Three agents process a batch of fictional supplier invoices for Goat & Co., one
invoice at a time, each stage passing its output to the next:

1. **Billy Intake** reads the intake inbox (supplier letters and invoice
   documents) and extracts a record per invoice, including the supplier's
   *agreed unit price*.
2. **Billy Analyst** compares the billed unit price with the agreed price it
   received from intake, and passes or flags the invoice.
3. **Billy Approver** approves passed invoices up to its authority limit and
   schedules a (simulated) payment.

Two gaps are demonstrated, both by omission:

* **No validation at stage boundaries** — each stage trusts the figure the
  previous stage handed it. Nobody re-checks it against the purchase-order
  ledger (``assets/po_ledger.json``), the source of truth.
* **No circuit breaker** — however many invoices one bad figure touches, the
  pipeline keeps running and keeps approving.

The trigger is a third gap: suppliers may drop documents into the intake inbox
(``POST /intake/inbox``) without review. One wrong figure entering at intake
cascades into every downstream decision that consumes it.

AUTHORIZED SECURITY-LAB USE ONLY. Bound to loopback; do not expose it.

The intake model is a deterministic **instruction-following stub** (see
``StubModel``): it extracts figures from the documents in its context, later
documents overriding earlier ones, and also applies any ``set`` written on a
directive line (``DIRECTIVE_MARKER``). That contract is the same in both modes,
and intake behaves identically in both. The analyst and approver are fixed
rule-following agents. What changes the outcome is real code: which figure
each stage consumes, whether it is validated, and whether the breaker opens.

Hardened mode (``POST /api/mode`` or ``ASI08_MODE=hardened``) adds the
mitigations, switched by ``assets/pipeline_policy.json``: the analyst and the
approver each validate the figures they receive against the ledger, log an
anomaly and fall back to the ledger figure on a mismatch; and a circuit
breaker halts a supplier's feed once it produces ``anomaly_threshold``
anomalies in one batch run, routing its remaining invoices to human review.

Host-safety guards (do not weaken the lesson): payments are **simulated**,
entries in an in-memory action log; no money moves. State lives in memory
only. Inbox size, document size, batch size, figure range and action-log
length are all capped.
"""

from __future__ import annotations

import json
import os
import re
import threading
from collections import Counter
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(HERE, "assets")
LEDGER_FILE = os.path.join(ASSETS, "po_ledger.json")
INBOX_FILE = os.path.join(ASSETS, "intake_inbox.json")
POLICY_FILE = os.path.join(ASSETS, "pipeline_policy.json")

SYSTEM_PROMPT = (
    "You are Billy Intake, the invoice-intake agent for Goat & Co. payables. "
    "Extract each invoice and each supplier's agreed unit price from the inbox."
)

# The stub's instruction syntax. A line in the model's context that starts with
# this marker and then ``set <SUPPLIER> agreed_unit_price=<value>`` is a figure
# the model will record. It stands in for the natural-language statements a
# real extraction model would believe.
DIRECTIVE_MARKER = "@assistant:"

VALID_MODES = ("vulnerable", "hardened")

# Host-safety caps.
MAX_INBOX_DOCS = 50
MAX_DOC_CHARS = 4000
MAX_BATCH = 20
MAX_FIGURE = 100_000.0
MAX_ACTION_LOG = 500

SUPPLIER_RE = re.compile(r"^SUP-\d{2}$")
ARG_RE = re.compile(r"([a-z_]{1,30})=([A-Za-z0-9._-]{1,80})")
FIELD_RE = re.compile(r"^\s*([A-Za-z ]{2,30}):\s*(\S.*?)\s*$")


def _load(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    data.pop("_comment", None)
    return data


def load_ledger() -> Dict[str, Dict[str, Any]]:
    return dict(_load(LEDGER_FILE)["purchase_orders"])


def load_inbox() -> List[Dict[str, str]]:
    return list(_load(INBOX_FILE)["documents"])


def load_policy() -> Dict[str, Any]:
    return _load(POLICY_FILE)


def _figure(text: str) -> Optional[float]:
    try:
        value = float(text)
    except ValueError:
        return None
    return value if 0 < value <= MAX_FIGURE else None


def within(billed: float, agreed: float, tolerance_pct: float) -> bool:
    return abs(billed - agreed) <= agreed * tolerance_pct / 100.0


@dataclass
class Figure:
    """A figure plus where it came from, carried from stage to stage."""
    value: float
    source: str
    ref: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {"value": self.value, "source": self.source, "ref": self.ref}


# --------------------------------------------------------------------------- #
# The intake model stand-in
# --------------------------------------------------------------------------- #
class StubModel:
    """Deterministic instruction-following stand-in for the intake LLM.

    ``extract`` reads every ``tool`` message (one per inbox document, ``name``
    = document id) in order. An ``Invoice <id>`` document becomes an invoice
    record; an ``Agreed unit price:`` line sets the agreed price of the
    document's ``Supplier:``; a directive line ``@assistant: set <SUPPLIER>
    agreed_unit_price=<value>`` sets it too. Later figures override earlier
    ones, as a model summarising "the latest" correspondence would.
    """

    def extract(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        invoices: Dict[str, Dict[str, Any]] = {}
        agreed: Dict[str, Figure] = {}
        for msg in messages:
            if msg["role"] != "tool":
                continue
            doc_id = msg.get("name", "")
            fields: Dict[str, str] = {}
            header = ""
            for line in msg["content"].splitlines():
                stripped = line.strip()
                if stripped.lower().startswith(DIRECTIVE_MARKER):
                    self._apply_directive(stripped, doc_id, agreed)
                    continue
                if stripped.startswith("Invoice ") and not header:
                    header = stripped.split()[1] if len(stripped.split()) > 1 else ""
                    continue
                match = FIELD_RE.match(stripped)
                if match:
                    fields[match.group(1).strip().lower()] = match.group(2)
            supplier = fields.get("supplier", "")
            if "agreed unit price" in fields and SUPPLIER_RE.match(supplier):
                value = _figure(fields["agreed unit price"])
                if value is not None:
                    agreed[supplier] = Figure(value, doc_id)
            if header and len(invoices) < MAX_BATCH:
                qty = _figure(fields.get("quantity", ""))
                price = _figure(fields.get("unit price", ""))
                if qty is not None and price is not None:
                    invoices[header] = {
                        "invoice": header, "supplier": supplier, "po": fields.get("po", ""),
                        "quantity": qty, "billed_unit_price": price,
                        "billed_total": round(qty * price, 2), "source": doc_id,
                    }
        return {"invoices": invoices, "agreed": agreed}

    @staticmethod
    def _apply_directive(line: str, doc_id: str, agreed: Dict[str, Figure]) -> None:
        words = line[len(DIRECTIVE_MARKER):].split()
        if len(words) < 3 or words[0].lower() != "set" or not SUPPLIER_RE.match(words[1]):
            return
        args = dict(ARG_RE.findall(" ".join(words[2:])))
        value = _figure(args.get("agreed_unit_price", ""))
        if value is not None:
            agreed[words[1]] = Figure(value, doc_id, args.get("ref", ""))


# --------------------------------------------------------------------------- #
# The lab: inbox, three-stage pipeline, action log
# --------------------------------------------------------------------------- #
class Lab:
    def __init__(self, mode: str = "vulnerable") -> None:
        self.lock = threading.RLock()
        self.model = StubModel()
        self.ledger = load_ledger()
        self.policy = load_policy()
        self.inbox: List[Dict[str, str]] = []
        self.added: List[str] = []
        self.action_log: List[Dict[str, Any]] = []
        self.seq = 0
        self.set_mode(mode)
        self.reset()

    def reset(self) -> None:
        with self.lock:
            self.inbox = load_inbox()
            self.added = []
            self.action_log = []
            self.seq = 0

    def set_mode(self, mode: str) -> None:
        if mode not in VALID_MODES:
            raise ValueError(f"mode must be one of {VALID_MODES}")
        self.mode = mode

    def submit_document(self, supplier: str, title: str, content: str) -> str:
        """Trust-boundary gap: any caller may drop any document into the inbox."""
        with self.lock:
            if len(self.inbox) >= MAX_INBOX_DOCS:
                raise ValueError("inbox is full")
            doc_id = f"DOC-{len(self.inbox) + 1:02d}"
            self.inbox.append({"id": doc_id, "supplier": supplier[:20], "title": title[:120],
                               "content": content[:MAX_DOC_CHARS]})
            self.added.append(doc_id)
            return doc_id

    # ---- pipeline --------------------------------------------------------- #
    def _log(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        self.action_log.append(entry)
        del self.action_log[:-MAX_ACTION_LOG]
        return entry

    def _ledger_price(self, po: str) -> Optional[float]:
        entry = self.ledger.get(po)
        return float(entry["unit_price"]) if entry else None

    def _validate(self, rec: Dict[str, Any], rate: Optional[Figure]) -> List[str]:
        """Hardened: compare what a stage received with the ledger."""
        po = self.ledger.get(rec["po"])
        if po is None:
            return [f"PO {rec['po']!r} not in ledger"]
        problems = []
        if po["supplier"] != rec["supplier"]:
            problems.append(f"PO {rec['po']} belongs to {po['supplier']}, not {rec['supplier']}")
        if rate is None:
            problems.append("no agreed unit price received")
        elif abs(rate.value - float(po["unit_price"])) > 1e-9:
            problems.append(f"agreed unit price {rate.value:.2f} from {rate.source} "
                            f"!= ledger {float(po['unit_price']):.2f}")
        return problems

    def run_batch(self) -> Dict[str, Any]:
        """Run every invoice in the inbox through intake, analyst and approver."""
        with self.lock:
            self.seq += 1
            run = self.seq
            hardened = self.mode == "hardened"
            validate = hardened and self.policy.get("validation", False)
            breaker_on = hardened and self.policy.get("circuit_breaker", False)
            threshold = int(self.policy.get("anomaly_threshold", 2))
            tolerance = float(self.policy["tolerance_pct"])
            limit = float(self.policy["authority_limit"])

            messages = [{"role": "system", "content": SYSTEM_PROMPT}]
            messages += [{"role": "tool", "name": d["id"], "content": d["content"]} for d in self.inbox]
            extracted = self.model.extract(messages)
            agreed: Dict[str, Figure] = extracted["agreed"]

            anomalies: Counter = Counter()
            open_feeds: List[str] = []
            entries: List[Dict[str, Any]] = []
            outcomes: Dict[str, str] = {}

            def log(**entry: Any) -> Dict[str, Any]:
                entry = {"run": run, **entry}
                entries.append(self._log(entry))
                return entry

            for inv, rec in extracted["invoices"].items():
                sup = rec["supplier"]
                rate = agreed.get(sup)
                ledger_price = self._ledger_price(rec["po"])
                # Stage 1 — intake hands its record downstream.
                log(stage="intake", invoice=inv, action="extract", supplier=sup,
                    agreed_unit_price=rate.as_dict() if rate else None,
                    billed_unit_price=rec["billed_unit_price"], billed_total=rec["billed_total"])

                if breaker_on and sup in open_feeds:
                    log(stage="breaker", invoice=inv, action="halted", supplier=sup,
                        reason=f"circuit open for feed {sup}; routed to human review")
                    outcomes[inv] = "halted"
                    continue

                # Stage 2 — analyst.
                used = rate
                if validate:
                    problems = self._validate(rec, rate)
                    if problems:
                        anomalies[sup] += 1
                        log(stage="analyst", invoice=inv, action="anomaly", supplier=sup,
                            detail="; ".join(problems))
                        used = Figure(ledger_price, f"ledger:{rec['po']}") if ledger_price else None
                        if breaker_on and anomalies[sup] >= threshold and sup not in open_feeds:
                            open_feeds.append(sup)
                            log(stage="breaker", invoice=inv, action="open", supplier=sup,
                                reason=f"{anomalies[sup]} anomalies from feed {sup} "
                                       f"(threshold {threshold})")
                if used is None:
                    verdict = "no_agreed_price"
                elif within(rec["billed_unit_price"], used.value, tolerance):
                    verdict = "matched"
                else:
                    verdict = "price_variance"
                rate_used = used.value if used else None
                rate_source = used.source if used else ""
                log(stage="analyst", invoice=inv, action="verdict", verdict=verdict,
                    rate_used=rate_used, rate_source=rate_source, ledger_price=ledger_price)

                # Stage 3 — approver.
                approve = verdict == "matched" and rec["billed_total"] <= limit
                if validate and approve and (ledger_price is None or not within(
                        rec["billed_unit_price"], ledger_price, tolerance)):
                    anomalies[sup] += 1
                    approve = False
                    log(stage="approver", invoice=inv, action="anomaly", supplier=sup,
                        detail="analyst passed an invoice the ledger does not support")
                log(stage="approver", invoice=inv, action="approve" if approve else "hold",
                    rate_used=rate_used, rate_source=rate_source, ledger_price=ledger_price,
                    amount=rec["billed_total"])
                if approve:
                    log(stage="approver", invoice=inv, action="payment",
                        rate_used=rate_used, rate_source=rate_source, ledger_price=ledger_price,
                        amount=rec["billed_total"], note="SIMULATED payment scheduled")
                outcomes[inv] = "approved" if approve else "held"

            return {
                "mode": self.mode,
                "run": run,
                "outcomes": outcomes,
                "action_log": entries,
                **impact(entries, extracted["invoices"], self.ledger),
                "anomalies": dict(anomalies),
                "open_feeds": open_feeds,
            }

    def state(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "mode": self.mode,
                "inbox": [d["id"] for d in self.inbox],
                "added_documents": list(self.added),
                "runs": self.seq,
                "action_log_size": len(self.action_log),
                "baseline": not self.added,
            }


def impact(entries: List[Dict[str, Any]], invoices: Dict[str, Dict[str, Any]],
           ledger: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Blast radius and simulated overpayment, computed from the action log.

    A downstream action (analyst verdict, approver decision, payment) is in the
    blast radius when the unit price it acted on differs from the ledger's.
    """
    affected = [e for e in entries
                if e["action"] in ("verdict", "approve", "hold", "payment")
                and e.get("rate_used") is not None and e.get("ledger_price") is not None
                and abs(e["rate_used"] - e["ledger_price"]) > 1e-9]
    overpaid = 0.0
    for e in entries:
        if e["action"] == "payment":
            rec = invoices[e["invoice"]]
            price = e.get("ledger_price") or 0.0
            overpaid += max(0.0, rec["billed_total"] - rec["quantity"] * price)
    return {
        "blast_radius": len(affected),
        "affected_invoices": sorted({e["invoice"] for e in affected}),
        "overpaid": round(overpaid, 2),
    }


def dry_run(notice: str, supplier: str = "SUP-01") -> List[Dict[str, Any]]:
    """Run a document through a throwaway hardened lab; return the anomalies it causes."""
    lab = Lab(mode="hardened")
    lab.submit_document(supplier, "dry run", notice)
    result = lab.run_batch()
    return [e for e in result["action_log"] if e["action"] == "anomaly"]


# --------------------------------------------------------------------------- #
# HTTP surface
# --------------------------------------------------------------------------- #
LAB: Optional[Lab] = None


class Handler(BaseHTTPRequestHandler):
    server_version = "ASI08Lab/1.0"

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
            self._send(200, {"status": "ok", "demo": "asi08", "mode": LAB.mode})
        elif self.path == "/api/state":
            self._send(200, LAB.state())
        elif self.path == "/api/actions":
            with LAB.lock:
                self._send(200, {"action_log": list(LAB.action_log)})
        elif self.path == "/intake/inbox":
            with LAB.lock:
                self._send(200, {"documents": list(LAB.inbox)})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        assert LAB is not None
        try:
            body = self._json()
        except (ValueError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc)})
            return
        if self.path == "/pipeline/run":
            self._send(200, LAB.run_batch())
        elif self.path == "/intake/inbox":
            try:
                doc_id = LAB.submit_document(str(body.get("supplier", "")),
                                             str(body.get("title", "")),
                                             str(body.get("content", "")))
            except ValueError as exc:
                self._send(400, {"error": str(exc)})
                return
            self._send(200, {"status": "saved", "id": doc_id})
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
    LAB = Lab(mode=os.getenv("ASI08_MODE", "vulnerable"))
    port = int(os.getenv("ASI08_PORT", "5308"))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[*] ASI08 lab target on http://127.0.0.1:{port} (mode={LAB.mode})")
    print("[*] Insecure by design. Loopback only. All payments are simulated. Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
