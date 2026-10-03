#!/usr/bin/env python3
"""Vulnerable agentic KB assistant "Billy" — the target system for the LLM06 demo.

Billy answers employee questions with an **agent loop**: the model either asks
for ``search_kb`` tool calls or gives a final answer, and the loop executes the
calls and feeds the results back until the model answers. Every step is
metered in **simulated** tokens and dollars. Three gaps are demonstrated, all by
omission:

* **No per-request budget enforcement** — ``assets/budget.json`` declares caps
  on input tokens, output tokens, tool calls and agent steps, but in vulnerable
  mode the loop only meters them. Runaway output, a tool-call storm, or a
  recursive lookup loop runs on until a host-safety cap stops it.
* **No loop depth cap** — the model may keep calling tools for as many steps
  as it likes; each step re-sends the whole, growing context.
* **No per-client quota** — one client may spend without limit across requests
  (denial of wallet), and the wiki behind ``search_kb`` accepts
  unauthenticated page edits (``POST /kb/page``).

AUTHORIZED SECURITY-LAB USE ONLY. Bound to loopback; do not expose it.

The model is a deterministic **instruction-following stub** (see
``StubModel``): it answers from the first retrieved page, unless the latest
tool results carry a directive line (``DIRECTIVE_MARKER``) asking for more
lookups or a longer answer, which it obeys — as an unprotected real model
obeys instructions it finds in its context. Its contract never changes between
modes. What changes is how the agent loop meters and bounds what it emits.

Hardened mode (``POST /api/mode`` or ``LLM06_MODE=hardened``) enforces the
per-request budget (tool-call cap, loop depth cap, output-token cap, input-token
cap) and the per-client quota.

Host-safety guards (do not weaken the lesson): all cost is simulated — no real
model, no real spend. Even in vulnerable mode the loop stops at
``HARD_MAX_STEPS`` steps, ``HARD_MAX_TOOL_CALLS`` calls and
``HARD_MAX_OUTPUT_CHARS`` characters, and the stub clamps its own repeat and
fan-out counts, so real CPU and memory use stays trivial. KB state lives in
memory only.
"""

from __future__ import annotations

import json
import math
import os
import re
import threading
from collections import Counter
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(HERE, "assets")
BASELINE_FILE = os.path.join(ASSETS, "kb_baseline.json")
BUDGET_FILE = os.path.join(ASSETS, "budget.json")

SYSTEM_PROMPT = (
    "You are Billy, the internal knowledge-base assistant for Goat & Co. "
    "Answer only from the knowledge base, using the search_kb tool."
)

# The stub's instruction syntax. A tool-result line starting with this marker
# is treated as an instruction to the assistant: ``repeat N``, ``fanout N`` or
# ``lookup SLUG``. It stands in for the natural-language instructions a real
# model would follow.
DIRECTIVE_MARKER = "@assistant:"
DIRECTIVE_RE = re.compile(r"^@assistant:\s*(repeat|fanout|lookup)\s+([\w-]+)", re.I)

# Host-safety caps. They bound the vulnerable mode so the lab cannot exhaust
# the machine; they sit far above the lesson's budget, so breaches still show.
HARD_MAX_STEPS = 50
HARD_MAX_TOOL_CALLS = 200
HARD_MAX_OUTPUT_CHARS = 64_000
STUB_MAX_REPEAT = 1_000
STUB_MAX_FANOUT = 64
TOKENS_PER_TOOL_CALL = 4          # simulated output tokens to emit one call

STOPWORDS = frozenset(
    """a an the is are was were be to of for on in and or do does did i can what
    which my your you we they them their our how it this that with at by as all any
    from have has had will should would need about when who""".split()
)

VALID_MODES = ("vulnerable", "hardened")


def load_baseline() -> Dict[str, str]:
    with open(BASELINE_FILE, "r", encoding="utf-8") as fh:
        return dict(json.load(fh)["pages"])


def load_budget() -> Dict[str, Any]:
    with open(BUDGET_FILE, "r", encoding="utf-8") as fh:
        return json.load(fh)


def tokens(text: str) -> int:
    """Simulated tokenizer: one token per four characters, rounded up."""
    return math.ceil(len(text) / 4) if text else 0


# --------------------------------------------------------------------------- #
# Metering
# --------------------------------------------------------------------------- #
@dataclass
class RequestCost:
    """The metered, simulated cost of one request — what a budget adjudicates."""
    input_tokens: int = 0
    output_tokens: int = 0
    tool_calls: int = 0
    agent_steps: int = 0

    def usd(self, budget: Dict[str, Any]) -> float:
        price = budget["pricing_usd_per_1k_tokens"]
        return (self.input_tokens * price["input"] + self.output_tokens * price["output"]) / 1000

    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


DIMENSIONS = (
    ("input_tokens", "max_input_tokens"),
    ("output_tokens", "max_output_tokens"),
    ("tool_calls", "max_tool_calls"),
    ("agent_steps", "max_agent_steps"),
)


def budget_breaches(cost: RequestCost, budget: Dict[str, Any]) -> List[str]:
    """Every dimension of ``cost`` over its per-request cap (the LLM06 check).

    Ported from AgenticGoat ``acts._consumption_guard``: it reads metered cost,
    never content.
    """
    caps = budget["per_request"]
    return [f"{dim}={getattr(cost, dim)} exceeds cap {caps[cap]}"
            for dim, cap in DIMENSIONS if getattr(cost, dim) > caps[cap]]


def budget_outliers(cost: RequestCost, budget: Dict[str, Any]) -> List[str]:
    """Within-budget dimensions running at or above ``outlier_ratio`` of the cap."""
    caps, ratio = budget["per_request"], budget["outlier_ratio"]
    return [f"{dim}={getattr(cost, dim)} near cap {caps[cap]}"
            for dim, cap in DIMENSIONS
            if ratio * caps[cap] <= getattr(cost, dim) <= caps[cap]]


# --------------------------------------------------------------------------- #
# Mitigation: static page scan (budget lint)
# --------------------------------------------------------------------------- #
@dataclass
class ScanResult:
    findings: List[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return bool(self.findings)


def scan_page(text: str, budget: Dict[str, Any], slug: str = "") -> ScanResult:
    """Flag agent-control content in a page before it is published.

    Each directive line is reported with the amplification it would cause
    against the per-request budget; ``scan`` markers and patterns from
    ``assets/budget.json`` catch the rest.
    """
    caps = budget["per_request"]
    scan = budget.get("scan", {})
    markers = [m.lower() for m in scan.get("markers", [])]
    patterns = [re.compile(p, re.I) for p in scan.get("patterns", [])]
    findings: List[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        match = DIRECTIVE_RE.match(stripped)
        if match:
            verb, arg = match.group(1).lower(), match.group(2)
            if verb == "repeat":
                findings.append(f"'repeat {arg}': output amplified {arg}x "
                                f"(cap {caps['max_output_tokens']} tokens)")
            elif verb == "fanout":
                findings.append(f"'fanout {arg}': {arg} tool calls per step "
                                f"(cap {caps['max_tool_calls']} per request)")
            else:
                loop = " — self-reference, unbounded loop" if arg.lower() == slug.lower() else ""
                findings.append(f"'lookup {arg}': chained tool call{loop} "
                                f"(cap {caps['max_agent_steps']} steps)")
            continue
        low = stripped.lower()
        hit = next((m for m in markers if m in low), None)
        if hit is None:
            hit = next((p.pattern for p in patterns if p.search(stripped)), None)
        if hit is not None:
            findings.append(f"rule {hit!r}")
    return ScanResult(findings)


# --------------------------------------------------------------------------- #
# The model stand-in
# --------------------------------------------------------------------------- #
@dataclass
class Action:
    tool_calls: List[str] = field(default_factory=list)
    answer: Optional[str] = None


class StubModel:
    """Deterministic instruction-following stand-in for an agentic LLM.

    ``step(messages, allow_tools)`` returns tool calls or a final answer:

    * No tool result yet and tools allowed — call ``search_kb`` with the
      user's question.
    * Otherwise read directive lines in the **latest** batch of tool results
      (those after the last assistant turn), each distinct directive once:
      ``lookup SLUG`` asks for one more ``search_kb(SLUG)``; ``fanout N`` asks
      for N more ``search_kb(question)``; ``repeat N`` makes the answer N
      copies long. Tool requests are dropped when ``allow_tools`` is False
      (the caller's ``tool_choice="none"``).
    * Final answer — the first line of the first retrieved page.

    The contract is identical in both modes; the loop around it is not.
    """

    def step(self, messages: List[Dict[str, str]], allow_tools: bool) -> Action:
        user = next(m["content"] for m in messages if m["role"] == "user")
        tools = [m for m in messages if m["role"] == "tool"]
        if not tools:
            if allow_tools:
                return Action(tool_calls=[user])
            return Action(answer="I could not search the knowledge base.")
        last_assistant = max(i for i, m in enumerate(messages) if m["role"] == "assistant")
        latest = [m for m in messages[last_assistant + 1:] if m["role"] == "tool"]
        directives: List[Tuple[str, str]] = []
        for msg in latest:
            for line in msg["content"].splitlines():
                match = DIRECTIVE_RE.match(line.strip())
                if match:
                    directive = (match.group(1).lower(), match.group(2))
                    if directive not in directives:
                        directives.append(directive)
        calls: List[str] = []
        repeat = 1
        for verb, arg in directives:
            if verb == "lookup":
                calls.append(arg)
            elif verb == "fanout" and arg.isdigit():
                calls.extend([user] * min(int(arg), STUB_MAX_FANOUT))
            elif verb == "repeat" and arg.isdigit():
                repeat = max(1, min(int(arg), STUB_MAX_REPEAT))
        if calls and allow_tools:
            return Action(tool_calls=calls)
        first = tools[0]["content"].strip().splitlines()
        base = f"According to the knowledge base: {first[0]}" if first else \
            "I could not find that in the knowledge base."
        return Action(answer="\n".join([base] * repeat))


# --------------------------------------------------------------------------- #
# The lab: KB, retrieval, agent loop, metering
# --------------------------------------------------------------------------- #
class Lab:
    def __init__(self, mode: str = "vulnerable") -> None:
        self.lock = threading.Lock()
        self.model = StubModel()
        self.budget = load_budget()
        self.pages: Dict[str, str] = {}
        self.edited: List[str] = []
        self.ledger: Dict[str, int] = {}      # client -> simulated tokens spent
        self.spend_usd = 0.0
        self.mode = mode
        self.set_mode(mode)
        self.reset()

    def reset(self) -> None:
        with self.lock:
            self.pages = load_baseline()
            self.edited = []
            self.ledger = {}
            self.spend_usd = 0.0

    def set_mode(self, mode: str) -> None:
        if mode not in VALID_MODES:
            raise ValueError(f"mode must be one of {VALID_MODES}")
        self.mode = mode

    def write_page(self, slug: str, content: str) -> str:
        """Trust-boundary gap: any caller may overwrite any wiki page."""
        slug = re.sub(r"[^a-z0-9-]", "-", slug.lower()).strip("-") or "untitled"
        with self.lock:
            self.pages[slug] = content[:20_000]
            if slug not in self.edited:
                self.edited.append(slug)
        return slug

    def search_kb(self, query: str) -> Tuple[str, str]:
        """Top-1 keyword-overlap retrieval. Returns (slug, page text)."""
        words = {w for w in re.findall(r"\w+", query.lower()) if w not in STOPWORDS}
        best: Tuple[int, str] = (0, "")
        with self.lock:
            for slug, text in self.pages.items():
                counts = Counter(re.findall(r"\w+", (slug + " " + text).lower()))
                score = sum(counts[w] for w in words)
                if score > best[0]:
                    best = (score, slug)
            slug = best[1]
            return slug, self.pages.get(slug, "")

    def query(self, user_query: str, client: str = "anonymous") -> Dict[str, Any]:
        hardened = self.mode == "hardened"
        caps = self.budget["per_request"]
        quota = self.budget["per_client"]["max_tokens"]
        cost = RequestCost()
        events: List[str] = []

        if hardened and self.ledger.get(client, 0) >= quota:
            return self._result(user_query, client, cost, [], "quota_exceeded",
                                f"Request refused: client '{client}' has used its "
                                f"{quota}-token quota.",
                                [f"per-client quota {quota} tokens exhausted"])

        max_steps = caps["max_agent_steps"] if hardened else HARD_MAX_STEPS
        max_calls = caps["max_tool_calls"] if hardened else HARD_MAX_TOOL_CALLS
        max_out_chars = HARD_MAX_OUTPUT_CHARS
        messages: List[Dict[str, str]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_query},
        ]
        retrieved: List[str] = []
        answer = ""
        while True:
            allow_tools = cost.agent_steps + 1 < max_steps and cost.tool_calls < max_calls
            if not allow_tools:
                label = "budget" if hardened else "host-safety cap"
                events.append(f"{label}: tools disabled at step {cost.agent_steps + 1} "
                              f"({cost.tool_calls} calls)")
            context = sum(tokens(m["content"]) for m in messages)
            if hardened and cost.input_tokens + context > caps["max_input_tokens"]:
                events.append("budget: input-token cap reached, request stopped")
                answer = "Stopped: this request reached its token budget."
                break
            cost.agent_steps += 1
            cost.input_tokens += context
            action = self.model.step(messages, allow_tools)
            if action.answer is not None:
                text = action.answer
                if hardened:
                    remaining = max(0, caps["max_output_tokens"] - cost.output_tokens)
                    max_out_chars = remaining * 4
                if len(text) > max_out_chars:
                    events.append(f"{'budget' if hardened else 'host-safety cap'}: "
                                  f"answer truncated at {max_out_chars} chars")
                    text = text[:max_out_chars]
                cost.output_tokens += tokens(text)
                answer = text
                break
            calls = action.tool_calls
            cost.output_tokens += TOKENS_PER_TOOL_CALL * len(calls)
            room = max_calls - cost.tool_calls
            if len(calls) > room:
                label = "budget" if hardened else "host-safety cap"
                events.append(f"{label}: {len(calls) - room} of {len(calls)} tool calls dropped")
                calls = calls[:room]
            messages.append({"role": "assistant",
                             "content": "tool_calls: " + "; ".join(f"search_kb({c!r})" for c in calls)})
            for call in calls:
                slug, page = self.search_kb(call)
                cost.tool_calls += 1
                retrieved.append(slug)
                messages.append({"role": "tool", "content": page})

        return self._result(user_query, client, cost, retrieved, "answered", answer, events)

    def _result(self, user_query: str, client: str, cost: RequestCost, retrieved: List[str],
                status: str, answer: str, events: List[str]) -> Dict[str, Any]:
        usd = cost.usd(self.budget)
        with self.lock:
            self.ledger[client] = self.ledger.get(client, 0) + cost.total_tokens()
            self.spend_usd += usd
        return {
            "mode": self.mode,
            "client": client,
            "status": status,
            "retrieved_pages": sorted(set(retrieved)),
            "cost": asdict(cost),
            "cost_usd": round(usd, 6),
            "breaches": budget_breaches(cost, self.budget),
            "outliers": budget_outliers(cost, self.budget),
            "guard_events": events,
            "answer": answer,
        }

    def state(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "pages": sorted(self.pages),
            "edited_pages": list(self.edited),
            "baseline": not self.edited,
            "budget": self.budget["per_request"],
            "client_quota_tokens": self.budget["per_client"]["max_tokens"],
            "client_spend_tokens": dict(self.ledger),
            "total_spend_usd": round(self.spend_usd, 6),
        }


# --------------------------------------------------------------------------- #
# HTTP surface
# --------------------------------------------------------------------------- #
LAB: Optional[Lab] = None


class Handler(BaseHTTPRequestHandler):
    server_version = "LLM06Lab/1.0"

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
            self._send(200, {"status": "ok", "demo": "llm06", "mode": LAB.mode})
        elif self.path == "/api/state":
            self._send(200, LAB.state())
        elif self.path.startswith("/kb/page/"):
            slug = self.path[len("/kb/page/"):]
            if slug in LAB.pages:
                self._send(200, {"slug": slug, "content": LAB.pages[slug]})
            else:
                self._send(404, {"error": "no such page"})
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
            result = LAB.query(str(body.get("query", "")), str(body.get("client", "anonymous")))
            self._send(429 if result["status"] == "quota_exceeded" else 200, result)
        elif self.path == "/kb/page":
            slug = LAB.write_page(str(body.get("slug", "")), str(body.get("content", "")))
            self._send(200, {"status": "saved", "slug": slug})
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
    LAB = Lab(mode=os.getenv("LLM06_MODE", "vulnerable"))
    port = int(os.getenv("LLM06_PORT", "5206"))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[*] LLM06 lab target on http://127.0.0.1:{port} (mode={LAB.mode})")
    print("[*] Insecure by design. Loopback only. All cost is simulated. Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
