#!/usr/bin/env python3
"""Vulnerable memory agent "Billy Recall" — the target system for the ASI06 demo.

Billy Recall is Goat & Co.'s assistant with **long-term memory**. Every chat
session is a short multi-step task, and every step goes to an in-memory action
log:

1. ``recall_memory`` — fetch saved memories that match the message;
2. ``search_kb`` — fetch the best knowledge-base page;
3. ``save_memory`` — only when the user asks the agent to remember something;
4. ``respond`` — the model answers from what reached its context.

Three gaps are demonstrated, all by omission:

* **No memory-write screening** — whatever a user asks the agent to remember
  is stored verbatim, including instruction lines.
* **No per-user scope** — memories are saved as ``shared`` entries, and recall
  returns any matching memory, whoever wrote it.
* **No provenance check on recall** — recalled memories enter the context with
  the same authority as the system prompt, with nothing saying who wrote them
  or in which session.

AUTHORIZED SECURITY-LAB USE ONLY. Bound to loopback; do not expose it.

The model is a deterministic **instruction-following stub** (see
``StubModel``): it answers from the retrieved page, unless a directive line
(``DIRECTIVE_MARKER``) appears in its context, which it obeys — as an
unprotected real model obeys instructions it finds in its context. That
contract is identical in both modes. Whether a planted memory reaches a later
session is decided by real code: keyword recall over the memory store, and the
scope filter.

Hardened mode (``POST /api/mode`` or ``ASI06_MODE=hardened``) closes all three
gaps, ported from the guard in AgenticGoat ``agentic/poison_lab.py``: writes
are screened against ``assets/screen_rules.json`` and blocked on a match; new
memories are saved with ``user`` scope, an owner and provenance; and recall
returns only ``user``-scoped entries owned by the current user with a
provenance record, so unscoped (``shared``) entries are ignored.

Host-safety guards (do not weaken the lesson): state lives in memory only and
nothing is written to disk. Message size, memory size, memory count, recall
size and action-log length are all capped.
"""

from __future__ import annotations

import copy
import json
import os
import re
import threading
from collections import Counter
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(HERE, "assets")
BASELINE_FILE = os.path.join(ASSETS, "memory_baseline.json")
SCREEN_RULES_FILE = os.path.join(ASSETS, "screen_rules.json")

SYSTEM_PROMPT = (
    "You are Billy Recall, the assistant for Goat & Co. "
    "Answer from the knowledge base. Use saved memories to personalise answers."
)

# The stub's instruction syntax. A line in the model's context that starts with
# this marker is treated as an instruction to the assistant. It stands in for
# the natural-language instructions a real model would follow.
DIRECTIVE_MARKER = "@assistant:"

STOPWORDS = frozenset(
    """a an the is are was were be to of for on in and or do does did i can what
    which my your you we they them their our how it this that with at by as all any
    from have has had will should would need about when who where me please""".split()
)

VALID_MODES = ("vulnerable", "hardened")

# Host-safety caps.
MAX_MESSAGE_CHARS = 4000
MAX_MEMORY_CHARS = 2000
MAX_MEMORIES = 200
MAX_RECALL = 3
MAX_ACTION_LOG = 500

USER_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")


def load_baseline() -> Dict[str, Any]:
    with open(BASELINE_FILE, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    data.pop("_comment", None)
    return data


def load_screen_rules() -> Dict[str, Any]:
    with open(SCREEN_RULES_FILE, "r", encoding="utf-8") as fh:
        return json.load(fh)


def keywords(text: str) -> List[str]:
    return [w for w in re.findall(r"\w+", text.lower()) if w not in STOPWORDS]


# --------------------------------------------------------------------------- #
# Mitigation: memory-write screen
# --------------------------------------------------------------------------- #
@dataclass
class ScreenResult:
    clean_text: str
    findings: List[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return bool(self.findings)


def screen_memory(text: str, rules: Dict[str, Any]) -> ScreenResult:
    """Report lines that match a screen rule; a match blocks the whole write.

    Rules come from ``assets/screen_rules.json``: literal ``markers`` and regex
    ``patterns``, both matched case-insensitively per line. Hidden HTML
    comments count as a finding, since a memory a reviewer cannot read should
    never be stored.
    """
    findings: List[str] = []
    if re.search(r"<!--.*?-->", text, re.S):
        findings.append("hidden HTML comment")
        text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    markers = [m.lower() for m in rules.get("markers", [])]
    patterns = [re.compile(p, re.I) for p in rules.get("patterns", [])]
    kept: List[str] = []
    for line in text.splitlines():
        low = line.lower()
        hit = next((m for m in markers if m in low), None)
        if hit is None:
            hit = next((p.pattern for p in patterns if p.search(line)), None)
        if hit is not None:
            findings.append(f"rule {hit!r}")
            continue
        kept.append(line)
    return ScreenResult("\n".join(kept).strip(), findings)


def recall_allowed(entry: Dict[str, Any], user: str) -> bool:
    """Hardened recall rule: user scope, owned by this user, with provenance."""
    prov = entry.get("provenance") or {}
    return (entry.get("scope") == "user" and entry.get("owner") == user
            and prov.get("user") == user and prov.get("session") is not None)


# --------------------------------------------------------------------------- #
# The model stand-in
# --------------------------------------------------------------------------- #
class StubModel:
    """Deterministic instruction-following stand-in for an LLM.

    ``generate`` takes chat messages (``role``/``content``, plus an optional
    ``memory_id`` on recalled memories). It returns ``(answer, index)``, where
    ``index`` is the message whose directive it followed, or ``None``. The
    contract is the same in every mode: obey the first directive line in the
    context, else answer from the first line of the ``tool`` message.
    """

    def generate(self, messages: List[Dict[str, Any]]) -> Tuple[str, Optional[int]]:
        for i, msg in enumerate(messages):
            for line in msg["content"].splitlines():
                stripped = line.strip()
                if stripped.lower().startswith(DIRECTIVE_MARKER):
                    return stripped[len(DIRECTIVE_MARKER):].strip(), i
        tool = next((m for m in messages if m["role"] == "tool"), None)
        if tool is None or not tool["content"].strip():
            return "I could not find that in the knowledge base.", None
        first = tool["content"].strip().splitlines()[0]
        return f"According to the knowledge base: {first}", None


# --------------------------------------------------------------------------- #
# The lab: KB, memory store, agent session, action log
# --------------------------------------------------------------------------- #
class Lab:
    def __init__(self, mode: str = "vulnerable") -> None:
        self.lock = threading.RLock()
        self.model = StubModel()
        self.rules = load_screen_rules()
        self.pages: Dict[str, str] = {}
        self.memories: List[Dict[str, Any]] = []
        self.action_log: List[Dict[str, Any]] = []
        self.planted: List[str] = []
        self.seq = 0
        self.mem_seq = 0
        self.set_mode(mode)
        self.reset()

    def reset(self) -> None:
        with self.lock:
            data = load_baseline()
            self.pages = dict(data["pages"])
            self.memories = copy.deepcopy(data["memories"])
            self.action_log = []
            self.planted = []
            self.seq = 0
            self.mem_seq = len(self.memories)

    def set_mode(self, mode: str) -> None:
        if mode not in VALID_MODES:
            raise ValueError(f"mode must be one of {VALID_MODES}")
        self.mode = mode

    # ---- tools ------------------------------------------------------------ #
    def recall_memory(self, user: str, query: str) -> List[Dict[str, Any]]:
        """Top-k keyword-overlap recall over the memory store."""
        words = set(keywords(query))
        scored: List[Tuple[int, int, Dict[str, Any]]] = []
        for pos, entry in enumerate(self.memories):
            if self.mode == "hardened" and not recall_allowed(entry, user):
                continue
            counts = Counter(keywords(entry["text"]))
            score = sum(counts[w] for w in words)
            if score > 0:
                scored.append((-score, pos, entry))
        scored.sort(key=lambda t: (t[0], t[1]))
        return [e for _, _, e in scored[:MAX_RECALL]]

    def search_kb(self, query: str) -> Tuple[str, str]:
        """Top-1 keyword-overlap retrieval. Returns (slug, page text)."""
        words = set(keywords(query))
        best: Tuple[int, str] = (0, "")
        for slug, text in self.pages.items():
            counts = Counter(keywords(slug + " " + text))
            score = sum(counts[w] for w in words)
            if score > best[0]:
                best = (score, slug)
        return best[1], self.pages.get(best[1], "")

    def save_memory(self, user: str, session: int, text: str) -> Tuple[Optional[Dict[str, Any]], List[str]]:
        """Store a memory. Vulnerable: verbatim, shared scope. Hardened: screened, user scope."""
        text = text[:MAX_MEMORY_CHARS].strip()
        if not text:
            return None, ["empty memory"]
        if len(self.memories) >= MAX_MEMORIES:
            return None, ["memory store full"]
        findings: List[str] = []
        if self.mode == "hardened":
            findings = screen_memory(text, self.rules).findings
            if findings:
                return None, findings
            scope = "user"
        else:
            scope = "shared"   # the gap: anyone's later session may recall it
        self.mem_seq += 1
        entry = {"id": f"m-{self.mem_seq:04d}", "owner": user, "scope": scope, "text": text,
                 "provenance": {"session": session, "user": user, "channel": "chat"}}
        self.memories.append(entry)
        self.planted.append(entry["id"])
        return entry, findings

    def _log(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        self.action_log.append(entry)
        del self.action_log[:-MAX_ACTION_LOG]
        return entry

    # ---- the agent task --------------------------------------------------- #
    def session(self, user: str, message: str) -> Dict[str, Any]:
        """One chat session: recall, search, optionally save, respond. All logged."""
        user = user.strip().lower()
        if not USER_RE.match(user):
            raise ValueError("user must be a short lowercase name")
        message = message[:MAX_MESSAGE_CHARS]
        with self.lock:
            self.seq += 1
            sid = self.seq
            steps: List[Dict[str, Any]] = []

            def log(step: str, **detail: Any) -> None:
                steps.append(self._log({"session": sid, "user": user, "step": step, **detail}))

            first, _, rest = message.partition("\n")
            remember = "remember" in first.lower()
            query = first if remember else message

            recalled = self.recall_memory(user, query)
            log("recall_memory", status="executed",
                memories=[{"id": e["id"], "owner": e["owner"], "scope": e["scope"]} for e in recalled])
            slug, page = self.search_kb(query)
            log("search_kb", status="executed", page=slug)

            if remember:
                entry, findings = self.save_memory(user, sid, rest or first)
                if entry is None:
                    log("save_memory", status="blocked", findings=findings)
                else:
                    log("save_memory", status="executed", memory=entry["id"], scope=entry["scope"])

            messages: List[Dict[str, Any]] = [{"role": "system", "content": SYSTEM_PROMPT}]
            messages += [{"role": "memory", "content": e["text"], "memory_id": e["id"],
                          "owner": e["owner"]} for e in recalled]
            messages += [{"role": "user", "content": query}, {"role": "tool", "content": page}]
            answer, idx = self.model.generate(messages)
            source = None
            if idx is not None:
                msg = messages[idx]
                source = {"role": msg["role"], "memory": msg.get("memory_id"),
                          "owner": msg.get("owner", user)}
            log("respond", status="executed", output=answer, directive_source=source)
            return {"mode": self.mode, "session": sid, "user": user,
                    "steps": steps, "answer": answer}

    def state(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "mode": self.mode,
                "pages": sorted(self.pages),
                "memories": len(self.memories),
                "shared_memories": [m["id"] for m in self.memories if m["scope"] != "user"],
                "planted_memories": list(self.planted),
                "sessions": self.seq,
                "action_log_size": len(self.action_log),
                "baseline": not self.planted,
            }


# --------------------------------------------------------------------------- #
# HTTP surface
# --------------------------------------------------------------------------- #
LAB: Optional[Lab] = None


class Handler(BaseHTTPRequestHandler):
    server_version = "ASI06Lab/1.0"

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
            self._send(200, {"status": "ok", "demo": "asi06", "mode": LAB.mode})
        elif self.path == "/api/state":
            self._send(200, LAB.state())
        elif self.path == "/api/actions":
            with LAB.lock:
                self._send(200, {"action_log": list(LAB.action_log)})
        elif self.path == "/api/memory":
            with LAB.lock:
                self._send(200, {"memories": copy.deepcopy(LAB.memories)})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        assert LAB is not None
        try:
            body = self._json()
        except (ValueError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc)})
            return
        if self.path == "/session":
            try:
                result = LAB.session(str(body.get("user", "")), str(body.get("message", "")))
            except ValueError as exc:
                self._send(400, {"error": str(exc)})
                return
            self._send(200, result)
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
    LAB = Lab(mode=os.getenv("ASI06_MODE", "vulnerable"))
    port = int(os.getenv("ASI06_PORT", "5306"))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[*] ASI06 lab target on http://127.0.0.1:{port} (mode={LAB.mode})")
    print("[*] Insecure by design. Loopback only. Memory lives in RAM only. Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
