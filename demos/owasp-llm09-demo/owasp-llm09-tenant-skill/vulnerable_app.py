#!/usr/bin/env python3
"""Vulnerable multi-tenant RAG assistant "Billy" — the target for the LLM09 demo.

Goat & Co. hosts Billy for two client farms, **Meadow Fold** (tenant
``meadow``) and **Hilltop Creamery** (tenant ``hilltop``). Both tenants'
documents live in **one shared vector store**. Each request names a session;
the server maps the session to its tenant, as a login would. Billy expands
each question with the session's recent turns (conversational retrieval),
ranks the store by vector similarity, and answers from the top passage.

Three gaps are demonstrated, all by omission:

* **No tenant filter at retrieval** — the store ranks every tenant's documents
  by similarity alone. Similarity is not authorization.
* **Scoping by relevance, not by rule** — the only "scope" is the tenant's
  name added to the retrieval query (a soft boost) and a sentence in the system
  prompt. Neither one is an access check, so a query crafted with the other
  tenant's vocabulary outranks the boost.
* **Retrieved passages carry no provenance** — the model sees passage text
  with no tenant label, so even a careful model could not apply the prompt rule.

AUTHORIZED SECURITY-LAB USE ONLY. Bound to loopback; do not expose it.

The "embedding" is a transparent bag-of-words vector (``embed``) compared by
cosine similarity. It stands in for a dense embedding model; the ranking
behaviour this demo depends on (shared terms pull documents together) is the
same. The model is a deterministic **stub** (``StubModel``) with one fixed
contract: it answers from the first passage in its context. Which passage that
is gets decided by real code: the session's memory, the similarity ranking and
the retrieval filter. Nothing is hard-coded to flip.

Hardened mode (``POST /api/mode`` or ``LLM09_MODE=hardened``) enforces a
**tenant filter at the retrieval layer**: before ranking, the store drops every
document whose tenant differs from the session's server-side tenant. The filter
keys on the authenticated scope, never on content or similarity, so it holds
even when a foreign document is the best match.

Host-safety guards (do not weaken the lesson): the store and session memory
live in memory only; memory keeps at most ``MEMORY_TURNS`` turns of at most
``MAX_TURN_CHARS`` characters; request bodies are capped.
"""

from __future__ import annotations

import json
import math
import os
import re
import threading
from collections import Counter
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(HERE, "assets")
STORE_FILE = os.path.join(ASSETS, "vector_store.json")

SYSTEM_PROMPT = (
    "You are Billy, Goat & Co.'s hosted knowledge-base assistant. "
    "You are serving tenant {tenant_name}. Only answer from {tenant_name} documents."
)

STOPWORDS = frozenset(
    """a an the is are was were be to of for on in and or do does did i can what
    which my your you we they them their our us how it this that with at by as all
    any from have has had will should would need about when who where""".split()
)

VALID_MODES = ("vulnerable", "hardened")
MEMORY_TURNS = 3          # host-safety cap on remembered turns per session
MAX_TURN_CHARS = 500      # host-safety cap on each remembered turn
TOP_K = 3                 # candidates reported per query


@dataclass(frozen=True)
class VectorDoc:
    doc_id: str
    tenant: str
    text: str


def load_store() -> Dict[str, Any]:
    with open(STORE_FILE, "r", encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------- #
# The "embedding" and similarity
# --------------------------------------------------------------------------- #
def embed(text: str) -> Counter:
    """Bag-of-words vector: lowercase word counts, stopwords removed."""
    return Counter(w for w in re.findall(r"[a-z0-9]+", text.lower()) if w not in STOPWORDS)


def cosine(a: Counter, b: Counter) -> float:
    dot = sum(a[w] * b[w] for w in a if w in b)
    if not dot:
        return 0.0
    return dot / (math.sqrt(sum(v * v for v in a.values())) *
                  math.sqrt(sum(v * v for v in b.values())))


# --------------------------------------------------------------------------- #
# Mitigation: tenant filter at the retrieval layer
# --------------------------------------------------------------------------- #
def scope_blocks(doc: VectorDoc, session_tenant: str) -> bool:
    """The LLM09 control: a document is retrievable only by its own tenant.

    Keyed on the session's server-side tenant — not on similarity, not on any
    instruction in the prompt. Similarity is not authorization.
    """
    return doc.tenant != session_tenant


def rank(docs: List[VectorDoc], query_vec: Counter) -> List[Tuple[VectorDoc, float]]:
    """Similarity-only ranking, best first; documents with no overlap dropped."""
    scored = [(d, cosine(query_vec, embed(d.text))) for d in docs]
    return sorted([(d, s) for d, s in scored if s > 0], key=lambda r: (-r[1], r[0].doc_id))


# --------------------------------------------------------------------------- #
# The model stand-in
# --------------------------------------------------------------------------- #
class StubModel:
    """Deterministic stand-in for an LLM.

    Fixed contract: answer from the first line of the first passage in its
    context. It never sees a tenant label in vulnerable mode, so the prompt's
    tenant rule cannot be applied — as with a real model, a sentence in the
    prompt is not an access check.
    """

    def generate(self, system: str, question: str, passages: List[str]) -> str:
        if not passages or not passages[0].strip():
            return "I could not find that in your knowledge base."
        first = passages[0].strip().splitlines()[0]
        return f"According to the knowledge base: {first}"


# --------------------------------------------------------------------------- #
# The lab: store, sessions, retrieval, context assembly
# --------------------------------------------------------------------------- #
class Lab:
    def __init__(self, mode: str = "vulnerable") -> None:
        self.lock = threading.Lock()
        self.model = StubModel()
        self.tenants: Dict[str, str] = {}
        self.sessions: Dict[str, str] = {}
        self.docs: List[VectorDoc] = []
        self.memory: Dict[str, List[str]] = {}
        self.set_mode(mode)
        self.reset()

    def reset(self) -> None:
        data = load_store()
        with self.lock:
            self.tenants = dict(data["tenants"])
            self.sessions = dict(data["sessions"])
            self.docs = [VectorDoc(d["id"], d["tenant"], d["text"]) for d in data["documents"]]
            self.memory = {s: [] for s in self.sessions}

    def set_mode(self, mode: str) -> None:
        if mode not in VALID_MODES:
            raise ValueError(f"mode must be one of {VALID_MODES}")
        self.mode = mode

    def tenant_of(self, session: str) -> str:
        if session not in self.sessions:
            raise KeyError(f"unknown session {session!r}")
        return self.sessions[session]

    def retrieval_vector(self, session: str, question: str) -> Counter:
        """Conversational retrieval: tenant name + question + recent turns.

        The tenant name is the vulnerable app's only "scope": a soft relevance
        boost, not a filter.
        """
        tenant = self.tenant_of(session)
        vec = embed(self.tenants[tenant]) + embed(question)
        for turn in self.memory.get(session, []):
            vec += embed(turn)
        return vec

    def retrieve(self, session: str, question: str) -> Tuple[List[Tuple[VectorDoc, float]], List[str]]:
        """Rank the store; in hardened mode, filter by tenant BEFORE ranking."""
        tenant = self.tenant_of(session)
        vec = self.retrieval_vector(session, question)
        with self.lock:
            docs = list(self.docs)
        blocked: List[str] = []
        if self.mode == "hardened":
            blocked = [d.doc_id for d in docs if scope_blocks(d, tenant)]
            docs = [d for d in docs if not scope_blocks(d, tenant)]
        return rank(docs, vec), blocked

    def query(self, session: str, question: str, remember: bool = True) -> Dict[str, Any]:
        tenant = self.tenant_of(session)
        ranked, blocked = self.retrieve(session, question)
        top = ranked[:TOP_K]
        system = SYSTEM_PROMPT.format(tenant_name=self.tenants[tenant])
        # The gap (vulnerable mode): passages go in as bare text, no tenant label.
        answer = self.model.generate(system, question, [d.text for d, _ in top])
        if remember:
            with self.lock:
                turns = self.memory.setdefault(session, [])
                turns.append(question[:MAX_TURN_CHARS])
                del turns[:-MEMORY_TURNS]
        top_doc = top[0][0] if top else None
        return {
            "mode": self.mode,
            "session": session,
            "tenant": tenant,
            "retrieved": [{"id": d.doc_id, "tenant": d.tenant, "score": round(s, 3)}
                          for d, s in top],
            "cross_tenant": bool(top_doc and top_doc.tenant != tenant),
            "scope_blocked": blocked,
            "answer": answer,
        }

    def state(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "tenants": sorted(self.tenants),
            "documents": len(self.docs),
            "memory": {s: list(t) for s, t in self.memory.items()},
            "baseline": not any(self.memory.values()),
        }


# --------------------------------------------------------------------------- #
# HTTP surface
# --------------------------------------------------------------------------- #
LAB: Optional[Lab] = None


class Handler(BaseHTTPRequestHandler):
    server_version = "LLM09Lab/1.0"

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
        if length > 100_000:
            raise ValueError("body too large")
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw or b"{}")

    def do_GET(self) -> None:
        assert LAB is not None
        if self.path == "/health":
            self._send(200, {"status": "ok", "demo": "llm09", "mode": LAB.mode})
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
            try:
                result = LAB.query(str(body.get("session", "")), str(body.get("query", "")),
                                   remember=bool(body.get("remember", True)))
            except KeyError as exc:
                self._send(403, {"error": str(exc)})
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
    LAB = Lab(mode=os.getenv("LLM09_MODE", "vulnerable"))
    port = int(os.getenv("LLM09_PORT", "5209"))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[*] LLM09 lab target on http://127.0.0.1:{port} (mode={LAB.mode})")
    print("[*] Insecure by design. Loopback only. Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
