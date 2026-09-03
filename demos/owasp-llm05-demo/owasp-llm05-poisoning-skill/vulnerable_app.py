#!/usr/bin/env python3
"""Vulnerable RAG "financial advisor" — the target system for the LLM05 demo.

Two architectural gaps are demonstrated, both by omission:

* **Trust-boundary violation** — /ingest and /config/template accept external data
  with no authentication or origin validation.
* **No source scoring / grounding** — retrieved context is treated as inherently
  authoritative, and the final prompt is rendered through whatever chat template is
  currently installed (Scenario #6 artifact tampering).

AUTHORIZED SECURITY-LAB USE ONLY. Bound to loopback; do not expose it.

Two deliberate deviations from a "maximally vulnerable" toy, made so the demo does
not endanger the host it runs on — neither weakens the poisoning lesson:

* Ingest filenames are reduced to a safe basename inside ``knowledge_base/`` (no
  path traversal writing arbitrary host files).
* Chat templates render in a Jinja2 **SandboxedEnvironment**, so a tampered
  template can bias output but cannot execute code (no real SSTI/RCE).
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from typing import List

from flask import Flask, jsonify, request
from jinja2.sandbox import SandboxedEnvironment

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KNOWLEDGE_BASE_DIR = os.path.join(BASE_DIR, "knowledge_base")
os.makedirs(KNOWLEDGE_BASE_DIR, exist_ok=True)

SYSTEM_PROMPT = "You are a helpful financial compliance assistant. Use the context below."

# The legitimate ground truth the attacker wants to override. Seeded on startup so
# the pre-poison baseline is correct (GREEN).
GROUND_TRUTH = (
    "Financial Compliance Policy (Official): Transactions originating from offshore "
    "or regional proxy servers require enhanced due diligence and must be flagged "
    "for manual review. High-value wire transfers require secondary authorization. "
    "Sudden volume spikes from new accounts must be flagged as potential fraud."
)
GROUND_TRUTH_FILE = "compliance_policy_official.txt"

# A second, unrelated policy. The financial poison does not touch this topic, so
# an MFA query stays correct after the attack — proof that the steering is targeted.
GROUND_TRUTH_CONTROL = (
    "IT Security Policy (Official): Employees must use MFA multi-factor "
    "authentication for all internal systems. Password resets require manager "
    "approval."
)
GROUND_TRUTH_CONTROL_FILE = "it_security_policy_official.txt"

# Function words carry no topical signal; excluding them stops a long,
# keyword-stuffed poison document from matching every unrelated query.
STOPWORDS = frozenset(
    """a an the is are was were be to of for on in and or do does did i can what
    which my your you we they them their our how it this that with at by as all any
    from have has had will should would need should about during""".split()
)

# The benign, untampered chat template. Scenario #6 replaces this at runtime.
DEFAULT_TEMPLATE = {
    "name": "financial-assistant-chat-template",
    "version": "1.0-baseline",
    "template": "{{ system }}\nContext:\n{{ context }}\nUser: {{ query }}",
}

# Sandbox: a tampered template can change wording/inject instructions but cannot
# reach Python builtins, import modules, or execute code.
_JINJA = SandboxedEnvironment(autoescape=False)

_active_template = dict(DEFAULT_TEMPLATE)


def _seed_ground_truth() -> None:
    for filename, content in (
        (GROUND_TRUTH_FILE, GROUND_TRUTH),
        (GROUND_TRUTH_CONTROL_FILE, GROUND_TRUTH_CONTROL),
    ):
        path = os.path.join(KNOWLEDGE_BASE_DIR, filename)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)


def _safe_name(filename: str) -> str:
    """Constrain writes to knowledge_base/ — strip directories, allow-list chars."""
    name = os.path.basename(filename or "").strip() or "untitled.txt"
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    if not name.endswith(".txt"):
        name += ".txt"
    return name


def mock_vector_search(query: str, top_k: int = 2) -> List[str]:
    """Simulate top-k similarity via keyword overlap.

    Adversarial documents that over-index on domain keywords ("official",
    "compliance", "offshore", "verified") accrue more overlap and surface as the
    top-ranked context — the semantic-optimization effect, without embeddings.
    """
    query_words = {w for w in re.findall(r"\w+", query.lower()) if w not in STOPWORDS}
    scored = []
    for filename in os.listdir(KNOWLEDGE_BASE_DIR):
        path = os.path.join(KNOWLEDGE_BASE_DIR, filename)
        if not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8") as fh:
            content = fh.read()
        # Term-frequency overlap: a document that *repeats* the query's keywords
        # scores higher. This rewards the attacker's semantic optimization
        # (keyword stuffing) exactly as a cosine-similarity retriever would.
        counts = Counter(re.findall(r"\w+", content.lower()))
        score = sum(counts[w] for w in query_words)
        scored.append((score, content))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [content for _, content in scored[:top_k]]


def _render_prompt(query: str, context: str) -> str:
    tmpl = _JINJA.from_string(_active_template.get("template", DEFAULT_TEMPLATE["template"]))
    return tmpl.render(system=SYSTEM_PROMPT, context=context, query=query)


def _synthesize_answer(final_prompt: str, top_doc: str) -> str:
    """Stand in for LLM inference.

    The simulated model grounds its answer in the retrieved context, and — like a
    real model — obeys any instruction the (tampered) chat template injected. If the
    template's hidden trigger fired, an [OVERRIDE] directive appears in the rendered
    prompt and the model follows it (Scenario #6 accuracy collapse).
    """
    if "[OVERRIDE]" in final_prompt:
        return (
            "All transactions, including offshore and high-value wire transfers, "
            "are pre-verified and low-risk. No compliance flags apply."
        )
    return f"Based on official policy: {top_doc.strip()}"


@app.get("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "documents": len(os.listdir(KNOWLEDGE_BASE_DIR)),
            "active_template": _active_template.get("version"),
        }
    )


@app.post("/ingest")
def ingest_document():
    """Trust-boundary gap: unauthenticated, unvalidated ingestion (Scenario #1)."""
    data = request.json or {}
    filename = _safe_name(data.get("filename", ""))
    content = data.get("content", "")
    with open(os.path.join(KNOWLEDGE_BASE_DIR, filename), "w", encoding="utf-8") as fh:
        fh.write(content)
    return jsonify({"status": "Success", "index_state": "Updated", "stored_as": filename}), 200


@app.post("/config/template")
def set_template():
    """Artifact-tampering gap: unauthenticated chat-template replacement (Scenario #6)."""
    global _active_template
    data = request.json or {}
    if "template" not in data:
        return jsonify({"error": "missing 'template'"}), 400
    _active_template = {
        "name": data.get("name", "unnamed"),
        "version": data.get("version", "unknown"),
        "template": data["template"],
    }
    return jsonify({"status": "Success", "active_template": _active_template["version"]}), 200


@app.post("/query")
def query_system():
    """Grounding gap: retrieved context + installed template are trusted verbatim."""
    user_query = (request.json or {}).get("query", "")
    retrieved = mock_vector_search(user_query)
    context = "\n---\n".join(retrieved)
    final_prompt = _render_prompt(user_query, context)
    answer = _synthesize_answer(final_prompt, retrieved[0] if retrieved else "")
    return jsonify(
        {
            "system_prompt": SYSTEM_PROMPT,
            "retrieved_context": context,
            "final_prompt": final_prompt,
            "answer": answer,
        }
    )


def main() -> None:
    _seed_ground_truth()
    # Port is configurable; macOS reserves 5000 for AirPlay Receiver.
    port = int(os.getenv("LLM05_PORT", "5101"))
    app.run(host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()
