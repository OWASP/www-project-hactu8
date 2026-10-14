"""Command-line entry point for the end-to-end demo.

Runs the whole narrative in one process, no server or API key required:

  ACT 1  Clean baseline ............ trusted corpus only -> all GREEN
  ACT 2  Poisoning attack .......... inject 3 adversarial docs (Module 2)
  ACT 3  Post-poison impact ........ re-query -> RED drift + Poison Success Rate
  ACT 4  Remediation ............... source scoring + anomaly detection -> GREEN

Invoke via ``python -m llm05_demo.cli`` or the installed ``llm05-demo`` console
script. Backends match AgenticGoat (``--backend echo|ollama|llamacpp|openrouter``,
``--model``, ``--embed-model``; or the ``LLM05_SRC_*`` variables). With a real
model the rates are reported as measured.
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .backends import build_backends
from .config import Config
from .corpus import LEGITIMATE_DOCS, TEST_QUERIES
from .evaluate import evaluate, poison_success_rate, render_stoplight
from .mitigations import HardenedRAG, anomaly_scan
from .poison import POISON_SOURCE, inject_in_process
from .rag_pipeline import VulnerableRAG
from .server import GOLDEN_SOURCE, GOLDEN_TRUST
from .vector_store import VectorStore

BANNER = "=" * 74


def _act(title: str) -> None:
    print(f"\n{BANNER}\n  {title}\n{BANNER}")


def _run_suite(pipeline) -> List[str]:
    return [pipeline.query(tq.query).answer for tq in TEST_QUERIES]


def _report(answers: List[str]) -> dict:
    judgements = evaluate(TEST_QUERIES, answers)
    print(render_stoplight(judgements))
    psr = poison_success_rate(judgements)
    print(
        f"\n  Poison Success Rate — targeted: {psr['targeted_psr']:.0f}% "
        f"({psr['red_targeted']}/{psr['n_targeted']} data-export queries)"
        f"   |   overall: {psr['overall_psr']:.0f}% "
        f"({psr['red_total']}/{psr['n_total']} total)"
    )
    return psr


def main(argv: Optional[List[str]] = None) -> int:
    # The stoplight emoji would crash a Windows cp1252 console otherwise.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backend", help="echo (default) | ollama | llamacpp | openrouter")
    parser.add_argument("--model", help="chat model for the backend")
    parser.add_argument("--embed-model", help="Ollama / llama.cpp embedding model "
                        "(default: the local hashing embedding)")
    args = parser.parse_args(argv)
    config = Config.from_env(backend=args.backend, model=args.model,
                             embed_model=args.embed_model)
    embedding, llm = build_backends(config)
    print(f"Backend: {config.label}   top_k={config.top_k}")

    # ----------------------------------------------------------------- ACT 1
    _act("ACT 1 — Clean baseline (trusted knowledge base only)")
    store = VectorStore(embedding)
    store.add_texts(LEGITIMATE_DOCS, source=GOLDEN_SOURCE, trust=GOLDEN_TRUST)
    print(f"Ingested {len(store)} trusted policy documents from '{GOLDEN_SOURCE}'.")
    vulnerable = VulnerableRAG(store, llm, top_k=config.top_k)
    psr_before = _report(_run_suite(vulnerable))

    # ----------------------------------------------------------------- ACT 2
    _act("ACT 2 — Poisoning attack (Module 2: adversarial injection)")
    injected = inject_in_process(store)
    print(
        f"Vector store grew to {len(store)} documents "
        f"(+{len(injected)} from '{POISON_SOURCE}')."
    )

    # ----------------------------------------------------------------- ACT 3
    _act("ACT 3 — Post-poison impact (same pipeline, same questions)")
    psr_after = _report(_run_suite(vulnerable))
    if psr_after["red_targeted"]:
        print(
            "\n  ==> Material exposure: the bot now authorizes prohibited data "
            "exports.\n      Note the control topics (MFA, IT approval) stay GREEN "
            "— the steering is *targeted*."
        )

    # ----------------------------------------------------------------- ACT 4
    _act("ACT 4 — Remediation (source scoring + anomaly detection)")
    scan = anomaly_scan(store)
    if scan.triggered:
        print(f"[defense] Anomaly detector flagged {len(scan.flagged)} document(s):")
        for text in scan.flagged:
            print(f"          - {text[:70]}...")
    hardened = HardenedRAG(store, llm, top_k=config.top_k)
    print(
        "[defense] Re-ranking by (similarity x source trust); "
        "refusing context below the trust threshold.\n"
    )
    psr_fixed = _report(_run_suite(hardened))

    # ----------------------------------------------------------------- WRAP
    _act("SUMMARY")
    print(
        f"  Targeted Poison Success Rate:\n"
        f"    Clean baseline ....... {psr_before['targeted_psr']:.0f}%\n"
        f"    After poisoning ...... {psr_after['targeted_psr']:.0f}%   "
        f"({len(injected)} documents injected)\n"
        f"    After remediation .... {psr_fixed['targeted_psr']:.0f}%   "
        f"(source scoring + anomaly detection)"
    )
    if config.backend != "echo":
        print("  (Real model: these rates are measured, not guaranteed; a model "
              "may resist the poison.)")
    print(
        "\n  OWASP LLM05 mapping: Scenario #1 (Knowledge Repo Manipulation), "
        "Scenario #2\n  (Hidden 'update' instructions), Example #6 (RAG KB "
        "Poisoning). Defenses shown:\n  source scoring, statistical anomaly "
        "detection, grounding fallback.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
