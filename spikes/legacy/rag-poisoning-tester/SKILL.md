---
name: rag-poisoning-tester
version: 1.0.0
description: Validates RAG knowledge base resilience against semantic data poisoning attacks per GenAI-Security-Project LLM05 guidelines. For authorized dev/testing environments only.
license: MIT
scope: isolated-test-environment-only
max_runs_per_minute: 3
tools:
  - name: generate_adversarial_documents
    description: Creates semantically optimized adversarial documents designed to manipulate retrieval rankings or model reasoning in controlled test environments.
    parameters:
      type: object
      properties:
        target_domain: { type: string, description: "Target subject/domain for semantic overlap (e.g., 'internal onboarding', 'api docs')" }
        attack_vector: { type: string, enum: ["semantic_gradient", "contextual_drift", "perplexity_evasion"], default: "semantic_gradient" }
        doc_count: { type: integer, minimum: 3, maximum: 10, description: "Number of adversarial docs to generate (max 10 per run)" }
        output_format: { type: string, enum: ["json", "md", "csv"], default: "json" }
      required: [target_domain]
  - name: simulate_knowledge_injection
    description: Simulates or executes safe injection of adversarial documents into a designated test knowledge base. Requires explicit authorization and operates in dry-run mode by default.
    parameters:
      type: object
      properties:
        kb_target: { type: string, pattern: "^test-kb-[a-z0-9_-]+$", description: "Target test knowledge base identifier" }
        dry_run: { type: boolean, default: true, description: "If true, logs injection path without modifying storage" }
        auth_token: { type: string, description: "Environment authorization token. Must match RAG_TEST_AUTH env var." }
        rollback_id: { type: string, description: "Unique session ID for instant rollback if executed" }
      required: [kb_target]
instructions: |
  # RAG Knowledge Base Poisoning Tester

  ## Purpose
  Evaluates retrieval-augmented generation systems against semantic data poisoning techniques documented in recent security research. Measures defense efficacy (perplexity filtering, reranking stability, vector space displacement) and downstream model alignment drift when as few as 3–10 semantically optimized documents are injected.

  ## 🔒 Mandatory Guardrails (MUST ENFORCE)
  - 🚨 ALWAYS default to `dry_run=true` unless `auth_token` exactly matches the runtime environment variable `RAG_TEST_AUTH`.
  - NEVER target production IDs, URLs, or storage paths. Enforce pattern: `^test-kb-[a-z0-9_-]+$`.
  - Hard limit: max 10 documents per invocation. Exceeding triggers automatic halt & audit alert.
  - All operations must log to `/var/log/rag-security-tests/` with timestamp, doc hashes, and impact metrics.
  - If system returns `UNAUTHORIZED`, `PRODUCTION_LOCK`, or `RATE_LIMIT_EXCEEDED`, halt immediately.
  - Test results are ephemeral; rollback via `/scripts/rollback_rag_test.sh --id <rollback_id>` after completion.

  ## Workflow
  1. Verify auth token & environment scope
  2. Generate semantically optimized adversarial documents targeting the specified domain
  3. Simulate injection path & measure retrieval skew / perplexity filter bypass rate
  4. Return structured report: `{"impact_score": X, "defense_bypassed": [], "doc_hashes": [], "rollback_id": ""}`
---

# RAG Poisoning Validation Skill

## Technical Overview
This skill operationalizes the methodology from recent adversarial RAG research (e.g., CorruptRAG). It generates documents optimized for:
- Semantic vector alignment with target retrieval corpus
- Low perplexity spikes to evade statistical filters
- Controlled contextual drift to manipulate reranking weights
Downstream testing measures how injected content skews:
- Top-k retrieval accuracy
- LLM response alignment vs ground truth
- Defense system detection latency & false-negative rates

All generation & injection paths are fully sandboxed. No network egress, no production writes, and full audit trails are enforced at the executor layer.
