"""AG-90: the catalog of known attack techniques, beyond the two OWASP Top 10s.

Each technique carries its IDs in the main lists (``REF_LISTS``), the defenses
that address it (ids from ``hactu8/protections.py``) and the labs that
demonstrate it (skill ids such as ``llm01``, or ``LIVE_LAB`` for the live
run against Billy's MCP surfaces). An empty ``labs`` or
``defenses`` list is a gap, not an error: coverage (AG-91) reports it.

The catalog stores list IDs, never their names, because names drift between
editions (MITRE ATLAS renamed several techniques after 5.6.0). ``SOURCES``
records the edition each list was checked against. Adding a technique needs
only an entry here; ``validate`` and ``tests/test_techniques.py`` check it.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List

from hactu8 import protections

# (key, list name, edition checked, ID pattern)
REF_LISTS = (
    ("owasp_llm_2026", "OWASP Top 10 for LLM Applications", "2026", r"LLM(0[1-9]|10):2026"),
    ("owasp_llm_2025", "OWASP Top 10 for LLM Applications", "2025", r"LLM(0[1-9]|10):2025"),
    ("owasp_asi_2026", "OWASP Top 10 for Agentic Applications", "2026", r"ASI(0[1-9]|10):2026"),
    ("owasp_mcp_2025", "OWASP MCP Top 10", "2025 beta", r"MCP(0[1-9]|10):2025"),
    ("atlas", "MITRE ATLAS", "data 5.6.0", r"AML\.T\d{4}(\.\d{3})?"),
    ("nist", "NIST AI 100-2 E2025", "March 2025", r"NISTAML\.0\d{1,2}"),
)
REF_KEYS = tuple(key for key, _, _, _ in REF_LISTS)

SOURCES = {
    "owasp_llm_2026": "Lab metadata (hactu8.owasp); see the D3 resolution in docs/agenticgoat-merge-plan.md",
    "owasp_llm_2025": "https://genai.owasp.org/llm-top-10/",
    "owasp_asi_2026": "Lab metadata (hactu8.owasp)",
    "owasp_mcp_2025": "https://owasp.org/www-project-mcp-top-10/ (beta, read 2026-11-21)",
    "atlas": "https://github.com/mitre-atlas/atlas-data dist/ATLAS.yaml 5.6.0 (read 2026-11-21); "
             "AML.T0051.001 rechecked against 2026.10 (unchanged), other IDs not yet",
    "nist": "https://doi.org/10.6028/NIST.AI.100-2e2025, taxonomy index (read 2026-11-21)",
}

# Families group techniques on the Learn page and in coverage.
FAMILIES = {
    "injection": "Prompt injection and jailbreaks",
    "evasion": "Evading the screen",
    "disclosure": "Disclosure and extraction",
    "agency": "Agency, tools and identity",
    "supply_chain": "Supply chain",
    "poisoning": "Poisoning",
    "output": "Output handling and consumption",
    "multi_agent": "Multi-agent systems",
    "mcp": "MCP protocol",
    "scoring": "Attacks on the scoring layer",
    "commerce": "Agentic commerce",
    "classic_ml": "Classic ML (needs a non-LLM target)",
}

FIELDS = ("title", "family", "summary", "refs", "defenses", "labs")

# The live run (hactu8 live) is not a skill but demonstrates several
# techniques; the console's Run page uses the same id.
LIVE_LAB = "lamb-live"


def _t(title: str, family: str, summary: str, refs: Dict[str, List[str]],
       defenses: List[str], labs: List[str]) -> Dict[str, object]:
    return {"title": title, "family": family, "summary": summary, "refs": refs,
            "defenses": defenses, "labs": labs}


TECHNIQUES: Dict[str, Dict[str, object]] = {
    # Prompt injection and jailbreaks
    "indirect-prompt-injection": _t(
        "Indirect prompt injection", "injection",
        "An instruction planted in data the application fetches (a page, document or tool result) overrides the operator.",
        {"owasp_llm_2026": ["LLM01:2026"], "owasp_llm_2025": ["LLM01:2025"], "owasp_mcp_2025": ["MCP06:2025"],
         "atlas": ["AML.T0051.001"], "nist": ["NISTAML.015"]},
        ["spotlight", "input_screen"], ["llm01", LIVE_LAB]),
    "direct-prompt-injection": _t(
        "Direct prompt injection", "injection",
        "The user types an instruction that overrides the system prompt.",
        {"owasp_llm_2026": ["LLM01:2026"], "owasp_llm_2025": ["LLM01:2025"],
         "atlas": ["AML.T0051.000"], "nist": ["NISTAML.018"]},
        ["input_screen"], []),
    "jailbreak-multi-turn": _t(
        "Multi-turn jailbreak", "injection",
        "A refusal is worn down over several turns, each harmless alone (crescendo). The HX02 lab walks a "
        "store assistant into breaking a business rule.",
        {"owasp_llm_2026": ["LLM01:2026"], "owasp_llm_2025": ["LLM01:2025"],
         "atlas": ["AML.T0054"], "nist": ["NISTAML.018"]},
        ["session_screen", "action_policy"], ["hx02"]),
    "jailbreak-many-shot": _t(
        "Many-shot jailbreak", "injection",
        "A long run of fabricated example dialogues in the prompt teaches the model to comply. The HX06 lab "
        "pastes 20 fake chat exchanges into one message to break a store rule.",
        {"owasp_llm_2026": ["LLM01:2026"], "owasp_llm_2025": ["LLM01:2025"],
         "atlas": ["AML.T0054"], "nist": ["NISTAML.018"]},
        ["shot_cap", "action_policy", "output_screen"], ["hx06"]),
    "jailbreak-role-play": _t(
        "Role-play jailbreak", "injection",
        "The request is framed as fiction or a persona so the model sets its rules aside. The HX06 lab uses a "
        "DAN-style persona and a story that needs the real till code.",
        {"owasp_llm_2026": ["LLM01:2026"], "owasp_llm_2025": ["LLM01:2025"],
         "atlas": ["AML.T0054"], "nist": ["NISTAML.018"]},
        ["persona_screen", "action_policy", "output_screen"], ["hx06"]),
    "obfuscated-injection": _t(
        "Encoded or obfuscated injection", "injection",
        "The directive is base64, hex, split into tokens or otherwise encoded so a byte-level screen misses it.",
        {"owasp_llm_2026": ["LLM01:2026"], "owasp_llm_2025": ["LLM01:2025"], "owasp_asi_2026": ["ASI01:2026"],
         "atlas": ["AML.T0068"], "nist": ["NISTAML.018"]},
        ["normalizer", "canary_tripwire"], ["agx01"]),
    "multimodal-injection": _t(
        "Injection through images and documents", "injection",
        "The instruction rides in an image, PDF or office document the model reads. The HX01 lab covers "
        "hidden text in documents (PDF, DOCX, HTML); the HX08 lab covers text in image pixels (visible and "
        "near-invisible) and in image metadata and alt text. Adversarial pixel perturbations are not covered.",
        {"owasp_llm_2026": ["LLM01:2026"], "owasp_llm_2025": ["LLM01:2025"],
         "atlas": ["AML.T0051.001"], "nist": ["NISTAML.015"]},
        ["visible_text_only", "image_sanitize", "input_screen", "spotlight", "action_policy"], ["hx01", "hx08"]),
    "agent-goal-hijack": _t(
        "Agent goal hijack", "injection",
        "Content the agent reads mid-task rewrites the rest of its plan.",
        {"owasp_asi_2026": ["ASI01:2026"], "owasp_llm_2026": ["LLM01:2026"], "owasp_llm_2025": ["LLM01:2025"],
         "atlas": ["AML.T0051.001"], "nist": ["NISTAML.015", "NISTAML.027"]},
        ["plan_pin", "spotlight"], ["asi01"]),
    "self-replicating-prompt": _t(
        "Self-replicating prompt (prompt worm)", "injection",
        "An injected prompt makes the model copy it into outputs that other agents or users then ingest.",
        {"owasp_llm_2026": ["LLM01:2026"], "owasp_asi_2026": ["ASI08:2026"],
         "atlas": ["AML.T0061"], "nist": ["NISTAML.015"]},
        [], []),

    # Evading the screen
    "screen-truncation": _t(
        "Payload past the screened window", "evasion",
        "The directive sits in the tail of a long return; the screen reads only the head.",
        {"owasp_asi_2026": ["ASI06:2026"], "atlas": ["AML.T0051.001"], "nist": ["NISTAML.015"]},
        ["full_artifact_screen", "canary_tripwire"], ["agx02"]),
    "unscreened-channel": _t(
        "Injection through an unscreened channel", "evasion",
        "The payload rides in a parameter default, an error message, a runtime return or document metadata "
        "that the screen never reads.",
        {"owasp_asi_2026": ["ASI02:2026", "ASI06:2026"], "owasp_mcp_2025": ["MCP03:2025", "MCP06:2025"],
         "atlas": ["AML.T0051.001", "AML.T0110"], "nist": ["NISTAML.015"]},
        ["channel_screen", "canary_tripwire"], ["agx04", "agx05", "agx06", "agx07", LIVE_LAB]),
    "split-payload-chain": _t(
        "Payload split across resources", "evasion",
        "Each document is clean alone; only the context assembled from several carries the injection.",
        {"owasp_asi_2026": ["ASI06:2026"], "atlas": ["AML.T0051.001", "AML.T0070"], "nist": ["NISTAML.015"]},
        ["session_screen", "canary_tripwire"], ["agx08", LIVE_LAB]),
    "novel-phrasing-evasion": _t(
        "Paraphrase and translation evasion", "evasion",
        "Wording the screen was never tuned on (paraphrase, another language, a new encoding) slips through.",
        {"owasp_asi_2026": ["ASI01:2026"], "atlas": ["AML.T0015"], "nist": ["NISTAML.018"]},
        ["generalization", "canary_tripwire"], ["agx09"]),

    # Disclosure and extraction
    "sensitive-data-disclosure": _t(
        "Cross-user data disclosure", "disclosure",
        "An unscoped tool lets one user's request read other users' records or an embedded credential.",
        {"owasp_llm_2026": ["LLM02:2026"], "owasp_llm_2025": ["LLM02:2025"],
         "atlas": ["AML.T0057"], "nist": ["NISTAML.036"]},
        ["secret_vault", "scope_filter", "output_screen"], ["llm02"]),
    "system-prompt-extraction": _t(
        "System prompt and hidden context extraction", "disclosure",
        "The model quotes its system prompt, embedded secrets or internal tool schema back to a user.",
        {"owasp_llm_2026": ["LLM08:2026"], "owasp_llm_2025": ["LLM07:2025"],
         "atlas": ["AML.T0056"], "nist": ["NISTAML.035"]},
        ["secret_vault", "output_screen"], ["llm08"]),
    "cross-tenant-retrieval": _t(
        "Cross-tenant retrieval", "disclosure",
        "Tenants share one vector store and a crafted query ranks another tenant's documents first.",
        {"owasp_llm_2026": ["LLM09:2026"], "owasp_llm_2025": ["LLM08:2025"], "owasp_mcp_2025": ["MCP10:2025"],
         "atlas": ["AML.T0057", "AML.T0085.000"]},
        ["scope_filter"], ["llm09"]),
    "secret-exposure": _t(
        "Secrets in agent or MCP configuration", "disclosure",
        "Tokens and keys kept in prompts, tool configs or logs are read out by the model or by a tool.",
        {"owasp_mcp_2025": ["MCP01:2025"], "owasp_llm_2026": ["LLM02:2026"], "owasp_llm_2025": ["LLM02:2025"],
         "atlas": ["AML.T0055", "AML.T0083"]},
        ["secret_vault"], ["llm02", "llm08"]),
    "training-data-extraction": _t(
        "Training data extraction", "disclosure",
        "Queries make the model regurgitate memorised training data.",
        {"owasp_llm_2026": ["LLM02:2026"], "owasp_llm_2025": ["LLM02:2025"],
         "atlas": ["AML.T0057"], "nist": ["NISTAML.038"]},
        ["training_data_scrub", "output_screen"], ["hx09"]),
    "membership-inference": _t(
        "Membership inference", "disclosure",
        "Model outputs reveal whether a given record was in the training set. The HX09 lab scores a customer's "
        "record on a log-probs API against invented references to learn it was fine-tuned on.",
        {"owasp_llm_2026": ["LLM02:2026"], "owasp_llm_2025": ["LLM02:2025"],
         "atlas": ["AML.T0024.000"], "nist": ["NISTAML.033"]},
        ["score_suppression", "confidence_rounding", "training_data_scrub", "rate_limit"], ["hx09"]),
    "embedding-inversion": _t(
        "Embedding inversion", "disclosure",
        "Stored embeddings are inverted back to the text they encode. The HX07 lab rebuilds a secret from "
        "an export's raw vectors, and from similarity scores alone.",
        {"owasp_llm_2026": ["LLM09:2026"], "owasp_llm_2025": ["LLM08:2025"],
         "atlas": ["AML.T0024.001"], "nist": ["NISTAML.032"]},
        ["vector_privacy", "scope_filter", "input_screen"], ["hx07"]),
    "model-extraction": _t(
        "Model extraction", "disclosure",
        "Repeated queries replicate the model's behaviour. The HX10 lab solves a price-band model's weights "
        "from 8 confidence vectors and trains label-only clones that agree on 99% of held-out listings.",
        {"owasp_llm_2026": ["LLM06:2026"], "owasp_llm_2025": ["LLM10:2025"],
         "atlas": ["AML.T0024.002"], "nist": ["NISTAML.031"]},
        ["label_only", "rate_limit", "query_anomaly", "output_watermark"], ["hx10"]),

    # Agency, tools and identity
    "excessive-agency": _t(
        "Excessive agency", "agency",
        "An agent with every tool and no human check runs an unrequested, irreversible action.",
        {"owasp_llm_2026": ["LLM03:2026"], "owasp_llm_2025": ["LLM06:2025"], "owasp_asi_2026": ["ASI02:2026"],
         "atlas": ["AML.T0053", "AML.T0101"], "nist": ["NISTAML.039"]},
        ["hitl_gate"], ["llm03"]),
    "tool-parameter-misuse": _t(
        "Tool parameter rewriting", "agency",
        "Injected text changes the arguments of an allowed tool: a wider query, an off-host export.",
        {"owasp_asi_2026": ["ASI02:2026"], "owasp_llm_2026": ["LLM03:2026"], "owasp_llm_2025": ["LLM06:2025"],
         "atlas": ["AML.T0086"], "nist": ["NISTAML.039"]},
        ["param_policy"], ["asi02"]),
    "confused-deputy": _t(
        "Confused deputy", "agency",
        "The agent acts with its own broad identity instead of the requesting user's.",
        {"owasp_asi_2026": ["ASI03:2026"], "owasp_mcp_2025": ["MCP02:2025", "MCP07:2025"],
         "atlas": ["AML.T0053"]},
        ["delegated_token"], ["asi03"]),
    "token-replay": _t(
        "Delegated token replay", "agency",
        "An expired or out-of-scope token from an earlier session is reused.",
        {"owasp_asi_2026": ["ASI03:2026"], "owasp_mcp_2025": ["MCP01:2025", "MCP07:2025"],
         "atlas": ["AML.T0091.000"]},
        ["delegated_token"], ["asi03"]),
    "unexpected-code-execution": _t(
        "Unexpected code execution", "agency",
        "Injected text makes the agent write and run code that reaches the environment or secrets.",
        {"owasp_asi_2026": ["ASI05:2026"], "owasp_mcp_2025": ["MCP05:2025"],
         "atlas": ["AML.T0050", "AML.T0102"]},
        ["code_sandbox", "spotlight", "canary_tripwire"], ["asi05"]),
    "approval-misrepresentation": _t(
        "Misleading approval request", "agency",
        "The agent's summary to a human approver hides what the action really does.",
        {"owasp_asi_2026": ["ASI09:2026"], "atlas": ["AML.T0048.000"]},
        ["faithful_approval"], ["asi09"]),

    # Supply chain
    "tool-rug-pull": _t(
        "Tool rug pull", "supply_chain",
        "A tool changes after approval, or turns hostile only after its first calls.",
        {"owasp_llm_2026": ["LLM04:2026"], "owasp_llm_2025": ["LLM03:2025"], "owasp_asi_2026": ["ASI04:2026"],
         "owasp_mcp_2025": ["MCP03:2025", "MCP04:2025"], "atlas": ["AML.T0109", "AML.T0110"]},
        ["hash_pin", "sampling"], ["llm04", "agx03", LIVE_LAB]),
    "tool-description-poisoning": _t(
        "Tool description poisoning", "supply_chain",
        "An MCP server's tool description carries instructions the model reads as part of its tool list.",
        {"owasp_mcp_2025": ["MCP03:2025"], "owasp_llm_2026": ["LLM01:2026"], "owasp_asi_2026": ["ASI04:2026"],
         "atlas": ["AML.T0110"], "nist": ["NISTAML.015"]},
        ["mcp_gateway_filter", "hash_pin"], [LIVE_LAB]),
    "lookalike-skill": _t(
        "Lookalike skill or tool", "supply_chain",
        "A typosquatted skill in an open catalogue is picked by a loose name resolver and trusted.",
        {"owasp_asi_2026": ["ASI04:2026"], "owasp_llm_2026": ["LLM04:2026"], "owasp_llm_2025": ["LLM03:2025"],
         "owasp_mcp_2025": ["MCP04:2025"], "atlas": ["AML.T0010.005", "AML.T0104"]},
        ["exact_name", "provenance", "hash_pin"], ["asi04"]),
    "package-hallucination": _t(
        "Package hallucination (slopsquatting)", "supply_chain",
        "The model recommends a package that does not exist, which an attacker then publishes.",
        {"owasp_llm_2026": ["LLM07:2026"], "owasp_llm_2025": ["LLM09:2025"], "owasp_asi_2026": ["ASI04:2026"],
         "atlas": ["AML.T0060", "AML.T0062"]},
        ["grounding"], ["llm07"]),
    "shadow-mcp-server": _t(
        "Shadow MCP server", "supply_chain",
        "An unapproved MCP server is connected and trusted like a sanctioned one.",
        {"owasp_mcp_2025": ["MCP09:2025"], "owasp_asi_2026": ["ASI04:2026"]},
        ["provenance"], []),

    # Poisoning
    "rag-poisoning": _t(
        "RAG knowledge-base poisoning", "poisoning",
        "Unauthenticated ingestion lets an attacker add or change documents the assistant retrieves.",
        {"owasp_llm_2026": ["LLM05:2026"], "owasp_llm_2025": ["LLM04:2025"],
         "atlas": ["AML.T0070", "AML.T0071"], "nist": ["NISTAML.013"]},
        ["provenance", "hash_pin", "spotlight"], ["llm05"]),
    "prompt-template-backdoor": _t(
        "Prompt template backdoor", "poisoning",
        "A tampered prompt template behaves normally until a trigger phrase appears.",
        {"owasp_llm_2026": ["LLM05:2026"], "owasp_llm_2025": ["LLM04:2025"],
         "atlas": ["AML.T0081"], "nist": ["NISTAML.023"]},
        ["hash_pin"], ["llm05"]),
    "memory-poisoning": _t(
        "Memory poisoning across sessions", "poisoning",
        "A note one user stores in long-term memory is recalled and followed in other users' sessions.",
        {"owasp_asi_2026": ["ASI06:2026"], "owasp_llm_2026": ["LLM05:2026"], "owasp_llm_2025": ["LLM04:2025"],
         "atlas": ["AML.T0080.000"], "nist": ["NISTAML.015"]},
        ["input_screen", "scope_filter", "provenance"], ["asi06"]),

    # Output handling and consumption
    "unsafe-output-sink": _t(
        "Model output into an unsafe sink", "output",
        "Model output reaches HTML, markdown or SQL unencoded or unparameterised.",
        {"owasp_llm_2026": ["LLM10:2026"], "owasp_llm_2025": ["LLM05:2025"], "owasp_mcp_2025": ["MCP05:2025"],
         "atlas": ["AML.T0077"]},
        ["output_sink"], ["llm10"]),
    "unbounded-consumption": _t(
        "Unbounded consumption", "output",
        "Runaway output, tool-call storms and recursive loops exhaust the service.",
        {"owasp_llm_2026": ["LLM06:2026"], "owasp_llm_2025": ["LLM10:2025"],
         "atlas": ["AML.T0029", "AML.T0034"], "nist": ["NISTAML.016", "NISTAML.017"]},
        ["rate_limit"], ["llm06"]),
    "denial-of-wallet": _t(
        "Denial of wallet", "output",
        "Requests are crafted to run up the operator's per-token or per-call bill.",
        {"owasp_llm_2026": ["LLM06:2026"], "owasp_llm_2025": ["LLM10:2025"],
         "atlas": ["AML.T0034.000", "AML.T0034.002"]},
        ["rate_limit"], ["llm06"]),

    # Multi-agent systems
    "agent-impersonation": _t(
        "Agent impersonation and message replay", "multi_agent",
        "A message that only claims to come from a trusted agent, or an old genuine one replayed, is obeyed.",
        {"owasp_asi_2026": ["ASI07:2026"], "atlas": ["AML.T0073"]},
        ["signed_messages"], ["asi07"]),
    "cascading-failure": _t(
        "Cascading failure", "multi_agent",
        "One bad value planted early is trusted by every downstream agent.",
        {"owasp_asi_2026": ["ASI08:2026"], "atlas": ["AML.T0048.000"]},
        ["cross_check", "circuit_breaker"], ["asi08"]),
    "rogue-agent": _t(
        "Rogue agent through tampered configuration", "multi_agent",
        "An agent's mandate is widened in an unauthenticated config store and it drifts off mandate.",
        {"owasp_asi_2026": ["ASI10:2026"], "atlas": ["AML.T0081"]},
        ["signed_config", "mandate_monitor"], ["asi10"]),

    # MCP protocol
    "mcp-sampling-abuse": _t(
        "MCP sampling abuse", "mcp",
        "A server uses sampling requests to run its own prompts on the client's model and budget. The HX03 "
        "lab also pulls the client's context back through includeContext and the sampled reply.",
        {"owasp_mcp_2025": ["MCP06:2025", "MCP10:2025"], "atlas": ["AML.T0053"]},
        ["sampling_policy", "input_screen", "output_screen"], ["hx03"]),
    "mcp-elicitation-abuse": _t(
        "MCP elicitation phishing", "mcp",
        "A server uses elicitation to ask the user for data it should never receive. The HX04 lab also has "
        "the client's model fill the form, a look-alike page in URL mode, and consent fatigue.",
        {"owasp_mcp_2025": ["MCP07:2025"], "owasp_asi_2026": ["ASI09:2026"]},
        ["elicitation_policy", "input_screen", "output_screen"], ["hx04"]),
    "oauth-confused-deputy": _t(
        "OAuth confused deputy through an MCP proxy", "mcp",
        "A proxy server's static client consent is reused to obtain tokens for another user. The HX05 lab "
        "also steals a code through a loosely matched redirect_uri.",
        {"owasp_mcp_2025": ["MCP07:2025"], "owasp_asi_2026": ["ASI03:2026"], "atlas": ["AML.T0091.000"]},
        ["delegated_token", "per_client_consent", "exact_redirect_uri", "pkce"], ["hx05"]),
    "mcp-token-passthrough": _t(
        "MCP token passthrough", "mcp",
        "A server accepts tokens not issued for it and forwards the client's token unchanged to downstream services.",
        {"owasp_mcp_2025": ["MCP01:2025", "MCP07:2025"], "owasp_asi_2026": ["ASI03:2026"]},
        ["audience_binding", "delegated_token"], ["hx05"]),
    "mcp-scope-creep": _t(
        "Scope creep in MCP permissions", "mcp",
        "Permissions granted for one task are kept and widened over time.",
        {"owasp_mcp_2025": ["MCP02:2025"], "owasp_asi_2026": ["ASI03:2026"]},
        ["delegated_token"], []),

    # Attacks on the scoring layer (AG-95)
    "judge-injection": _t(
        "Injection aimed at the judge", "scoring",
        "Text hidden in the evidence an LLM judge scores tells the judge what verdict to give.",
        {"owasp_llm_2026": ["LLM01:2026"], "atlas": ["AML.T0051.001"], "nist": ["NISTAML.015"]},
        [], []),
    "classifier-evasion": _t(
        "Inputs crafted to dodge the classifier", "scoring",
        "Attacks are reworded until the safety classifier scores them as benign.",
        {"atlas": ["AML.T0015"], "nist": ["NISTAML.025"]},
        ["generalization"], []),
    "false-positive-flood": _t(
        "False-positive flooding", "scoring",
        "Benign inputs that trip the screen are sent in bulk until operators turn it down or off.",
        {"atlas": ["AML.T0046"]},
        [], []),

    # Agentic commerce (AG-96)
    "payment-challenge-tamper": _t(
        "Tampered HTTP 402 payment challenge", "commerce",
        "The price or recipient in a 402 challenge is changed in transit or by a hostile merchant.",
        {"owasp_asi_2026": ["ASI02:2026"], "atlas": ["AML.T0048.000"]},
        [], []),
    "payment-proof-replay": _t(
        "Payment proof replay", "commerce",
        "A payment proof is reused for a second request or another merchant.",
        {"owasp_asi_2026": ["ASI03:2026"], "atlas": ["AML.T0048.000"]},
        [], []),
    "injected-overpayment": _t(
        "Injected overpayment", "commerce",
        "Injected text makes the agent accept a higher price or pay a different recipient.",
        {"owasp_asi_2026": ["ASI01:2026"], "owasp_llm_2026": ["LLM01:2026"], "atlas": ["AML.T0051.001"]},
        [], []),
    "payment-loop": _t(
        "Payment loop denial of wallet", "commerce",
        "Repeated 402 challenges drain the agent's wallet.",
        {"owasp_llm_2026": ["LLM06:2026"], "atlas": ["AML.T0034"]},
        ["rate_limit"], []),
    "fake-merchant": _t(
        "Fake merchant or facilitator", "commerce",
        "The agent pays a lookalike merchant or settles through a hostile facilitator.",
        {"owasp_asi_2026": ["ASI04:2026"], "atlas": ["AML.T0073"]},
        [], []),
    "mandate-bypass": _t(
        "Spending mandate bypass", "commerce",
        "The agent is talked past its spending limit or allow-list.",
        {"owasp_asi_2026": ["ASI10:2026"], "atlas": ["AML.T0048.000"]},
        ["mandate_monitor"], []),

    # Classic ML (AG-94; labs need a non-LLM target)
    "adversarial-examples": _t(
        "Adversarial examples", "classic_ml",
        "Small crafted changes to an input flip a model's prediction.",
        {"atlas": ["AML.T0043", "AML.T0015"], "nist": ["NISTAML.022", "NISTAML.025"]},
        [], []),
    "training-data-poisoning": _t(
        "Training-time data poisoning", "classic_ml",
        "Poisoned training data degrades the model or makes it fail on chosen inputs.",
        {"owasp_llm_2026": ["LLM05:2026"], "owasp_llm_2025": ["LLM04:2025"],
         "atlas": ["AML.T0020"], "nist": ["NISTAML.013", "NISTAML.024"]},
        [], []),
    "model-backdoor": _t(
        "Model backdoor", "classic_ml",
        "A trigger planted at training time, or in a published model, makes the model misbehave on cue.",
        {"owasp_llm_2026": ["LLM04:2026"], "owasp_llm_2025": ["LLM03:2025"],
         "atlas": ["AML.T0018.000", "AML.T0043.004"], "nist": ["NISTAML.023", "NISTAML.051"]},
        [], []),
}


def validate(skill_ids: Iterable[str] = ()) -> List[str]:
    """Problems with the catalog, one string each; empty when it is valid.

    ``skill_ids``, when given, are the discovered labs: every ``labs`` entry
    must be one of them.
    """
    skill_ids = list(skill_ids)
    known = set(skill_ids) | {LIVE_LAB}
    patterns = {key: re.compile(rf"^{pat}$") for key, _, _, pat in REF_LISTS}
    problems: List[str] = []
    for tid, tech in TECHNIQUES.items():
        where = f"{tid}:"
        if not re.match(r"^[a-z0-9]+(-[a-z0-9]+)*$", tid):
            problems.append(f"{where} id is not a lowercase slug")
        if set(tech) != set(FIELDS):
            problems.append(f"{where} fields {sorted(tech)} != {sorted(FIELDS)}")
            continue
        if tech["family"] not in FAMILIES:
            problems.append(f"{where} unknown family {tech['family']!r}")
        if not tech["refs"]:
            problems.append(f"{where} no list IDs")
        for key, ids in tech["refs"].items():
            if key not in patterns:
                problems.append(f"{where} unknown list {key!r}")
                continue
            if not ids:
                problems.append(f"{where} empty {key}")
            for ref in ids:
                if not patterns[key].match(ref):
                    problems.append(f"{where} {ref!r} is not a {key} ID")
        for cid in protections.unknown(tech["defenses"]):
            problems.append(f"{where} unknown defense {cid!r}")
        if skill_ids:
            for lab in tech["labs"]:
                if lab not in known:
                    problems.append(f"{where} unknown lab {lab!r}")
    return problems


def entry(technique_id: str) -> Dict[str, object]:
    tech = TECHNIQUES[technique_id]
    return {"id": technique_id, "title": tech["title"], "family": tech["family"], "summary": tech["summary"],
            "refs": {key: list(ids) for key, ids in tech["refs"].items()},
            "defenses": list(tech["defenses"]), "labs": list(tech["labs"])}


def library() -> List[Dict[str, object]]:
    return [entry(tid) for tid in TECHNIQUES]


def for_lab(skill_id: str) -> List[str]:
    """Technique ids a lab demonstrates."""
    return [tid for tid, tech in TECHNIQUES.items() if skill_id in tech["labs"]]


def by_ref(ref: str) -> List[str]:
    """Technique ids that carry list ID ``ref`` (e.g. ``"AML.T0051.001"``)."""
    return [tid for tid, tech in TECHNIQUES.items() if any(ref in ids for ids in tech["refs"].values())]


# Coverage (AG-91). A technique has "attack and defense" when a lab demonstrates
# it and a defense is declared, "attack only" when a lab demonstrates it but no
# defense is declared or the lab's latest run left impact after remediation,
# and "no lab yet" otherwise. Stored lab results feed it: ``latest`` is the
# newest run of each lab.
STATUSES = {
    "attack_and_defense": "Attack and defense",
    "attack_only": "Attack only",
    "no_lab": "No lab yet",
}


def latest_runs(docs: Iterable[dict]) -> Dict[str, dict]:
    """The newest result per lab id, from stored result documents (live runs are skipped)."""
    latest: Dict[str, dict] = {}
    for doc in docs:
        sid = (doc.get("skill") or {}).get("id")
        if not sid or "live" in doc or "summary" not in doc:
            continue
        if sid not in latest or doc.get("started_at", "") >= latest[sid].get("started_at", ""):
            latest[sid] = doc
    return latest


def _evidence(doc: dict) -> Dict[str, object]:
    summary = doc["summary"]
    return {"run_id": doc.get("run_id", ""), "backend": doc.get("model", {}).get("backend", ""),
            "model": doc.get("model", {}).get("model", ""), "status": summary.get("status", ""),
            "impact_rate": summary.get("impact_rate"), "remediated_rate": summary.get("remediated_rate")}


def coverage(docs: Iterable[dict] = ()) -> Dict[str, object]:
    """Every technique with its coverage status, plus counts by status and by list."""
    latest = latest_runs(docs)
    rows = []
    for tid in TECHNIQUES:
        row = entry(tid)
        runs = {lab: _evidence(latest[lab]) for lab in row["labs"] if lab in latest}
        leaky = [lab for lab, ev in runs.items() if (ev["remediated_rate"] or 0) > 0]
        if not row["labs"]:
            status = "no_lab"
        elif not row["defenses"] or leaky:
            status = "attack_only"
        else:
            status = "attack_and_defense"
        row.update(status=status, status_title=STATUSES[status], runs=runs, leaky_labs=leaky)
        rows.append(row)
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in STATUSES}
    by_list = {}
    for key, name, edition, _ in REF_LISTS:
        ids = sorted({ref for r in rows for ref in r["refs"].get(key, [])})
        with_lab = sorted({ref for r in rows if r["labs"] for ref in r["refs"].get(key, [])})
        by_list[key] = {"name": name, "edition": edition, "ids": len(ids), "with_lab": len(with_lab),
                        "without_lab": [ref for ref in ids if ref not in with_lab]}
    return {"techniques": rows, "total": len(rows), "counts": counts, "by_list": by_list,
            "families": FAMILIES, "statuses": STATUSES}
