"""AG-92: the defense catalog.

Each defense (a control in ``hactu8/protections.py``) is linked to the attack
techniques it covers (``hactu8/techniques.py``) and to the evidence that it
works:

- bench evidence: the ProtectoGW bench items on the surfaces the defense
  screens (caught, missed, false positives). Control items the bench lists but
  does not score are named, not counted.
- lab evidence: the newest stored run of each lab whose hardened mode applies
  the defense (``hactu8.protections`` in SKILL.md). It counts only when that
  run had impact and remediation brought it to 0; a lab not yet run is no
  evidence.

Techniques with no defense are reported as gaps.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from hactu8 import protections, techniques

KINDS = {
    "protectogw_rule": "ProtectoGW rule",
    "gateway_control": "Gateway control",
    "lab_hardening": "Lab hardening",
    "architectural": "Architectural control",
}

KIND: Dict[str, str] = {
    # Content screens built on ProtectoGW's rules.
    "input_screen": "protectogw_rule", "output_screen": "protectogw_rule", "normalizer": "protectogw_rule",
    "full_artifact_screen": "protectogw_rule", "channel_screen": "protectogw_rule",
    "session_screen": "protectogw_rule", "generalization": "protectogw_rule", "persona_screen": "protectogw_rule",
    # Checks the MCP gateway applies to what passes through it.
    "mcp_gateway_filter": "gateway_control", "hash_pin": "gateway_control", "sampling": "gateway_control",
    "canary_tripwire": "gateway_control",
    # Runtime policies a lab's hardened mode adds to the application.
    "hitl_gate": "lab_hardening", "param_policy": "lab_hardening", "plan_pin": "lab_hardening",
    "rate_limit": "lab_hardening", "grounding": "lab_hardening", "cross_check": "lab_hardening",
    "circuit_breaker": "lab_hardening", "faithful_approval": "lab_hardening", "mandate_monitor": "lab_hardening",
    "action_policy": "lab_hardening", "sampling_policy": "lab_hardening", "elicitation_policy": "lab_hardening",
    "shot_cap": "lab_hardening", "query_anomaly": "lab_hardening", "output_watermark": "lab_hardening",
    # Design changes: where data lives, who acts, how trust is established.
    "spotlight": "architectural", "secret_vault": "architectural", "scope_filter": "architectural",
    "delegated_token": "architectural", "signed_messages": "architectural", "signed_config": "architectural",
    "code_sandbox": "architectural", "output_sink": "architectural", "provenance": "architectural",
    "exact_name": "architectural", "visible_text_only": "architectural", "label_only": "architectural",
}

EVIDENCE = {
    "bench_and_lab": "Bench and lab run",
    "lab": "Lab run",
    "bench": "Bench only",
    "none": "No evidence yet",
}

# Bench surfaces each defense is scored on. ``TRAIN`` and ``HELD_OUT`` stand
# for the training set (t1: items) and the independent held-out set.
TRAIN = "train set"
HELD_OUT = "held-out set"
BENCH_SURFACES: Dict[str, List[str]] = {
    "input_screen": ["tool_result", "resource_body", "okf_body", "okf_clean", "a2a_message", "document_hidden", "wild",
                     TRAIN],
    "mcp_gateway_filter": ["tool_description", "schema_param"],
    "channel_screen": ["schema_param", "error_channel", "okf_frontmatter"],
    "normalizer": ["obfuscation"],
    "full_artifact_screen": ["depth_tail"],
    "session_screen": ["okf_chain", "chain_pointer", "chain_destination", "chain_clean", "conversation"],
    "sampling": ["conditional_return"],
    "sampling_policy": ["sampling_request"],
    "elicitation_policy": ["elicitation_request"],
    "persona_screen": ["chat_message"],
    "hash_pin": ["prompt_template"],
    "output_sink": ["output_sink"],
    "generalization": [HELD_OUT],
}

# Bench control items (listed, not scored by screen()); the lab is the evidence.
BENCH_CONTROLS: Dict[str, List[str]] = {
    "hash_pin": ["post_approval_swap"],
    "rate_limit": ["consumption"],
    "hitl_gate": ["agency_gate"],
    "grounding": ["grounding"],
    "scope_filter": ["retrieval_scope"],
}


def _surface(item) -> str:
    if item.id.startswith("h2:"):
        return HELD_OUT
    if item.id.startswith("t1:"):
        return TRAIN
    return item.surface


def bench_evidence(items: Iterable) -> Dict[str, Dict[str, object]]:
    """Per defense: counts over the bench items on its surfaces. ``items`` are ``bench.run().items``."""
    by_surface: Dict[str, list] = {}
    for item in items:
        by_surface.setdefault(_surface(item), []).append(item)
    out = {}
    for cid, surfaces in BENCH_SURFACES.items():
        scored = [i for s in surfaces for i in by_surface.get(s, [])]
        attacks = [i for i in scored if i.attack]
        out[cid] = {"surfaces": surfaces, "attacks": len(attacks), "caught": sum(i.flagged for i in attacks),
                    "clean": sum(1 for i in scored if not i.attack),
                    "false_positives": sum(1 for i in scored if not i.attack and i.flagged)}
    return out


def report(skills: Iterable = (), docs: Iterable[dict] = (), bench_items: Optional[Iterable] = None) -> Dict[str, object]:
    """Every defense with the techniques it covers and its evidence, plus the techniques with no defense.

    ``skills`` are ``catalog.discover()`` results; ``docs`` are stored result
    documents; ``bench_items`` are ``bench.run().items`` (None: bench not run).
    """
    latest = techniques.latest_runs(docs)
    bench = bench_evidence(bench_items) if bench_items is not None else {}
    labs_by_defense: Dict[str, List[str]] = {}
    for skill in skills:
        for cid in skill.protections:
            labs_by_defense.setdefault(cid, []).append(skill.id)
    for cid in protections.LIVE:
        labs_by_defense.setdefault(cid, []).append(techniques.LIVE_LAB)
    rows = []
    for cid in protections.CATALOG:
        covers = [tid for tid, tech in techniques.TECHNIQUES.items() if cid in tech["defenses"]]
        labs = labs_by_defense.get(cid, [])
        runs = {lab: techniques._evidence(latest[lab]) for lab in labs if lab in latest}
        bench_row = bench.get(cid)
        has_bench = bool(bench_row and bench_row["attacks"])
        # A lab is evidence only when its newest run had impact that remediation brought to 0.
        shown = [lab for lab, ev in runs.items() if (ev["impact_rate"] or 0) > 0 and ev["remediated_rate"] == 0]
        if has_bench and shown:
            evidence = "bench_and_lab"
        elif shown:
            evidence = "lab"
        elif has_bench:
            evidence = "bench"
        else:
            evidence = "none"
        rows.append({"id": cid, "title": protections.CATALOG[cid]["title"], "kind": KIND[cid],
                     "kind_title": KINDS[KIND[cid]], "techniques": covers, "labs": labs, "runs": runs,
                     "shown_by": shown, "bench": bench_row, "bench_controls": BENCH_CONTROLS.get(cid, []),
                     "evidence": evidence, "evidence_title": EVIDENCE[evidence]})
    gaps = [{"id": tid, "title": tech["title"], "family": tech["family"]}
            for tid, tech in techniques.TECHNIQUES.items() if not tech["defenses"]]
    return {"defenses": rows, "total": len(rows), "gaps": gaps, "kinds": KINDS, "evidence": EVIDENCE,
            "bench_run": bench_items is not None}
