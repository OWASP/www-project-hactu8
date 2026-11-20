"""Lab adapter: run a demo's ``run_demo.py`` and parse its four-act output.

Every lab prints the same shape (``demos/_template/TEMPLATE.md``):

    [*] Act 1 — Clean baseline
        <icon> GREEN  <prompt>            (targeted)
        <icon> GREEN  <prompt>  (control)
        <Metric Name>: 0% targeted
    [*] Act 2 — Attack: ...
    [+] attack step
    [defense] Act 4 — Remediation
    [defense] mitigation step
    [*] Act 4 — Re-run with mitigations

so one parser covers all labs. With ``HACTU8_EVIDENCE=1`` (set by ``run``) each
item line is followed by what the model produced, as one JSON string:

        evidence: "<answer, tool calls or steps>"

Items are classified after parsing, so a classifier sees the evidence.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from typing import List, Optional, Union

from hactu8 import protections
from hactu8.classify import Classifier, get_classifier
from hactu8.result import PHASES, envelope, now_iso, rate, summarize

ACT_RE = re.compile(r"^\[\*\] Act (\d) — (.+)$")
DEFENSE_ACT_RE = re.compile(r"^\[defense\] Act (\d) — (.+)$")
ITEM_RE = re.compile(r"^ {4}\S+ (GREEN|YELLOW|RED)\s+(.+?)(  \(control\))?$")
RATE_RE = re.compile(r"^ {4}(.+?): (\d+(?:\.\d+)?)% targeted")
NOTE_RE = re.compile(r"^\[(\+|defense)\] (.+)$")
EVIDENCE_RE = re.compile(r'^ {8}evidence: (".*")$')


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:48]


def parse(output: str, classifier: Union[str, Classifier] = "keyword", context: Optional[dict] = None) -> List[dict]:
    if isinstance(classifier, str):
        classifier = get_classifier(classifier)
    acts: List[dict] = []
    current: Optional[dict] = None

    def open_act(n: int, title: str) -> dict:
        for act in acts:
            if act["act"] == n:
                if title and not act["title"].endswith(title):
                    act["title"] = f'{act["title"]}; {title}' if act["title"] else title
                return act
        act = {"act": n, "phase": PHASES.get(n, "other"), "title": title, "notes": [], "items": [], "reported_rate": None}
        acts.append(act)
        return act

    for line in output.splitlines():
        if m := ACT_RE.match(line):
            current = open_act(int(m.group(1)), m.group(2).strip())
        elif m := DEFENSE_ACT_RE.match(line):
            current = open_act(int(m.group(1)), m.group(2).strip())
        elif current is not None and (m := EVIDENCE_RE.match(line)):
            if current["items"] and "evidence" not in current["items"][-1]:
                try:
                    current["items"][-1]["evidence"] = str(json.loads(m.group(1)))
                except ValueError:
                    pass
        elif current is not None and (m := ITEM_RE.match(line)):
            prompt = m.group(2).strip()
            current["items"].append({
                "id": f"{len(current['items']) + 1:02d}-{_slug(prompt)}",
                "prompt": prompt,
                "targeted": m.group(3) is None,
                "lab_verdict": m.group(1),
            })
        elif current is not None and (m := RATE_RE.match(line)):
            current["reported_rate"] = float(m.group(2))
        elif current is not None and (m := NOTE_RE.match(line)):
            note = m.group(2).strip()
            if not DEFENSE_ACT_RE.match(line):
                current["notes"].append(note)

    for act in acts:
        for item in act["items"]:
            v = classifier.classify(item["prompt"], item.get("evidence", ""), item["lab_verdict"],
                                    {**(context or {}), "act": act["act"], "phase": act["phase"],
                                     "targeted": item["targeted"]})
            item.update(verdict=v.verdict, confidence=v.confidence, reason=v.reason)
            if v.source:
                item["classified_by"] = v.source
        act["metric"] = {"targeted": rate(act["items"], True), "overall": rate(act["items"], False)}
    acts.sort(key=lambda a: a["act"])
    return acts


def attach_protections(acts: List[dict], ids: List[str]) -> None:
    """Put the lab's declared controls on its remediation act (Act 4 "Protections added").

    Unknown ids are skipped here so one typo cannot break a run; the test suite
    fails on any unknown id in a SKILL.md.
    """
    known = [cid for cid in ids if cid in protections.CATALOG]
    for act in acts:
        if act["phase"] == "remediation" and known:
            act["protections"] = protections.resolve(known)


def run(skill, backend: str = "echo", model: str = "", classifier: Union[str, Classifier] = "keyword",
        timeout: int = 300, tier: str = "") -> dict:
    if isinstance(classifier, str):
        classifier = get_classifier(classifier)
    doc = envelope(skill, backend, model, classifier.name)
    if tier:
        doc["model"]["tier"] = tier
    cmd = [sys.executable, "run_demo.py", "--backend", backend]
    if model:
        cmd += ["--model", model]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1", HACTU8_EVIDENCE="1")
    start = time.monotonic()
    try:
        proc = subprocess.run(cmd, cwd=skill.lab_dir, capture_output=True, text=True,
                              encoding="utf-8", timeout=timeout, env=env)
        output, code = proc.stdout + proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        output, code = (exc.stdout or "") if isinstance(exc.stdout, str) else "", 124
    doc["duration_ms"] = int((time.monotonic() - start) * 1000)
    doc["finished_at"] = now_iso()
    doc["acts"] = parse(output, classifier, {"risk": skill.risk, "metric": skill.metric_name})
    attach_protections(doc["acts"], getattr(skill, "protections", []))
    doc["classifier"] = classifier.info()
    doc["summary"] = summarize(doc["acts"], backend)
    doc["exit_code"] = code
    if code not in (0,) and doc["summary"]["status"] == "pass":
        doc["summary"]["status"] = "fail"
    doc["output"] = "\n".join(l for l in output.splitlines() if not EVIDENCE_RE.match(l))[-8000:]
    return doc
