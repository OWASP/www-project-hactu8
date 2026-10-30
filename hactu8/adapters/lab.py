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

so one parser covers all labs without changing them.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from typing import List, Optional

from hactu8.classify import get_classifier
from hactu8.result import PHASES, envelope, now_iso, rate, summarize

ACT_RE = re.compile(r"^\[\*\] Act (\d) — (.+)$")
DEFENSE_ACT_RE = re.compile(r"^\[defense\] Act (\d) — (.+)$")
ITEM_RE = re.compile(r"^ {4}\S+ (GREEN|YELLOW|RED)\s+(.+?)(  \(control\))?$")
RATE_RE = re.compile(r"^ {4}(.+?): (\d+(?:\.\d+)?)% targeted")
NOTE_RE = re.compile(r"^\[(\+|defense)\] (.+)$")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:48]


def parse(output: str, classifier_name: str = "keyword") -> List[dict]:
    classifier = get_classifier(classifier_name)
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
        elif current is not None and (m := ITEM_RE.match(line)):
            prompt = m.group(2).strip()
            v = classifier.classify(prompt, lab_verdict=m.group(1))
            current["items"].append({
                "id": f"{len(current['items']) + 1:02d}-{_slug(prompt)}",
                "prompt": prompt,
                "targeted": m.group(3) is None,
                "verdict": v.verdict,
                "confidence": v.confidence,
                "reason": v.reason,
            })
        elif current is not None and (m := RATE_RE.match(line)):
            current["reported_rate"] = float(m.group(2))
        elif current is not None and (m := NOTE_RE.match(line)):
            note = m.group(2).strip()
            if not DEFENSE_ACT_RE.match(line):
                current["notes"].append(note)

    for act in acts:
        act["metric"] = {"targeted": rate(act["items"], True), "overall": rate(act["items"], False)}
    acts.sort(key=lambda a: a["act"])
    return acts


def run(skill, backend: str = "echo", model: str = "", classifier: str = "keyword", timeout: int = 300) -> dict:
    doc = envelope(skill, backend, model, classifier)
    cmd = [sys.executable, "run_demo.py", "--backend", backend]
    if model:
        cmd += ["--model", model]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
    start = time.monotonic()
    try:
        proc = subprocess.run(cmd, cwd=skill.lab_dir, capture_output=True, text=True,
                              encoding="utf-8", timeout=timeout, env=env)
        output, code = proc.stdout + proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        output, code = (exc.stdout or "") if isinstance(exc.stdout, str) else "", 124
    doc["duration_ms"] = int((time.monotonic() - start) * 1000)
    doc["finished_at"] = now_iso()
    doc["acts"] = parse(output, classifier)
    doc["summary"] = summarize(doc["acts"], backend)
    doc["exit_code"] = code
    if code not in (0,) and doc["summary"]["status"] == "pass":
        doc["summary"]["status"] = "fail"
    doc["output"] = output[-8000:]
    return doc
