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

An item where no harm got through but a later layer had to hold (a reply
withheld, an action denied, budget spent off the task) may carry one more
line, printed always. It is not a colour; it lands in the item's ``held_by``:

        held_by: <what held>; <another>

A lab whose call to the model under test failed for an item (the server
answered an HTTP error, the connection dropped) prints that item as ERROR,
with the error as its evidence:

        <icon> ERROR  <prompt>
        evidence: "<the model call error>"

ERROR is not a grade. No classifier sees the item, and it counts in neither
the red count nor the total of the act's rate (``result.rate``).

Items are classified after parsing, so a classifier sees the evidence.

Lines are split on ``\n`` only (``lines``), never on the other characters
``str.splitlines`` treats as breaks (``\r``, ``\v``, ``\f``, ``\x1c``-``\x1e``,
``\x85``, U+2028, U+2029), so model text inside an evidence line cannot start a
new line. The labs' ``evidence()`` prints ASCII-only JSON, where those
characters are escaped anyway; a structural line (act, item, rate, note,
held_by) that still carries one of them is ignored, never parsed.

A run that hits the timeout is parsed from what the lab printed before it was
stopped (``exc.stdout`` is bytes and is decoded): the items seen keep their
grades, so a RED observed before the timeout is kept, each act's rate covers
only the items it printed, and the summary is ``status: error`` with
``timed_out: true``, never pass or fail.

On a real backend ``model.think`` records the reasoning control
(``providers.think_setting``) and, when the model returned reasoning apart
from its answer, the totals of the labs' ``hactu8.reasoning {json}`` stderr
lines. That reasoning is never graded (the app never shows it); a canary in it
is counted in ``canary_hits`` so it is not hidden.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from typing import List, Optional, Union

from hactu8 import protections, providers
from hactu8.classify import ERROR, Classifier, get_classifier
from hactu8.result import PHASES, envelope, now_iso, rate, summarize

ACT_RE = re.compile(r"^\[\*\] Act (\d) — (.+)$")
DEFENSE_ACT_RE = re.compile(r"^\[defense\] Act (\d) — (.+)$")
ITEM_RE = re.compile(r"^ {4}\S+ (GREEN|YELLOW|RED|ERROR)\s+(.+?)(  \(control\))?$")
RATE_RE = re.compile(r"^ {4}(.+?): (\d+(?:\.\d+)?)% targeted")
NOTE_RE = re.compile(r"^\[(\+|defense)\] (.+)$")
EVIDENCE_RE = re.compile(r'^ {8}evidence: (".*")$')
HELD_BY_RE = re.compile(r"^ {8}held_by: (.+)$")


# Characters str.splitlines() breaks on besides "\n" (and a trailing "\r").
_FOREIGN_BREAKS = re.compile("[\r\v\f\x1c-\x1e\x85\u2028\u2029]")


def lines(output: str) -> List[str]:
    """Split on "\n" only; a CRLF's "\r" is dropped."""
    return [line[:-1] if line.endswith("\r") else line for line in output.split("\n")]


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

    for line in lines(output):
        if _FOREIGN_BREAKS.search(line) and not EVIDENCE_RE.match(line):
            continue  # a structural line never holds these: text smuggled out of a payload
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
        elif current is not None and (m := HELD_BY_RE.match(line)):
            if current["items"] and "held_by" not in current["items"][-1]:
                held = [h.strip() for h in m.group(1).split(";") if h.strip()]
                if held:
                    current["items"][-1]["held_by"] = held
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
            if item["lab_verdict"] == ERROR:
                item.update(verdict=ERROR, confidence=0.0, reason="model call failed in the lab; not graded",
                            classified_by="lab")
                continue
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


REASONING_RE = re.compile(r"^" + re.escape(providers.REASONING.LINE) + r" (\{.*\})\s*$")
REASONING_KEYS = ("replies", "chars", "answer_cut_off", "canary_hits")


def reasoning_totals(output: str) -> dict:
    """Sum the ``hactu8.reasoning`` lines (one per lab process that saw reasoning)."""
    total = {k: 0 for k in REASONING_KEYS}
    seen = False
    for line in lines(output):
        m = REASONING_RE.match(line)
        if not m:
            continue
        try:
            data = json.loads(m.group(1))
        except ValueError:
            continue
        seen = True
        for k in REASONING_KEYS:
            if isinstance(data.get(k), int):
                total[k] += data[k]
    return total if seen else {}


def _text(data) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return data


def run(skill, backend: str = "echo", model: str = "", classifier: Union[str, Classifier] = "keyword",
        timeout: int = 300, tier: str = "") -> dict:
    if isinstance(classifier, str):
        classifier = get_classifier(classifier)
    doc = envelope(skill, backend, model, classifier.name)
    if tier:
        doc["model"]["tier"] = tier
    if providers.normalize(backend) != providers.OFFLINE:
        doc["model"]["think"] = providers.think_setting(backend)
    cmd = [sys.executable, "run_demo.py", "--backend", backend]
    if model:
        cmd += ["--model", model]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1", HACTU8_EVIDENCE="1")
    start = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run(cmd, cwd=skill.lab_dir, capture_output=True, text=True,
                              encoding="utf-8", timeout=timeout, env=env)
        output, code = proc.stdout + proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        # The partial output comes back as bytes even with text=True: keep what was printed.
        output, code, timed_out = _text(exc.stdout) + _text(exc.stderr), 124, True
    doc["duration_ms"] = int((time.monotonic() - start) * 1000)
    doc["finished_at"] = now_iso()
    # The lab's own providers.py redacts at the source; this catches anything else
    # (a traceback, a lab's own print) before it becomes evidence, a reason or the tail.
    output = providers.redact(output)
    reasoning = reasoning_totals(output)
    if reasoning and "think" in doc["model"]:
        doc["model"]["think"]["reasoning"] = reasoning
    output = "\n".join(l for l in lines(output) if not REASONING_RE.match(l))
    doc["acts"] = parse(output, classifier, {"risk": skill.risk, "metric": skill.metric_name})
    attach_protections(doc["acts"], getattr(skill, "protections", []))
    doc["classifier"] = classifier.info()
    doc["summary"] = summarize(doc["acts"], backend)
    doc["exit_code"] = code
    if timed_out:
        doc["summary"].update(status="error", timed_out=True)
    elif code not in (0,) and doc["summary"]["status"] == "pass":
        doc["summary"]["status"] = "fail"
    doc["output"] = "\n".join(l for l in lines(output) if not EVIDENCE_RE.match(l))[-8000:]
    return doc
