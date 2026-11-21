"""Discover runnable skills.

Phase 1 discovers the labs under ``demos/``: every ``<lab>/run_demo.py`` whose
``SKILL_DIR`` points at a skill directory with a ``SKILL.md``. HACTU8 facts come
from the skill's ``metadata.hactu8.*`` keys; ``hactu8.protections`` lists the
Act 4 controls by id from ``hactu8/protections.py``.

Learning path (AG-63): ``hactu8.path: "<stage>:<n>"`` places a lab at position
``n`` (1-based) within a stage of ``STAGES``. The track is the stages in order,
then ``n`` within each stage. A lab without a valid ``hactu8.path`` is left out
of the track (and fails the repo test). ``has_lesson`` is true when the skill
folder holds a ``LESSON.md`` (see ``hactu8/lessons.py``).
"""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from hactu8.lessons import has_lesson
from hactu8.protections import parse_ids
from hactu8.skillmeta import read_frontmatter

_SKILL_DIR_RE = re.compile(r'SKILL_DIR = os\.path\.join\(HERE, "([^"]+)"\)')

# Learning-path stages, in order: (id, title, what it covers). A stage may be
# empty until its labs exist.
STAGES: Tuple[Tuple[str, str, str], ...] = (
    ("basics", "Basics", "Single-model attacks: prompt injection, output handling, disclosure, poisoning."),
    ("agentic", "Agentic", "Agents with tools, MCP servers and gateways, memory, and agent-to-agent traffic."),
    ("commerce", "Commerce and scoring", "Agent payments and attacks on the scoring layer."),
)
STAGE_IDS = tuple(stage[0] for stage in STAGES)


def parse_path(value: str) -> Tuple[str, int]:
    """``"basics:3"`` -> ``("basics", 3)``; anything malformed or unknown -> ``("", 0)``."""
    stage, _, order = (value or "").strip().partition(":")
    stage = stage.strip().lower()
    if stage not in STAGE_IDS or not order.strip().isdigit() or int(order) < 1:
        return "", 0
    return stage, int(order)


@dataclass
class Skill:
    id: str
    name: str
    version: str
    owasp: str
    risk: str
    metric: str
    metric_name: str
    target: str
    port: str
    lab_dir: str
    skill_dir: str
    description: str
    protections: List[str] = field(default_factory=list)
    path_stage: str = ""
    path_order: int = 0
    has_lesson: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def find_root(start: Optional[Path] = None) -> Path:
    """Repo root: $HACTU8_ROOT, else the nearest parent holding demos/, else the package's parent."""
    env = os.environ.get("HACTU8_ROOT")
    if env:
        return Path(env).resolve()
    here = (start or Path.cwd()).resolve()
    for candidate in (here, *here.parents):
        if (candidate / "demos").is_dir() and (candidate / "hactu8").is_dir():
            return candidate
    return Path(__file__).resolve().parents[1]


def _skill_id(owasp: str, lab_dir: str) -> str:
    if owasp:
        return owasp.split(":")[0].lower()
    return lab_dir.replace("owasp-", "").replace("-demo", "")


def discover(root: Optional[Path] = None) -> List[Skill]:
    root = root or find_root()
    demos = root / "demos"
    skills: List[Skill] = []
    for runner in sorted(demos.glob("*/run_demo.py")):
        lab = runner.parent
        match = _SKILL_DIR_RE.search(runner.read_text(encoding="utf-8"))
        if not match:
            continue
        skill_dir = lab / match.group(1)
        manifest = skill_dir / "SKILL.md"
        if not manifest.is_file():
            continue
        fm = read_frontmatter(manifest)
        meta = fm.get("metadata", {}) or {}
        owasp = meta.get("hactu8.owasp", "")
        stage, order = parse_path(meta.get("hactu8.path", ""))
        skills.append(Skill(
            id=_skill_id(owasp, lab.name),
            name=str(fm.get("name", skill_dir.name)),
            version=meta.get("version", ""),
            owasp=owasp,
            risk=meta.get("hactu8.risk", ""),
            metric=meta.get("hactu8.metric", ""),
            metric_name=meta.get("hactu8.metric-name", ""),
            target=meta.get("hactu8.target", "lab"),
            port=meta.get("hactu8.port", ""),
            lab_dir=str(lab),
            skill_dir=str(skill_dir),
            description=str(fm.get("description", "")),
            protections=parse_ids(meta.get("hactu8.protections", "")),
            path_stage=stage,
            path_order=order,
            has_lesson=has_lesson(skill_dir),
        ))
    return skills


def get(skill_id: str, root: Optional[Path] = None) -> Skill:
    wanted = skill_id.lower().split(":")[0]
    for skill in discover(root):
        if wanted in (skill.id, skill.name, Path(skill.lab_dir).name):
            return skill
    raise KeyError(f"unknown skill: {skill_id}")


def path_order(skills: List[Skill]) -> List[Skill]:
    """The labs on the learning path, in track order (stage, then position)."""
    on_path = [s for s in skills if s.path_stage]
    return sorted(on_path, key=lambda s: (STAGE_IDS.index(s.path_stage), s.path_order, s.id))


def learning_path(skills: List[Skill]) -> dict:
    """The track as data: every stage (empty ones too), each lab with its 1-based global step."""
    ordered = path_order(skills)
    stages = [{"id": sid, "title": title, "summary": summary, "skills": []} for sid, title, summary in STAGES]
    by_id = {stage["id"]: stage for stage in stages}
    for step, skill in enumerate(ordered, start=1):
        by_id[skill.path_stage]["skills"].append({
            "step": step, "order": skill.path_order, "id": skill.id, "owasp": skill.owasp,
            "risk": skill.risk, "has_lesson": skill.has_lesson,
        })
    unassigned = sorted(s.id for s in skills if not s.path_stage)
    return {"stages": stages, "total": len(ordered), "unassigned": unassigned}
