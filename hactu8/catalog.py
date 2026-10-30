"""Discover runnable skills.

Phase 1 discovers the labs under ``demos/``: every ``<lab>/run_demo.py`` whose
``SKILL_DIR`` points at a skill directory with a ``SKILL.md``. HACTU8 facts come
from the skill's ``metadata.hactu8.*`` keys.
"""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional

from hactu8.skillmeta import read_frontmatter

_SKILL_DIR_RE = re.compile(r'SKILL_DIR = os\.path\.join\(HERE, "([^"]+)"\)')


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
        ))
    return skills


def get(skill_id: str, root: Optional[Path] = None) -> Skill:
    wanted = skill_id.lower().split(":")[0]
    for skill in discover(root):
        if wanted in (skill.id, skill.name, Path(skill.lab_dir).name):
            return skill
    raise KeyError(f"unknown skill: {skill_id}")
