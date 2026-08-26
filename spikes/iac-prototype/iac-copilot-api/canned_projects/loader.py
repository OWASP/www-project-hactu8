"""Loads curated Project definitions from canned_projects/<project-id>/ —
project.json + overview.md + instructions.md. Repo-committed, read-only,
same "ships with the product" posture as HOST_SKILLS_DIR. Fail-soft: a
malformed project directory is skipped with a log warning, not a crash,
matching skill_packages/runner.py's discovery posture.
"""

import json
import logging
from pathlib import Path
from typing import List, Optional

from iac_paths import CANNED_PROJECTS_DIR
from canned_projects.models import CannedProjectDetail, CannedProjectManifest, CannedProjectSummary

logger = logging.getLogger(__name__)


def _load_manifest(project_dir: Path) -> Optional[CannedProjectManifest]:
    manifest_path = project_dir / "project.json"
    if not manifest_path.is_file():
        logger.warning("Skipping %s: no project.json", project_dir)
        return None
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest = CannedProjectManifest(**raw)
    except Exception as exc:
        logger.warning("Skipping %s: invalid project.json (%s)", project_dir, exc)
        return None

    if manifest.id != project_dir.name:
        logger.warning(
            "Skipping %s: project.json id %r must match directory name %r",
            project_dir, manifest.id, project_dir.name,
        )
        return None
    return manifest


def list_canned_projects() -> List[CannedProjectSummary]:
    if not CANNED_PROJECTS_DIR.is_dir():
        return []

    summaries: List[CannedProjectSummary] = []
    for entry in sorted(CANNED_PROJECTS_DIR.iterdir()):
        if not entry.is_dir():
            continue
        manifest = _load_manifest(entry)
        if manifest is None:
            continue
        summaries.append(
            CannedProjectSummary(
                id=manifest.id,
                name=manifest.name,
                category=manifest.category,
                summary=manifest.summary,
                default_skill_names=manifest.default_skill_names,
                legacy_route=manifest.legacy_route,
            )
        )
    return summaries


def get_canned_project(project_id: str) -> Optional[CannedProjectDetail]:
    project_dir = CANNED_PROJECTS_DIR / project_id
    if not project_dir.is_dir():
        return None
    manifest = _load_manifest(project_dir)
    if manifest is None:
        return None

    overview_path = project_dir / "overview.md"
    instructions_path = project_dir / "instructions.md"
    overview_md = overview_path.read_text(encoding="utf-8") if overview_path.is_file() else ""
    instructions_md = instructions_path.read_text(encoding="utf-8") if instructions_path.is_file() else ""

    return CannedProjectDetail(
        id=manifest.id,
        name=manifest.name,
        category=manifest.category,
        summary=manifest.summary,
        default_skill_names=manifest.default_skill_names,
        legacy_route=manifest.legacy_route,
        resources=manifest.resources,
        overview_md=overview_md,
        instructions_md=instructions_md,
    )
