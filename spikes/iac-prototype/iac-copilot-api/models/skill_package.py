"""Models for Skill Packages — real, filesystem-backed skill directories that
conform to the agentskills.io Agent Skills specification. Distinct from the
legacy frontend "Skills" concept and from the `skills/` tool-registry package
used by the agent engagement loop.
"""

from datetime import datetime
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel


class SkillPackageManifest(BaseModel):
    """Matches the SKILL.md YAML frontmatter fields defined by
    https://agentskills.io/specification."""
    name: str
    description: str
    license: Optional[str] = None
    compatibility: Optional[str] = None
    metadata: Optional[Dict[str, str]] = None
    allowed_tools: Optional[str] = None


class InstalledSkillPackage(BaseModel):
    """Lightweight record of a skill package installed on disk. Mirrors what's
    actually at `install_path` — not a cache the frontend should trust over
    the filesystem."""
    name: str
    install_path: str
    installed_at: datetime
    source: Literal["upload", "host"] = "upload"
    source_filename: Optional[str] = None
    sha256: Optional[str] = None
    manifest: SkillPackageManifest
    files: List[str] = []


class SkillPackageInstallResponse(BaseModel):
    skill: InstalledSkillPackage
    warnings: List[str] = []


class SkillPackageListResponse(BaseModel):
    skills: List[InstalledSkillPackage]
    total: int


class SkillPackageUninstallResponse(BaseModel):
    success: bool
    name: str
