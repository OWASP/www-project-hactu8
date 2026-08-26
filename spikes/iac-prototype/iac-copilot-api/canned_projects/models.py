"""Models for curated ("canned") Projects — authored by the HACTU8 core team,
read from JSON + Markdown files in canned_projects/<project-id>/, not
uploaded/packaged like Skill Packages.
"""

from typing import List, Optional

from pydantic import BaseModel


class ProjectResource(BaseModel):
    title: str
    description: Optional[str] = None
    url: Optional[str] = None


class CannedProjectManifest(BaseModel):
    """Matches project.json exactly."""
    id: str
    name: str
    category: str
    summary: str
    resources: List[ProjectResource] = []
    default_skill_names: List[str] = []
    legacy_route: Optional[str] = None
    version: str = "1.0.0"


class CannedProjectSummary(BaseModel):
    """List-view shape — no prose bodies."""
    id: str
    name: str
    category: str
    summary: str
    default_skill_names: List[str] = []
    legacy_route: Optional[str] = None


class CannedProjectDetail(CannedProjectSummary):
    resources: List[ProjectResource] = []
    overview_md: str
    instructions_md: str


class CannedProjectListResponse(BaseModel):
    projects: List[CannedProjectSummary]
    total: int
