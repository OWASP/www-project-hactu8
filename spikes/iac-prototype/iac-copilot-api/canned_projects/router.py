"""FastAPI router for curated Project discovery."""

from fastapi import APIRouter, HTTPException

from canned_projects.loader import get_canned_project, list_canned_projects
from canned_projects.models import CannedProjectDetail, CannedProjectListResponse

router = APIRouter(prefix="/canned-projects", tags=["canned-projects"])


@router.get("", response_model=CannedProjectListResponse)
async def list_projects() -> CannedProjectListResponse:
    projects = list_canned_projects()
    return CannedProjectListResponse(projects=projects, total=len(projects))


@router.get("/{project_id}", response_model=CannedProjectDetail)
async def get_project(project_id: str) -> CannedProjectDetail:
    project = get_canned_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail=f"Canned project {project_id!r} not found")
    return project
