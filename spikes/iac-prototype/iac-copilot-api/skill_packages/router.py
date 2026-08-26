"""FastAPI router for Skill Package install/discovery endpoints."""

import tempfile
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from models.skill_package import (
    SkillPackageInstallResponse,
    SkillPackageListResponse,
    SkillPackageUninstallResponse,
)
from skill_packages.installer import (
    MAX_ZIP_BYTES,
    SkillInstallError,
    SkillPackageAlreadyInstalled,
    SkillPackageNotFound,
    install_skill_package,
    list_skill_packages,
    uninstall_skill_package,
)

router = APIRouter(prefix="/skill-packages", tags=["skill-packages"])


@router.post("", response_model=SkillPackageInstallResponse, status_code=201)
async def install_skill(
    file: UploadFile = File(...),
    overwrite: bool = Form(False),
) -> SkillPackageInstallResponse:
    # Bounded read — never buffer more than MAX_ZIP_BYTES + 1 into memory,
    # regardless of what the client claims the file's size is.
    content = await file.read(MAX_ZIP_BYTES + 1)
    if len(content) > MAX_ZIP_BYTES:
        raise HTTPException(status_code=413, detail=f"Skill package exceeds {MAX_ZIP_BYTES} byte limit")
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    with tempfile.NamedTemporaryFile(suffix=".zip", delete=True) as tmp:
        tmp.write(content)
        tmp.flush()
        try:
            skill = install_skill_package(
                Path(tmp.name),
                source_filename=file.filename or "upload.skill",
                overwrite=overwrite,
            )
        except SkillPackageAlreadyInstalled as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except SkillInstallError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    return SkillPackageInstallResponse(skill=skill, warnings=[])


@router.get("", response_model=SkillPackageListResponse)
async def list_skills(include_host: bool = False) -> SkillPackageListResponse:
    skills = list_skill_packages(include_host=include_host)
    return SkillPackageListResponse(skills=skills, total=len(skills))


@router.delete("/{name}", response_model=SkillPackageUninstallResponse)
async def uninstall_skill(name: str) -> SkillPackageUninstallResponse:
    try:
        uninstall_skill_package(name)
    except SkillPackageNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except SkillInstallError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return SkillPackageUninstallResponse(success=True, name=name)
