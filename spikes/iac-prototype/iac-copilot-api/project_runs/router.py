"""FastAPI router for Project run endpoints — create a run, send a message
(SSE-streamed), get status/full state. Mirrors agents/router.py's
persistence pattern (JSON file per run under PROJECT_RUNS_DIR)."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from canned_projects.loader import get_canned_project
from iac_paths import PROJECT_RUNS_DIR
from project_runs.engine import run_turn
from project_runs.models import (
    CreateRunRequest,
    CreateRunResponse,
    ProjectRunScope,
    ProjectRunState,
    ProjectRunStatus,
    ProjectRunTurn,
    SendMessageRequest,
)

router = APIRouter(tags=["project-runs"])


def _state_path(run_id: str) -> Path:
    return PROJECT_RUNS_DIR / run_id / "state.json"


def _load_state(run_id: str) -> ProjectRunState:
    path = _state_path(run_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Project run {run_id!r} not found")
    with open(path) as f:
        return ProjectRunState.model_validate_json(f.read())


def _save_state(state: ProjectRunState) -> None:
    path = _state_path(state.run_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    state.updated_at = datetime.utcnow()
    with open(path, "w") as f:
        f.write(state.model_dump_json(indent=2))


@router.post("/projects/{project_id}/runs", response_model=CreateRunResponse, status_code=201)
async def create_run(project_id: str, request: CreateRunRequest) -> CreateRunResponse:
    project = get_canned_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail=f"Canned project {project_id!r} not found")

    scope = ProjectRunScope(
        project_id=project.id,
        project_name=project.name,
        target=request.target,
        skill_names=request.skill_names,
        model=request.model,
    )
    state = ProjectRunState(scope=scope)
    _save_state(state)
    return CreateRunResponse(run_id=state.run_id, status=state.status)


@router.get("/project-runs/{run_id}", response_model=ProjectRunState)
async def get_run(run_id: str) -> ProjectRunState:
    return _load_state(run_id)


@router.get("/project-runs/{run_id}/status")
async def get_run_status(run_id: str) -> Dict[str, Any]:
    state = _load_state(run_id)
    return {
        "run_id": state.run_id,
        "status": state.status,
        "turn_count": len(state.turns),
        "error": state.error,
        "updated_at": state.updated_at.isoformat(),
    }


@router.post("/project-runs/{run_id}/messages")
async def send_message(run_id: str, request: SendMessageRequest) -> StreamingResponse:
    state = _load_state(run_id)
    if state.status == ProjectRunStatus.RUNNING:
        raise HTTPException(status_code=409, detail="Project run is already processing a message")

    project = get_canned_project(state.scope.project_id)
    instructions_md = project.instructions_md if project else ""
    overview_md = project.overview_md if project else ""

    async def event_stream():
        state.status = ProjectRunStatus.RUNNING
        _save_state(state)

        user_turn = ProjectRunTurn(role="user", content=request.content)
        prior_turns = list(state.turns)

        assistant_text_parts = []
        try:
            async for event in run_turn(state.scope, prior_turns, request.content, instructions_md, overview_md):
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("type") == "text":
                    assistant_text_parts.append(event["content"])
                elif event.get("type") == "complete":
                    state.turns.append(user_turn)
                    state.turns.append(ProjectRunTurn(role="assistant", content=event.get("content", "")))
                    state.findings.extend(event.get("findings", []))
                    state.status = ProjectRunStatus.AWAITING_INPUT
                    state.error = None
                    _save_state(state)
                    return
                elif event.get("type") == "error":
                    state.status = ProjectRunStatus.FAILED
                    state.error = event.get("message")
                    _save_state(state)
                    return
        except Exception as exc:
            err_msg = str(exc) or f"{type(exc).__name__} (no detail)"
            state.status = ProjectRunStatus.FAILED
            state.error = err_msg
            _save_state(state)
            yield f"data: {json.dumps({'type': 'error', 'message': err_msg})}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
