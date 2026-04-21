"""FastAPI router for IAC agent engagement endpoints."""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from agents.models import (
    EngagementScope,
    EngagementState,
    EngagementStatus,
    PhaseEnum,
)
from agents.phase1_planning import KickOffAgent, ReconAgent, RiskAssessmentAgent
from skills.registry import skill_registry

router = APIRouter(prefix="/agents", tags=["agents"])

# Engagement state storage directory
IAC_HOME = Path(os.path.expanduser("~/.iac"))
ENGAGEMENTS_DIR = IAC_HOME / "engagements"

# In-memory approval events: engagement_id -> asyncio.Event
# (Phase B will replace this with proper async gates)
_approval_pending: Dict[str, bool] = {}

# Phase chain for a full engagement
PHASE_CHAIN = [
    PhaseEnum.KICKOFF,
    PhaseEnum.RECON,
    PhaseEnum.RISK,
]

AGENT_MAP = {
    PhaseEnum.KICKOFF: KickOffAgent,
    PhaseEnum.RECON: ReconAgent,
    PhaseEnum.RISK: RiskAssessmentAgent,
}


# --------------------------------------------------------------------------- #
# Persistence helpers
# --------------------------------------------------------------------------- #

def _state_path(engagement_id: str) -> Path:
    return ENGAGEMENTS_DIR / engagement_id / "state.json"


def _load_state(engagement_id: str) -> EngagementState:
    path = _state_path(engagement_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Engagement {engagement_id!r} not found")
    with open(path) as f:
        return EngagementState.model_validate_json(f.read())


def _save_state(state: EngagementState) -> None:
    path = _state_path(state.engagement_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    state.updated_at = datetime.utcnow()
    with open(path, "w") as f:
        f.write(state.model_dump_json(indent=2))


# --------------------------------------------------------------------------- #
# Request / response models
# --------------------------------------------------------------------------- #

class EngageRequest(BaseModel):
    scope: EngagementScope


class ApproveRequest(BaseModel):
    level: str = "phase"  # "phase" or "tool"


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #

@router.post("/engage")
async def create_engagement(request: EngageRequest) -> Dict[str, Any]:
    """Create a new engagement and return its ID."""
    ENGAGEMENTS_DIR.mkdir(parents=True, exist_ok=True)
    state = EngagementState(scope=request.scope)
    _save_state(state)
    return {
        "engagement_id": state.engagement_id,
        "status": state.status,
        "created_at": state.created_at.isoformat(),
    }


@router.get("/engage/{engagement_id}/status")
async def get_status(engagement_id: str) -> Dict[str, Any]:
    """Return current engagement state."""
    state = _load_state(engagement_id)
    return {
        "engagement_id": state.engagement_id,
        "status": state.status,
        "current_phase": state.current_phase,
        "phases_complete": list(state.phase_outputs.keys()),
        "pending_approval": state.pending_approval.model_dump() if state.pending_approval else None,
        "error": state.error,
        "updated_at": state.updated_at.isoformat(),
    }


@router.get("/engage/{engagement_id}/stream")
async def stream_phase(engagement_id: str, phase: Optional[str] = None) -> StreamingResponse:
    """
    Run the next phase (or specified phase) and stream events as Server-Sent Events.
    Each event line: data: <json>\\n\\n
    """
    state = _load_state(engagement_id)

    if state.status == EngagementStatus.RUNNING:
        raise HTTPException(status_code=409, detail="Engagement is already running")

    # Determine which phase to run next
    if phase:
        try:
            target_phase = PhaseEnum(phase)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Unknown phase: {phase!r}")
    else:
        # Pick first phase not yet complete
        target_phase = None
        for p in PHASE_CHAIN:
            if p.value not in state.phase_outputs:
                target_phase = p
                break

    if target_phase is None:
        async def already_done():
            yield f"data: {json.dumps({'type': 'error', 'message': 'All phases complete'})}\n\n"
        return StreamingResponse(already_done(), media_type="text/event-stream")

    if target_phase not in AGENT_MAP:
        async def unsupported():
            yield f"data: {json.dumps({'type': 'error', 'message': f'Phase {target_phase} not yet implemented'})}\n\n"
        return StreamingResponse(unsupported(), media_type="text/event-stream")

    async def event_stream():
        # Update state to RUNNING
        state.status = EngagementStatus.RUNNING
        state.current_phase = target_phase
        _save_state(state)

        yield f"data: {json.dumps({'type': 'phase_start', 'phase': target_phase.value})}\n\n"

        # Build context from prior phase outputs
        prior_parts = []
        for phase_key, result in state.phase_outputs.items():
            prior_parts.append(f"=== {phase_key.upper()} PHASE ===\n{result.summary}")
        prior_context = "\n\n".join(prior_parts)

        scope = state.scope
        scope_summary = (
            f"Target: {scope.target_url}\n"
            f"Objectives: {scope.objectives}\n"
            f"Rules of Engagement: {scope.roe}\n"
            f"Team Type: {scope.team_type}"
        )

        agent_cls = AGENT_MAP[target_phase]
        agent = agent_cls()

        agent_result = None
        try:
            async for event in agent.run(scope_summary, prior_context):
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("type") == "complete":
                    agent_result = event["result"]
                elif event.get("type") == "error":
                    state.status = EngagementStatus.FAILED
                    state.error = event.get("message")
                    _save_state(state)
                    return
        except Exception as exc:
            # Always emit a non-empty message so the UI shows something useful
            err_msg = str(exc) or f"{type(exc).__name__} (no detail)"
            state.status = EngagementStatus.FAILED
            state.error = err_msg
            _save_state(state)
            yield f"data: {json.dumps({'type': 'error', 'message': err_msg})}\n\n"
            return

        if agent_result:
            # Persist result — agent_result arrives as a dict (model_dump'd by base_agent)
            if isinstance(agent_result, dict):
                from agents.models import AgentResult
                agent_result = AgentResult.model_validate(agent_result)

            state.phase_outputs[target_phase.value] = agent_result
            state.status = EngagementStatus.AWAITING_APPROVAL
            state.pending_approval = None  # phase-level approval
            _save_state(state)

            yield f"data: {json.dumps({'type': 'awaiting_approval', 'phase': target_phase.value})}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/engage/{engagement_id}/approve")
async def approve(engagement_id: str, request: ApproveRequest) -> Dict[str, Any]:
    """Approve a phase or tool gate to continue the engagement."""
    state = _load_state(engagement_id)
    if state.status != EngagementStatus.AWAITING_APPROVAL:
        raise HTTPException(status_code=409, detail="No pending approval for this engagement")
    state.status = EngagementStatus.IDLE
    state.pending_approval = None
    _save_state(state)
    return {"engagement_id": engagement_id, "status": state.status}


@router.post("/engage/{engagement_id}/reject")
async def reject(engagement_id: str) -> Dict[str, Any]:
    """Reject and halt the engagement."""
    state = _load_state(engagement_id)
    state.status = EngagementStatus.REJECTED
    _save_state(state)
    return {"engagement_id": engagement_id, "status": state.status}


@router.get("/skills")
async def list_skills() -> Dict[str, Any]:
    """Return all registered skills and their schemas."""
    return {"skills": skill_registry.list_skills()}
