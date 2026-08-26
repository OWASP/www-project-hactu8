"""Data models for Project runs — a user's conversation + tool-call history
against a curated Project. Deliberately NOT typed against agents/models.py's
PhaseEnum-based fields: a Project run isn't a fixed phase, it's a
user-configured (target, skills, model) conversation.
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class TargetSnapshot(BaseModel):
    """Client-resolved snapshot of a Registry target entry — the backend has
    no Registry persistence of its own (Registry is browser localStorage
    only), so the frontend resolves and sends this rather than an id to
    look up."""
    registry_entry_id: Optional[str] = None
    name: str
    target_url: Optional[str] = None
    description: Optional[str] = None
    risk_notes: Optional[str] = None


class ModelConfigSnapshot(BaseModel):
    """Client-resolved snapshot of a ModelProviderConfig — same rationale as
    TargetSnapshot; ModelProviderContext is also localStorage-only."""
    provider_id: str
    model_id: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None


class ProjectRunScope(BaseModel):
    project_id: str
    project_name: str
    target: TargetSnapshot
    skill_names: List[str]
    model: ModelConfigSnapshot


class ProjectRunTurn(BaseModel):
    role: str  # "user" | "assistant"
    content: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ProjectRunStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    AWAITING_INPUT = "awaiting_input"
    FAILED = "failed"


class ProjectRunState(BaseModel):
    run_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scope: ProjectRunScope
    status: ProjectRunStatus = ProjectRunStatus.IDLE
    turns: List[ProjectRunTurn] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    error: Optional[str] = None


class CreateRunRequest(BaseModel):
    target: TargetSnapshot
    skill_names: List[str]
    model: ModelConfigSnapshot


class CreateRunResponse(BaseModel):
    run_id: str
    status: ProjectRunStatus


class SendMessageRequest(BaseModel):
    content: str
