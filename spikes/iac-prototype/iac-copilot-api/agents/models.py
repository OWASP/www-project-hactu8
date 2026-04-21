"""Data models for IAC engagement agents."""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class PhaseEnum(str, Enum):
    KICKOFF = "kickoff"
    RECON = "recon"
    RISK = "risk"
    ATTACK_SELECTION = "attack_selection"
    SIMULATED_ATTACKS = "simulated_attacks"
    REPORTING = "reporting"
    DEBRIEF = "debrief"


class EngagementStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETE = "complete"
    FAILED = "failed"
    REJECTED = "rejected"


class EngagementScope(BaseModel):
    target_url: str
    objectives: str
    roe: str  # Rules of Engagement
    team_type: str = "red"  # red, blue, purple
    authorized_tools: List[str] = Field(default_factory=list)
    enable_persistence: bool = False


class AgentResult(BaseModel):
    phase: PhaseEnum
    agent_name: str
    summary: str
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    tool_calls: List[Dict[str, Any]] = Field(default_factory=list)
    completed_at: datetime = Field(default_factory=datetime.utcnow)


class ApprovalContext(BaseModel):
    level: str  # "phase" or "tool"
    phase: Optional[str] = None
    tool_name: Optional[str] = None
    tool_input: Optional[Dict[str, Any]] = None
    risk: str = "low"  # low, medium, high
    description: str = ""


class EngagementState(BaseModel):
    engagement_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scope: EngagementScope
    current_phase: Optional[PhaseEnum] = None
    status: EngagementStatus = EngagementStatus.IDLE
    phase_outputs: Dict[str, AgentResult] = Field(default_factory=dict)
    pending_approval: Optional[ApprovalContext] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    error: Optional[str] = None
