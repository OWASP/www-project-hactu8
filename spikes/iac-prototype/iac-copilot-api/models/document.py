"""Document models for the IAC Copilot API."""

from datetime import datetime
from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field
import uuid


class SourceType(str, Enum):
    """Types of document sources."""
    USER_UPLOAD = "user_upload"
    OWASP = "owasp"
    URL = "url"
    PROJECT = "project"


class Document(BaseModel):
    """Document metadata model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    source_type: SourceType
    source_url: Optional[str] = None
    content_hash: Optional[str] = None
    file_name: Optional[str] = None
    file_size: Optional[int] = None
    mime_type: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        use_enum_values = True


class ChatRequest(BaseModel):
    """Request model for chat endpoint."""
    message: str
    mode: str = "assist"
    context_document_ids: Optional[List[str]] = None


class ChatResponse(BaseModel):
    """Response model for chat endpoint."""
    reply: str
    sources: List[dict] = Field(default_factory=list)


class DocumentUploadResponse(BaseModel):
    """Response model for document upload."""
    document: Document
    chunks_created: int


class OwaspSyncResponse(BaseModel):
    """Response model for OWASP sync operation."""
    documents_synced: int
    documents_updated: int
    documents_added: int
