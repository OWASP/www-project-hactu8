"""FastAPI backend for the IAC Copilot."""

import os
import hashlib
from typing import Dict, List, Optional
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from models.document import (
    Document, SourceType, ChatRequest, ChatResponse,
    DocumentUploadResponse, OwaspSyncResponse
)
from services.vector_store import VectorStoreService
from services.rag_service import RAGService
from services.owasp_fetcher import OwaspFetcher
from services.url_fetcher import URLFetcher


# In-memory document store (replace with database in production)
document_store: Dict[str, Document] = {}

# Service instances
vector_store: Optional[VectorStoreService] = None
rag_service: Optional[RAGService] = None
owasp_fetcher: Optional[OwaspFetcher] = None
url_fetcher: Optional[URLFetcher] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize services on startup."""
    global vector_store, rag_service, owasp_fetcher, url_fetcher

    print("Initializing IAC Copilot services...")

    vector_store = VectorStoreService()
    rag_service = RAGService(vector_store)
    owasp_fetcher = OwaspFetcher()
    url_fetcher = URLFetcher()

    print(f"Vector store initialized with {vector_store.get_collection_stats()['count']} chunks")

    yield

    print("Shutting down IAC Copilot services...")


app = FastAPI(
    title="IAC Copilot API",
    description="Backend API for the Intelligence Assurance Copilot",
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",  # Vite dev server
        "http://localhost:3000",  # Alternative dev server
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request/Response models
class URLAddRequest(BaseModel):
    url: str
    title: Optional[str] = None


class DocumentListResponse(BaseModel):
    documents: List[Document]
    total: int


class HealthResponse(BaseModel):
    status: str
    vector_store_count: int
    document_count: int


# Health check endpoint
@app.get("/api/copilot/health", response_model=HealthResponse)
async def health_check():
    """Check the health of the Copilot API."""
    return HealthResponse(
        status="healthy",
        vector_store_count=vector_store.get_collection_stats()['count'] if vector_store else 0,
        document_count=len(document_store)
    )


# Chat endpoint
@app.post("/api/copilot/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """Process a chat message with RAG-enhanced context."""
    if not rag_service:
        raise HTTPException(status_code=503, detail="RAG service not initialized")

    result = await rag_service.chat(
        message=request.message,
        mode=request.mode,
        document_ids=request.context_document_ids
    )

    return ChatResponse(
        reply=result["reply"],
        sources=result["sources"]
    )


# Document management endpoints
@app.get("/api/copilot/documents", response_model=DocumentListResponse)
async def list_documents(source_type: Optional[str] = None):
    """List all indexed documents, optionally filtered by source type."""
    docs = list(document_store.values())

    if source_type:
        docs = [d for d in docs if d.source_type == source_type]

    return DocumentListResponse(
        documents=docs,
        total=len(docs)
    )


@app.post("/api/copilot/documents", response_model=DocumentUploadResponse)
async def upload_document(
    file: UploadFile = File(...),
    title: Optional[str] = Form(None)
):
    """Upload and index a document."""
    if not vector_store:
        raise HTTPException(status_code=503, detail="Vector store not initialized")

    # Read file content
    content = await file.read()

    # Determine how to process based on content type
    mime_type = file.content_type or "text/plain"

    if mime_type in ["text/plain", "text/markdown", "application/json"]:
        text_content = content.decode("utf-8")
    elif mime_type == "application/pdf":
        # For MVP, just extract text (could use PyPDF2 for better extraction)
        try:
            text_content = content.decode("utf-8", errors="ignore")
        except Exception:
            raise HTTPException(status_code=400, detail="Could not process PDF file")
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {mime_type}"
        )

    # Create document ID from content hash
    content_hash = hashlib.sha256(content).hexdigest()
    doc_id = hashlib.md5(f"{file.filename}_{content_hash}".encode()).hexdigest()

    # Create document
    doc = Document(
        id=doc_id,
        title=title or file.filename or "Untitled Document",
        source_type=SourceType.USER_UPLOAD,
        content_hash=content_hash,
        file_name=file.filename,
        file_size=len(content),
        mime_type=mime_type
    )

    # Chunk and index content
    chunks = _chunk_content(text_content)
    vector_store.add_document_chunks(
        chunks=chunks,
        document_id=doc_id,
        metadata={
            "title": doc.title,
            "source_type": SourceType.USER_UPLOAD.value,
            "file_name": file.filename
        }
    )

    # Store document metadata
    document_store[doc_id] = doc

    return DocumentUploadResponse(
        document=doc,
        chunks_created=len(chunks)
    )


@app.post("/api/copilot/documents/url", response_model=Document)
async def add_url_document(request: URLAddRequest):
    """Add and index a document from a URL."""
    if not url_fetcher or not vector_store:
        raise HTTPException(status_code=503, detail="Services not initialized")

    doc = await url_fetcher.index_url(
        url=request.url,
        vector_store=vector_store,
        document_store=document_store,
        custom_title=request.title
    )

    if not doc:
        raise HTTPException(status_code=400, detail="Could not fetch or process URL")

    return doc


@app.delete("/api/copilot/documents/{document_id}")
async def delete_document(document_id: str):
    """Delete a document and its indexed chunks."""
    if document_id not in document_store:
        raise HTTPException(status_code=404, detail="Document not found")

    if vector_store:
        chunks_deleted = vector_store.delete_document(document_id)
    else:
        chunks_deleted = 0

    del document_store[document_id]

    return {"deleted": True, "chunks_removed": chunks_deleted}


# OWASP sync endpoint
@app.post("/api/copilot/sync/owasp", response_model=OwaspSyncResponse)
async def sync_owasp_documents():
    """Fetch and index OWASP documents from GitHub."""
    if not owasp_fetcher or not vector_store:
        raise HTTPException(status_code=503, detail="Services not initialized")

    stats = await owasp_fetcher.sync_owasp_documents(vector_store, document_store)

    return OwaspSyncResponse(
        documents_synced=stats["documents_synced"],
        documents_updated=stats["documents_updated"],
        documents_added=stats["documents_added"]
    )


# Sources endpoint
@app.get("/api/copilot/sources")
async def get_configured_sources():
    """Get statistics about configured document sources."""
    sources = {
        "user_upload": {"count": 0, "documents": []},
        "owasp": {"count": 0, "documents": []},
        "url": {"count": 0, "documents": []},
        "project": {"count": 0, "documents": []}
    }

    for doc in document_store.values():
        source_type = doc.source_type
        if source_type in sources:
            sources[source_type]["count"] += 1
            sources[source_type]["documents"].append({
                "id": doc.id,
                "title": doc.title,
                "created_at": doc.created_at.isoformat()
            })

    return {
        "sources": sources,
        "total_documents": len(document_store),
        "total_chunks": vector_store.get_collection_stats()['count'] if vector_store else 0
    }


# Vector store stats endpoint
@app.get("/api/copilot/stats")
async def get_stats():
    """Get statistics about the vector store and documents."""
    vs_stats = vector_store.get_collection_stats() if vector_store else {}

    return {
        "vector_store": vs_stats,
        "documents": {
            "total": len(document_store),
            "by_type": {
                source_type.value: len([d for d in document_store.values() if d.source_type == source_type])
                for source_type in SourceType
            }
        }
    }


def _chunk_content(content: str, chunk_size: int = 1000, overlap: int = 200) -> List[str]:
    """Split content into overlapping chunks."""
    if len(content) <= chunk_size:
        return [content]

    chunks = []
    start = 0

    while start < len(content):
        end = start + chunk_size

        if end < len(content):
            search_start = end - int(chunk_size * 0.2)
            sentence_end = content.rfind('. ', search_start, end)
            if sentence_end > search_start:
                end = sentence_end + 1
            else:
                word_end = content.rfind(' ', search_start, end)
                if word_end > search_start:
                    end = word_end

        chunks.append(content[start:end].strip())
        start = end - overlap

    return chunks


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
