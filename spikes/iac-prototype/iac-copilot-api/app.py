"""FastAPI backend for the IAC Copilot API."""

import os
import hashlib
from typing import Dict, List, Optional
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request
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
from agents.router import router as agents_router


# In-memory document store (replace with database in production)
document_store: Dict[str, Document] = {}

# Service instances
vector_store: Optional[VectorStoreService] = None
rag_service: Optional[RAGService] = None
owasp_fetcher: Optional[OwaspFetcher] = None
url_fetcher: Optional[URLFetcher] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(agents_router, prefix="/api")


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


class ModelProviderEntry(BaseModel):
    id: str
    label: str
    models: List[str]
    requires_base_url: bool = False


class ModelRegistryResponse(BaseModel):
    providers: List[ModelProviderEntry]
    updated_at: datetime


def _parse_model_list(raw: Optional[str], defaults: List[str]) -> List[str]:
    if not raw:
        return defaults

    return [item.strip() for item in raw.split(",") if item.strip()]


def _default_model_registry() -> List[ModelProviderEntry]:
    return [
        ModelProviderEntry(
            id="openai",
            label="OpenAI",
            models=_parse_model_list(
                os.getenv("OPENAI_MODEL_LIST"),
                ["gpt-4o-mini", "gpt-4.1", "gpt-4o"]
            ),
            requires_base_url=False
        ),
        ModelProviderEntry(
            id="anthropic",
            label="Anthropic",
            models=_parse_model_list(
                os.getenv("ANTHROPIC_MODEL_LIST"),
                ["claude-3.5-sonnet", "claude-3.5-haiku", "claude-3-opus"]
            ),
            requires_base_url=False
        ),
        ModelProviderEntry(
            id="ollama",
            label="Local - Ollama",
            models=_parse_model_list(
                os.getenv("OLLAMA_MODEL_LIST"),
                ["llama3.1", "mistral", "qwen2.5"]
            ),
            requires_base_url=True
        ),
        ModelProviderEntry(
            id="foundry",
            label="Local - Foundry",
            models=_parse_model_list(
                os.getenv("FOUNDRY_MODEL_LIST"),
                ["phi-4", "phi-3.5-mini"]
            ),
            requires_base_url=True
        ),
        ModelProviderEntry(
            id="custom",
            label="Custom (OpenAI-compatible)",
            models=_parse_model_list(os.getenv("CUSTOM_MODEL_LIST"), []),
            requires_base_url=True
        ),
    ]


@app.get("/api/copilot/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(
        status="healthy",
        vector_store_count=vector_store.get_collection_stats()["count"] if vector_store else 0,
        document_count=len(document_store)
    )


@app.get("/api/copilot/models", response_model=ModelRegistryResponse)
async def get_model_registry():
    return ModelRegistryResponse(
        providers=_default_model_registry(),
        updated_at=datetime.utcnow()
    )


@app.post("/api/copilot/chat", response_model=ChatResponse)
async def chat(request: ChatRequest, http_request: Request):
    if not rag_service:
        raise HTTPException(status_code=503, detail="RAG service not initialized")

    provider_id = http_request.headers.get("x-model-provider")
    model_id = http_request.headers.get("x-model-id")
    api_key = http_request.headers.get("x-api-key")
    base_url = http_request.headers.get("x-model-base-url")

    result = await rag_service.chat(
        message=request.message,
        mode=request.mode,
        document_ids=request.context_document_ids,
        provider_id=provider_id,
        model_id=model_id,
        api_key=api_key,
        base_url=base_url
    )

    return ChatResponse(
        reply=result["reply"],
        sources=result["sources"]
    )


@app.get("/api/copilot/documents", response_model=DocumentListResponse)
async def list_documents(source_type: Optional[str] = None):
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
    if not vector_store:
        raise HTTPException(status_code=503, detail="Vector store not initialized")

    content = await file.read()
    mime_type = file.content_type or "text/plain"

    if mime_type in ["text/plain", "text/markdown", "application/json"]:
        text_content = content.decode("utf-8")
    elif mime_type == "application/pdf":
        try:
            text_content = content.decode("utf-8", errors="ignore")
        except Exception:
            raise HTTPException(status_code=400, detail="Could not process PDF file")
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {mime_type}"
        )

    content_hash = hashlib.sha256(content).hexdigest()
    doc_id = hashlib.md5(f"{file.filename}_{content_hash}".encode()).hexdigest()

    doc = Document(
        id=doc_id,
        title=title or file.filename or "Untitled Document",
        source_type=SourceType.USER_UPLOAD,
        content_hash=content_hash,
        file_name=file.filename,
        file_size=len(content),
        mime_type=mime_type
    )

    chunks = _chunk_content(text_content)
    vector_store.add_document_chunks(
        chunks=chunks,
        document_id=doc_id,
        metadata={
            "title": doc.title,
            "source_type": SourceType.USER_UPLOAD.value,
            "file_name": file.filename
        },
        collection_key="assist"
    )

    document_store[doc_id] = doc

    return DocumentUploadResponse(
        document=doc,
        chunks_created=len(chunks)
    )


@app.post("/api/copilot/documents/url", response_model=Document)
async def add_url_document(request: URLAddRequest):
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
    if document_id not in document_store:
        raise HTTPException(status_code=404, detail="Document not found")

    doc = document_store[document_id]
    collection_key = "assist"
    if doc.source_type == SourceType.OWASP:
        collection_key = "owasp"
    elif doc.source_type == SourceType.PROJECT:
        collection_key = "project"

    if vector_store:
        chunks_deleted = vector_store.delete_document(document_id, collection_key=collection_key)
    else:
        chunks_deleted = 0

    del document_store[document_id]

    return {"deleted": True, "chunks_removed": chunks_deleted}


@app.post("/api/copilot/sync/owasp", response_model=OwaspSyncResponse)
async def sync_owasp_documents():
    if not owasp_fetcher or not vector_store:
        raise HTTPException(status_code=503, detail="Services not initialized")

    stats = await owasp_fetcher.sync_owasp_documents(vector_store, document_store)

    return OwaspSyncResponse(
        documents_synced=stats["documents_synced"],
        documents_updated=stats["documents_updated"],
        documents_added=stats["documents_added"]
    )


@app.get("/api/copilot/sources")
async def get_configured_sources():
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
                "created_at": doc.created_at.isoformat(),
                "source_url": doc.source_url
            })

    return {
        "sources": sources,
        "total_documents": len(document_store),
        "total_chunks": vector_store.get_collection_stats()["count"] if vector_store else 0
    }


@app.get("/api/copilot/stats")
async def get_stats():
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
