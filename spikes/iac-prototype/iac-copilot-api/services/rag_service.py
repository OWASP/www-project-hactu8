"""RAG service for the IAC Copilot API."""

import os
from typing import List, Dict, Any, Optional
import openai
from .vector_store import VectorStoreService
from .llm_dispatch import call_model


class RAGService:
    """Service for RAG-enhanced chat with document context."""

    SYSTEM_PROMPTS = {
        "assist": """You are an IAC (Intelligence Assurance Copilot) assistant helping users with research, planning, and summarization tasks.

You have access to the user's uploaded documents and can help with:
- Summarizing document content
- Answering questions about the documents
- Research and analysis tasks
- Planning and organizing information

When answering, cite relevant sources from the provided context. Be concise but thorough.""",

        "owasp": """You are an expert in OWASP (Open Web Application Security Project) AI security guidelines and best practices.

You have access to OWASP documentation including:
- OWASP Top 10 for LLM Applications
- OWASP AI Security and Privacy Guide
- OWASP Machine Learning Security Top 10
- Various AI security best practices and defense strategies

When answering questions about AI/ML security, reference specific OWASP guidelines and provide actionable recommendations. Always cite the relevant OWASP document.""",

        "project": """You are a HACTU8 (Heuristics for AI, Cybersecurity, and Trust Unified Threats) project documentation assistant.

You have access to HACTU8 project documentation including:
- Project architecture and design documents
- Implementation guides
- API references
- Contributing guidelines

Help users understand the HACTU8 project, its components, and how to work with it. Reference specific documentation sections when answering.""",
    }

    def __init__(self, vector_store: Optional[VectorStoreService] = None):
        self.vector_store = vector_store or VectorStoreService()
        self.openai_client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    def get_relevant_context(
        self,
        query: str,
        mode: str = "assist",
        document_ids: Optional[List[str]] = None,
        n_results: int = 5
    ) -> List[Dict[str, Any]]:
        filter_metadata = None
        collection_key = "assist"
        allowed_source_types = None

        if mode == "owasp":
            filter_metadata = {"source_type": "owasp"}
            collection_key = "owasp"
        elif mode == "project":
            filter_metadata = {"source_type": "project"}
            collection_key = "project"
        else:
            allowed_source_types = {"user_upload", "url"}

        results = self.vector_store.search(
            query=query,
            n_results=n_results * 2 if document_ids else n_results,
            filter_metadata=filter_metadata,
            collection_key=collection_key
        )

        if allowed_source_types:
            results = [
                r for r in results
                if r.get("metadata", {}).get("source_type") in allowed_source_types
            ]

        if document_ids:
            results = [r for r in results if r["metadata"].get("document_id") in document_ids]
            results = results[:n_results]

        return results[:n_results]

    def build_context_prompt(self, chunks: List[Dict[str, Any]]) -> str:
        if not chunks:
            return "No relevant documents found in the knowledge base."

        context_parts = ["Relevant context from documents:\n"]
        for i, chunk in enumerate(chunks, 1):
            title = chunk["metadata"].get("title", "Unknown Document")
            source_type = chunk["metadata"].get("source_type", "unknown")
            content = chunk["content"]

            context_parts.append(f"[Source {i}: {title} ({source_type})]")
            context_parts.append(content)
            context_parts.append("")

        return "\n".join(context_parts)

    def format_sources(self, chunks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        sources = []
        seen_docs = set()

        for chunk in chunks:
            doc_id = chunk["metadata"].get("document_id")
            if doc_id and doc_id not in seen_docs:
                seen_docs.add(doc_id)
                sources.append({
                    "id": doc_id,
                    "title": chunk["metadata"].get("title", "Unknown"),
                    "source_type": chunk["metadata"].get("source_type", "unknown"),
                    "relevance": 1.0 - chunk.get("distance", 0.0)
                })

        return sources

    async def chat(
        self,
        message: str,
        mode: str = "assist",
        document_ids: Optional[List[str]] = None,
        conversation_history: Optional[List[Dict[str, str]]] = None,
        provider_id: Optional[str] = None,
        model_id: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None
    ) -> Dict[str, Any]:
        chunks = self.get_relevant_context(
            query=message,
            mode=mode,
            document_ids=document_ids
        )

        context = self.build_context_prompt(chunks)
        system_prompt = f"{self.SYSTEM_PROMPTS.get(mode, self.SYSTEM_PROMPTS['assist'])}\n\n{context}"

        messages: List[Dict[str, Any]] = []
        if conversation_history:
            for msg in conversation_history[-10:]:
                messages.append({"role": msg["role"], "content": msg["content"]})
        messages.append({"role": "user", "content": message})

        try:
            result = await call_model(
                messages,
                provider_id=provider_id,
                model_id=model_id,
                api_key=api_key,
                base_url=base_url,
                system_prompt=system_prompt,
            )
            reply = "".join(result.text_blocks) or "(No response from model)"
        except Exception as e:
            reply = f"I apologize, but I encountered an error processing your request: {str(e)}"

        sources = self.format_sources(chunks)

        return {
            "reply": reply,
            "sources": sources
        }
