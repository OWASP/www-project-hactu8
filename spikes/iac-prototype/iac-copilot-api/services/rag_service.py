"""RAG service for the IAC Copilot API."""

import os
from typing import List, Dict, Any, Optional
import httpx
import openai
from .vector_store import VectorStoreService


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

    def _resolve_model(self, provider_id: Optional[str], model_id: Optional[str]) -> str:
        if model_id:
            return model_id

        if provider_id in ("ollama", "foundry", "custom"):
            return os.getenv("OPENAI_MODEL", "gpt-4o-mini")

        if provider_id == "anthropic":
            return os.getenv("ANTHROPIC_MODEL", "claude-3.5-sonnet")

        return os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    def _get_openai_client(self, api_key: Optional[str], base_url: Optional[str]) -> openai.OpenAI:
        resolved_key = api_key or os.getenv("OPENAI_API_KEY") or ""
        if base_url:
            return openai.OpenAI(api_key=resolved_key or "local", base_url=base_url)

        return openai.OpenAI(api_key=resolved_key)

    def _get_ollama_client(self, base_url: Optional[str]) -> openai.OpenAI:
        resolved_base = (base_url or os.getenv("OLLAMA_BASE_URL") or "").strip()
        if not resolved_base:
            return openai.OpenAI(api_key="local")

        if not resolved_base.endswith("/v1"):
            resolved_base = f"{resolved_base.rstrip('/')}/v1"

        return openai.OpenAI(api_key="local", base_url=resolved_base)

    async def _call_anthropic(self, messages: List[Dict[str, str]], model: str, api_key: Optional[str]) -> str:
        resolved_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not resolved_key:
            raise ValueError("Anthropic API key is not configured")

        system_parts = [m["content"] for m in messages if m["role"] == "system"]
        system_prompt = "\n\n".join(system_parts).strip()
        user_messages = [m for m in messages if m["role"] in ("user", "assistant")]

        payload = {
            "model": model,
            "max_tokens": 1024,
            "temperature": 0.7,
            "messages": user_messages,
        }
        if system_prompt:
            payload["system"] = system_prompt

        headers = {
            "x-api-key": resolved_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post("https://api.anthropic.com/v1/messages", json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()

        content_blocks = data.get("content", [])
        if not content_blocks:
            return "(No response from model)"

        return "".join(block.get("text", "") for block in content_blocks if block.get("type") == "text")

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
        system_prompt = self.SYSTEM_PROMPTS.get(mode, self.SYSTEM_PROMPTS["assist"])

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "system", "content": context}
        ]

        if conversation_history:
            for msg in conversation_history[-10:]:
                messages.append({"role": msg["role"], "content": msg["content"]})

        messages.append({"role": "user", "content": message})

        resolved_provider = (provider_id or "openai").lower()
        resolved_model = self._resolve_model(resolved_provider, model_id)

        try:
            if resolved_provider in ("openai", "ollama", "foundry", "custom"):
                if resolved_provider in ("foundry", "custom") and not base_url:
                    raise ValueError("Base URL is required for the selected provider")

                if resolved_provider == "ollama":
                    client = self._get_ollama_client(base_url)
                else:
                    client = self._get_openai_client(api_key, base_url)
                response = client.chat.completions.create(
                    model=resolved_model,
                    messages=messages,
                    temperature=0.7,
                    max_tokens=1024
                )
                reply = response.choices[0].message.content or "(No response from model)"
            elif resolved_provider == "anthropic":
                reply = await self._call_anthropic(messages, resolved_model, api_key)
            else:
                raise ValueError(f"Unsupported model provider: {resolved_provider}")
        except Exception as e:
            reply = f"I apologize, but I encountered an error processing your request: {str(e)}"

        sources = self.format_sources(chunks)

        return {
            "reply": reply,
            "sources": sources
        }
