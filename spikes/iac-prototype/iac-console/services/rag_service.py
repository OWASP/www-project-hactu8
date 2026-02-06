"""RAG (Retrieval-Augmented Generation) service for the IAC Copilot."""

import os
from typing import List, Dict, Any, Optional
import openai
from .vector_store import VectorStoreService


class RAGService:
    """Service for RAG-enhanced chat with document context."""

    # System prompts for different modes
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

Help users understand the HACTU8 project, its components, and how to work with it. Reference specific documentation sections when answering."""
    }

    def __init__(self, vector_store: Optional[VectorStoreService] = None):
        """Initialize the RAG service.

        Args:
            vector_store: VectorStoreService instance. Creates new one if not provided.
        """
        self.vector_store = vector_store or VectorStoreService()
        self.openai_client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    def get_relevant_context(
        self,
        query: str,
        mode: str = "assist",
        document_ids: Optional[List[str]] = None,
        n_results: int = 5
    ) -> List[Dict[str, Any]]:
        """Retrieve relevant document chunks for a query.

        Args:
            query: The user's query
            mode: The copilot mode ('assist', 'owasp', 'project')
            document_ids: Optional list of specific document IDs to search within
            n_results: Maximum number of chunks to retrieve

        Returns:
            List of relevant document chunks with metadata
        """
        # Build filter based on mode
        filter_metadata = None

        if mode == "owasp":
            filter_metadata = {"source_type": "owasp"}
        elif mode == "project":
            filter_metadata = {"source_type": "project"}
        elif document_ids:
            # For assist mode with specific documents, we'll filter after search
            pass

        # Search vector store
        results = self.vector_store.search(
            query=query,
            n_results=n_results * 2 if document_ids else n_results,  # Get more if filtering
            filter_metadata=filter_metadata
        )

        # Filter by document_ids if specified
        if document_ids:
            results = [r for r in results if r['metadata'].get('document_id') in document_ids]
            results = results[:n_results]

        return results

    def build_context_prompt(self, chunks: List[Dict[str, Any]]) -> str:
        """Build a context prompt from retrieved chunks.

        Args:
            chunks: List of document chunks with content and metadata

        Returns:
            Formatted context string for the LLM
        """
        if not chunks:
            return "No relevant documents found in the knowledge base."

        context_parts = ["Relevant context from documents:\n"]

        for i, chunk in enumerate(chunks, 1):
            title = chunk['metadata'].get('title', 'Unknown Document')
            source_type = chunk['metadata'].get('source_type', 'unknown')
            content = chunk['content']

            context_parts.append(f"[Source {i}: {title} ({source_type})]")
            context_parts.append(content)
            context_parts.append("")

        return "\n".join(context_parts)

    def format_sources(self, chunks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format chunks as source citations for the response.

        Args:
            chunks: List of document chunks

        Returns:
            List of formatted source references
        """
        sources = []
        seen_docs = set()

        for chunk in chunks:
            doc_id = chunk['metadata'].get('document_id')
            if doc_id and doc_id not in seen_docs:
                seen_docs.add(doc_id)
                sources.append({
                    "id": doc_id,
                    "title": chunk['metadata'].get('title', 'Unknown'),
                    "source_type": chunk['metadata'].get('source_type', 'unknown'),
                    "relevance": 1.0 - chunk.get('distance', 0.0)  # Convert distance to relevance
                })

        return sources

    async def chat(
        self,
        message: str,
        mode: str = "assist",
        document_ids: Optional[List[str]] = None,
        conversation_history: Optional[List[Dict[str, str]]] = None
    ) -> Dict[str, Any]:
        """Process a chat message with RAG-enhanced context.

        Args:
            message: The user's message
            mode: The copilot mode ('assist', 'owasp', 'project')
            document_ids: Optional list of document IDs to use as context
            conversation_history: Optional previous messages in the conversation

        Returns:
            Dictionary with 'reply' and 'sources'
        """
        # Get relevant context
        chunks = self.get_relevant_context(
            query=message,
            mode=mode,
            document_ids=document_ids
        )

        # Build the context prompt
        context = self.build_context_prompt(chunks)

        # Get the system prompt for this mode
        system_prompt = self.SYSTEM_PROMPTS.get(mode, self.SYSTEM_PROMPTS["assist"])

        # Build messages
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "system", "content": context}
        ]

        # Add conversation history if provided
        if conversation_history:
            for msg in conversation_history[-10:]:  # Limit to last 10 messages
                messages.append({"role": msg["role"], "content": msg["content"]})

        # Add the current message
        messages.append({"role": "user", "content": message})

        # Call OpenAI
        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4o-mini",  # Use a capable but cost-effective model
                messages=messages,
                temperature=0.7,
                max_tokens=1024
            )

            reply = response.choices[0].message.content

        except Exception as e:
            reply = f"I apologize, but I encountered an error processing your request: {str(e)}"

        # Format sources
        sources = self.format_sources(chunks)

        return {
            "reply": reply,
            "sources": sources
        }

    def chat_sync(
        self,
        message: str,
        mode: str = "assist",
        document_ids: Optional[List[str]] = None,
        conversation_history: Optional[List[Dict[str, str]]] = None
    ) -> Dict[str, Any]:
        """Synchronous version of chat for non-async contexts."""
        import asyncio
        return asyncio.get_event_loop().run_until_complete(
            self.chat(message, mode, document_ids, conversation_history)
        )
