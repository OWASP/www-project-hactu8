"""Vector store service using ChromaDB for document embeddings."""

import os
from typing import List, Optional, Dict, Any
import chromadb
from chromadb.config import Settings
import hashlib


class VectorStoreService:
    """Service for managing document embeddings in ChromaDB."""

    def __init__(self, persist_directory: Optional[str] = None):
        """Initialize the vector store.

        Args:
            persist_directory: Directory to persist ChromaDB data.
                             Defaults to ./data/chroma
        """
        self.persist_directory = persist_directory or os.getenv(
            "CHROMA_PERSIST_DIR",
            os.path.join(os.path.dirname(__file__), "..", "data", "chroma")
        )

        # Ensure directory exists
        os.makedirs(self.persist_directory, exist_ok=True)

        # Initialize ChromaDB client with persistence
        self.client = chromadb.PersistentClient(
            path=self.persist_directory,
            settings=Settings(anonymized_telemetry=False)
        )

        # Get or create the main collection
        self.collection = self.client.get_or_create_collection(
            name="iac_copilot_documents",
            metadata={"description": "IAC Copilot document embeddings"}
        )

    def add_document_chunks(
        self,
        chunks: List[str],
        document_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        """Add document chunks to the vector store.

        Args:
            chunks: List of text chunks to embed and store
            document_id: ID of the parent document
            metadata: Additional metadata for the chunks

        Returns:
            List of chunk IDs
        """
        if not chunks:
            return []

        chunk_ids = []
        documents = []
        metadatas = []

        for i, chunk in enumerate(chunks):
            chunk_id = f"{document_id}_chunk_{i}"
            chunk_ids.append(chunk_id)
            documents.append(chunk)

            chunk_metadata = {
                "document_id": document_id,
                "chunk_index": i,
                **(metadata or {})
            }
            metadatas.append(chunk_metadata)

        # Add to collection (ChromaDB handles embedding automatically)
        self.collection.add(
            ids=chunk_ids,
            documents=documents,
            metadatas=metadatas
        )

        return chunk_ids

    def search(
        self,
        query: str,
        n_results: int = 5,
        filter_metadata: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Search for relevant document chunks.

        Args:
            query: The search query
            n_results: Maximum number of results to return
            filter_metadata: Optional metadata filter (e.g., {"source_type": "owasp"})

        Returns:
            List of matching chunks with metadata and distances
        """
        where_filter = filter_metadata if filter_metadata else None

        results = self.collection.query(
            query_texts=[query],
            n_results=n_results,
            where=where_filter,
            include=["documents", "metadatas", "distances"]
        )

        # Format results
        formatted_results = []
        if results and results['ids'] and results['ids'][0]:
            for i, chunk_id in enumerate(results['ids'][0]):
                formatted_results.append({
                    "id": chunk_id,
                    "content": results['documents'][0][i] if results['documents'] else "",
                    "metadata": results['metadatas'][0][i] if results['metadatas'] else {},
                    "distance": results['distances'][0][i] if results['distances'] else 0.0
                })

        return formatted_results

    def delete_document(self, document_id: str) -> int:
        """Delete all chunks for a document.

        Args:
            document_id: ID of the document to delete

        Returns:
            Number of chunks deleted
        """
        # Find all chunks for this document
        results = self.collection.get(
            where={"document_id": document_id},
            include=["metadatas"]
        )

        if results and results['ids']:
            self.collection.delete(ids=results['ids'])
            return len(results['ids'])

        return 0

    def get_document_chunks(self, document_id: str) -> List[Dict[str, Any]]:
        """Get all chunks for a specific document.

        Args:
            document_id: ID of the document

        Returns:
            List of chunks with their content and metadata
        """
        results = self.collection.get(
            where={"document_id": document_id},
            include=["documents", "metadatas"]
        )

        chunks = []
        if results and results['ids']:
            for i, chunk_id in enumerate(results['ids']):
                chunks.append({
                    "id": chunk_id,
                    "content": results['documents'][i] if results['documents'] else "",
                    "metadata": results['metadatas'][i] if results['metadatas'] else {}
                })

        return chunks

    def get_collection_stats(self) -> Dict[str, Any]:
        """Get statistics about the collection.

        Returns:
            Dictionary with collection statistics
        """
        return {
            "name": self.collection.name,
            "count": self.collection.count(),
            "metadata": self.collection.metadata
        }

    @staticmethod
    def compute_content_hash(content: str) -> str:
        """Compute a hash of content for deduplication.

        Args:
            content: The content to hash

        Returns:
            SHA-256 hash of the content
        """
        return hashlib.sha256(content.encode()).hexdigest()
