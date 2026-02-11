"""Vector store service using ChromaDB for document embeddings."""

import os
from typing import List, Optional, Dict, Any
import chromadb
from chromadb.config import Settings
import hashlib


COLLECTIONS = {
    "assist": "iac_copilot_documents",
    "owasp": "iac_copilot_owasp",
    "project": "iac_copilot_project",
}


class VectorStoreService:
    """Service for managing document embeddings in ChromaDB."""

    def __init__(self, persist_directory: Optional[str] = None):
        self.persist_directory = persist_directory or os.getenv(
            "CHROMA_PERSIST_DIR",
            os.path.join(os.path.dirname(__file__), "..", "data", "chroma")
        )

        os.makedirs(self.persist_directory, exist_ok=True)

        self.client = chromadb.PersistentClient(
            path=self.persist_directory,
            settings=Settings(anonymized_telemetry=False)
        )

        self.collections = {
            key: self.client.get_or_create_collection(
                name=collection_name,
                metadata={"description": f"IAC Copilot {key} embeddings"}
            )
            for key, collection_name in COLLECTIONS.items()
        }

    def _get_collection(self, collection_key: str):
        return self.collections.get(collection_key, self.collections["assist"])

    def add_document_chunks(
        self,
        chunks: List[str],
        document_id: str,
        metadata: Optional[Dict[str, Any]] = None,
        collection_key: str = "assist"
    ) -> List[str]:
        if not chunks:
            return []

        collection = self._get_collection(collection_key)

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

        collection.add(
            ids=chunk_ids,
            documents=documents,
            metadatas=metadatas
        )

        return chunk_ids

    def search(
        self,
        query: str,
        n_results: int = 5,
        filter_metadata: Optional[Dict[str, Any]] = None,
        collection_key: str = "assist"
    ) -> List[Dict[str, Any]]:
        collection = self._get_collection(collection_key)
        results = collection.query(
            query_texts=[query],
            n_results=n_results,
            where=filter_metadata,
            include=["documents", "metadatas", "distances"]
        )

        formatted_results = []
        if results and results["ids"] and results["ids"][0]:
            for i, chunk_id in enumerate(results["ids"][0]):
                formatted_results.append({
                    "id": chunk_id,
                    "content": results["documents"][0][i] if results["documents"] else "",
                    "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                    "distance": results["distances"][0][i] if results["distances"] else 0.0
                })

        return formatted_results

    def delete_document(self, document_id: str, collection_key: str = "assist") -> int:
        collection = self._get_collection(collection_key)
        results = collection.get(
            where={"document_id": document_id},
            include=["metadatas"]
        )

        if results and results["ids"]:
            collection.delete(ids=results["ids"])
            return len(results["ids"])

        return 0

    def get_collection_stats(self, collection_key: Optional[str] = None) -> Dict[str, Any]:
        if collection_key:
            collection = self._get_collection(collection_key)
            return {
                "name": collection.name,
                "count": collection.count(),
                "metadata": collection.metadata
            }

        total_count = sum(collection.count() for collection in self.collections.values())
        return {
            "name": "iac_copilot_all",
            "count": total_count,
            "metadata": {"collections": list(self.collections.keys())}
        }

    @staticmethod
    def compute_content_hash(content: str) -> str:
        return hashlib.sha256(content.encode()).hexdigest()
