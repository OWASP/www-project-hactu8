"""Service for fetching OWASP documents from GitHub repositories."""

import os
import re
import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime
import httpx
from ..models.document import Document, SourceType


class OwaspFetcher:
    """Fetches and indexes OWASP documentation from GitHub."""

    # OWASP GitHub repositories to fetch
    OWASP_REPOS = [
        {
            "owner": "OWASP",
            "repo": "www-project-top-10-for-large-language-model-applications",
            "title": "OWASP Top 10 for LLM Applications",
            "category": "Standards",
            "description": "The most critical security risks for Large Language Model applications.",
            "paths": ["2_0_vulns/", "Archive/", "1_1_vulns/"],
            "file_pattern": r".*\.md$"
        },
        {
            "owner": "OWASP",
            "repo": "www-project-ai-security-and-privacy-guide",
            "title": "OWASP AI Security and Privacy Guide",
            "category": "Guides",
            "description": "Comprehensive guide on AI security and privacy best practices.",
            "paths": ["content/"],
            "file_pattern": r".*\.md$"
        },
        {
            "owner": "OWASP",
            "repo": "www-project-machine-learning-security-top-10",
            "title": "OWASP ML Security Top 10",
            "category": "Standards",
            "description": "Top security risks specific to machine learning systems.",
            "paths": [""],
            "file_pattern": r".*\.md$"
        }
    ]

    def __init__(self, github_token: Optional[str] = None):
        """Initialize the OWASP fetcher.

        Args:
            github_token: Optional GitHub token for higher rate limits
        """
        self.github_token = github_token or os.getenv("OWASP_GITHUB_TOKEN")
        self.base_url = "https://api.github.com"
        self.raw_base_url = "https://raw.githubusercontent.com"

    def _get_headers(self) -> Dict[str, str]:
        """Get headers for GitHub API requests."""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "IAC-Copilot"
        }
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        return headers

    async def fetch_repo_contents(
        self,
        owner: str,
        repo: str,
        path: str = ""
    ) -> List[Dict[str, Any]]:
        """Fetch contents of a GitHub repository path.

        Args:
            owner: Repository owner
            repo: Repository name
            path: Path within the repository

        Returns:
            List of file/directory entries
        """
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{path}"

        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=self._get_headers())

            if response.status_code == 200:
                return response.json()
            else:
                print(f"Failed to fetch {url}: {response.status_code}")
                return []

    async def fetch_file_content(
        self,
        owner: str,
        repo: str,
        path: str
    ) -> Optional[str]:
        """Fetch raw content of a file from GitHub.

        Args:
            owner: Repository owner
            repo: Repository name
            path: File path within the repository

        Returns:
            File content as string, or None if fetch failed
        """
        url = f"{self.raw_base_url}/{owner}/{repo}/main/{path}"

        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=self._get_headers())

            if response.status_code == 200:
                return response.text

            # Try master branch if main doesn't exist
            url = f"{self.raw_base_url}/{owner}/{repo}/master/{path}"
            response = await client.get(url, headers=self._get_headers())

            if response.status_code == 200:
                return response.text

            print(f"Failed to fetch file {path}: {response.status_code}")
            return None

    def chunk_content(
        self,
        content: str,
        chunk_size: int = 1000,
        overlap: int = 200
    ) -> List[str]:
        """Split content into overlapping chunks for RAG.

        Args:
            content: The content to chunk
            chunk_size: Target size for each chunk in characters
            overlap: Number of characters to overlap between chunks

        Returns:
            List of content chunks
        """
        if len(content) <= chunk_size:
            return [content]

        chunks = []
        start = 0

        while start < len(content):
            end = start + chunk_size

            # Try to end at a sentence boundary
            if end < len(content):
                # Look for sentence ending within the last 20% of the chunk
                search_start = end - int(chunk_size * 0.2)
                sentence_end = content.rfind('. ', search_start, end)
                if sentence_end > search_start:
                    end = sentence_end + 1
                else:
                    # Fall back to word boundary
                    word_end = content.rfind(' ', search_start, end)
                    if word_end > search_start:
                        end = word_end

            chunks.append(content[start:end].strip())
            start = end - overlap

        return chunks

    def extract_title_from_markdown(self, content: str, fallback: str) -> str:
        """Extract title from markdown content.

        Args:
            content: Markdown content
            fallback: Fallback title if none found

        Returns:
            Extracted or fallback title
        """
        # Try to find first H1 header
        match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
        if match:
            return match.group(1).strip()

        # Try to find title in YAML frontmatter
        match = re.search(r'^---\s*\n.*?title:\s*["\']?([^"\'\n]+)["\']?\s*\n.*?---',
                         content, re.MULTILINE | re.DOTALL)
        if match:
            return match.group(1).strip()

        return fallback

    async def sync_owasp_documents(
        self,
        vector_store,
        document_store: Dict[str, Document]
    ) -> Dict[str, int]:
        """Sync OWASP documents from GitHub to the vector store.

        Args:
            vector_store: VectorStoreService instance
            document_store: Dictionary to store document metadata

        Returns:
            Dictionary with sync statistics
        """
        stats = {
            "documents_synced": 0,
            "documents_added": 0,
            "documents_updated": 0,
            "chunks_created": 0
        }

        for repo_config in self.OWASP_REPOS:
            owner = repo_config["owner"]
            repo = repo_config["repo"]

            print(f"Syncing {repo_config['title']}...")

            for search_path in repo_config.get("paths", [""]):
                try:
                    contents = await self.fetch_repo_contents(owner, repo, search_path)

                    for item in contents:
                        if item["type"] != "file":
                            continue

                        if not re.match(repo_config.get("file_pattern", r".*\.md$"), item["name"]):
                            continue

                        # Fetch file content
                        file_path = item["path"]
                        content = await self.fetch_file_content(owner, repo, file_path)

                        if not content:
                            continue

                        # Create document ID from repo and path
                        doc_id = hashlib.md5(f"{owner}/{repo}/{file_path}".encode()).hexdigest()
                        content_hash = hashlib.sha256(content.encode()).hexdigest()

                        # Check if document needs updating
                        existing_doc = document_store.get(doc_id)
                        if existing_doc and existing_doc.content_hash == content_hash:
                            stats["documents_synced"] += 1
                            continue

                        # Extract title
                        title = self.extract_title_from_markdown(
                            content,
                            item["name"].replace(".md", "").replace("-", " ").title()
                        )

                        # Create document
                        doc = Document(
                            id=doc_id,
                            title=title,
                            source_type=SourceType.OWASP,
                            source_url=f"https://github.com/{owner}/{repo}/blob/main/{file_path}",
                            content_hash=content_hash,
                            file_name=item["name"],
                            category=repo_config.get("category", "Guides"),
                            description=repo_config.get("description", "")
                        )

                        # Delete old chunks if updating
                        if existing_doc:
                            vector_store.delete_document(doc_id)
                            stats["documents_updated"] += 1
                        else:
                            stats["documents_added"] += 1

                        # Chunk and index content
                        chunks = self.chunk_content(content)
                        vector_store.add_document_chunks(
                            chunks=chunks,
                            document_id=doc_id,
                            metadata={
                                "title": title,
                                "source_type": SourceType.OWASP.value,
                                "category": repo_config.get("category"),
                                "repo": f"{owner}/{repo}"
                            }
                        )
                        stats["chunks_created"] += len(chunks)

                        # Store document metadata
                        document_store[doc_id] = doc
                        stats["documents_synced"] += 1

                except Exception as e:
                    print(f"Error syncing {repo}: {str(e)}")
                    continue

        return stats

    def sync_owasp_documents_sync(
        self,
        vector_store,
        document_store: Dict[str, Document]
    ) -> Dict[str, int]:
        """Synchronous wrapper for sync_owasp_documents."""
        import asyncio
        return asyncio.get_event_loop().run_until_complete(
            self.sync_owasp_documents(vector_store, document_store)
        )
