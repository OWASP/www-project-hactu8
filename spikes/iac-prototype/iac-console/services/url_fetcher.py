"""Service for fetching and indexing content from URLs."""

import os
import re
import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime
from urllib.parse import urlparse
import httpx
from bs4 import BeautifulSoup

from ..models.document import Document, SourceType


class URLFetcher:
    """Fetches and indexes content from user-provided URLs."""

    # Supported content types
    SUPPORTED_CONTENT_TYPES = [
        "text/html",
        "text/plain",
        "text/markdown",
        "application/pdf",
        "application/json"
    ]

    def __init__(self):
        """Initialize the URL fetcher."""
        self.timeout = 30.0  # Request timeout in seconds

    async def fetch_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Fetch content from a URL.

        Args:
            url: The URL to fetch

        Returns:
            Dictionary with content and metadata, or None if fetch failed
        """
        try:
            async with httpx.AsyncClient(follow_redirects=True) as client:
                response = await client.get(
                    url,
                    timeout=self.timeout,
                    headers={"User-Agent": "IAC-Copilot/1.0"}
                )

                if response.status_code != 200:
                    print(f"Failed to fetch {url}: {response.status_code}")
                    return None

                content_type = response.headers.get("content-type", "").split(";")[0].strip()

                # Check if content type is supported
                if not any(ct in content_type for ct in ["text/", "application/json"]):
                    print(f"Unsupported content type for {url}: {content_type}")
                    return None

                return {
                    "url": str(response.url),  # Final URL after redirects
                    "content": response.text,
                    "content_type": content_type,
                    "status_code": response.status_code
                }

        except Exception as e:
            print(f"Error fetching {url}: {str(e)}")
            return None

    def extract_text_from_html(self, html: str) -> str:
        """Extract readable text from HTML content.

        Args:
            html: HTML content

        Returns:
            Extracted text content
        """
        soup = BeautifulSoup(html, "html.parser")

        # Remove script and style elements
        for element in soup(["script", "style", "nav", "footer", "header", "aside"]):
            element.decompose()

        # Try to find main content area
        main_content = (
            soup.find("main") or
            soup.find("article") or
            soup.find(class_=re.compile(r"content|article|post|entry")) or
            soup.find("body")
        )

        if main_content:
            text = main_content.get_text(separator="\n", strip=True)
        else:
            text = soup.get_text(separator="\n", strip=True)

        # Clean up whitespace
        lines = [line.strip() for line in text.split("\n") if line.strip()]
        return "\n".join(lines)

    def extract_title_from_html(self, html: str, fallback: str) -> str:
        """Extract title from HTML content.

        Args:
            html: HTML content
            fallback: Fallback title if none found

        Returns:
            Extracted or fallback title
        """
        soup = BeautifulSoup(html, "html.parser")

        # Try various title sources
        title_tag = soup.find("title")
        if title_tag and title_tag.string:
            return title_tag.string.strip()

        h1_tag = soup.find("h1")
        if h1_tag:
            return h1_tag.get_text(strip=True)

        og_title = soup.find("meta", property="og:title")
        if og_title and og_title.get("content"):
            return og_title["content"]

        return fallback

    def chunk_content(
        self,
        content: str,
        chunk_size: int = 1000,
        overlap: int = 200
    ) -> List[str]:
        """Split content into overlapping chunks for RAG.

        Args:
            content: The content to chunk
            chunk_size: Target size for each chunk
            overlap: Characters to overlap between chunks

        Returns:
            List of content chunks
        """
        if len(content) <= chunk_size:
            return [content]

        chunks = []
        start = 0

        while start < len(content):
            end = start + chunk_size

            if end < len(content):
                # Try to end at sentence boundary
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

    async def index_url(
        self,
        url: str,
        vector_store,
        document_store: Dict[str, Document],
        custom_title: Optional[str] = None
    ) -> Optional[Document]:
        """Fetch, process, and index content from a URL.

        Args:
            url: The URL to index
            vector_store: VectorStoreService instance
            document_store: Dictionary to store document metadata
            custom_title: Optional custom title for the document

        Returns:
            Created Document, or None if indexing failed
        """
        # Fetch URL content
        result = await self.fetch_url(url)
        if not result:
            return None

        content = result["content"]
        content_type = result["content_type"]
        final_url = result["url"]

        # Extract text based on content type
        if "text/html" in content_type:
            text_content = self.extract_text_from_html(content)
            title = custom_title or self.extract_title_from_html(content, urlparse(final_url).netloc)
        else:
            text_content = content
            title = custom_title or urlparse(final_url).path.split("/")[-1] or urlparse(final_url).netloc

        if not text_content.strip():
            print(f"No content extracted from {url}")
            return None

        # Create document ID from URL
        doc_id = hashlib.md5(final_url.encode()).hexdigest()
        content_hash = hashlib.sha256(text_content.encode()).hexdigest()

        # Check if document needs updating
        existing_doc = document_store.get(doc_id)
        if existing_doc:
            if existing_doc.content_hash == content_hash:
                return existing_doc  # No update needed
            # Delete old chunks
            vector_store.delete_document(doc_id)

        # Create document
        doc = Document(
            id=doc_id,
            title=title,
            source_type=SourceType.URL,
            source_url=final_url,
            content_hash=content_hash,
            description=f"Content from {urlparse(final_url).netloc}"
        )

        # Chunk and index content
        chunks = self.chunk_content(text_content)
        vector_store.add_document_chunks(
            chunks=chunks,
            document_id=doc_id,
            metadata={
                "title": title,
                "source_type": SourceType.URL.value,
                "source_url": final_url,
                "domain": urlparse(final_url).netloc
            }
        )

        # Store document metadata
        document_store[doc_id] = doc

        return doc

    def index_url_sync(
        self,
        url: str,
        vector_store,
        document_store: Dict[str, Document],
        custom_title: Optional[str] = None
    ) -> Optional[Document]:
        """Synchronous wrapper for index_url."""
        import asyncio
        return asyncio.get_event_loop().run_until_complete(
            self.index_url(url, vector_store, document_store, custom_title)
        )
