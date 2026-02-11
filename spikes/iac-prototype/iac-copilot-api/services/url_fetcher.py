"""Service for fetching and indexing content from URLs."""

import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import httpx
from bs4 import BeautifulSoup

from models.document import Document, SourceType


class URLFetcher:
    """Fetches and indexes content from user-provided URLs."""

    def __init__(self):
        self.timeout = 30.0

    async def fetch_url(self, url: str) -> Optional[Dict[str, Any]]:
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

                if not any(ct in content_type for ct in ["text/", "application/json"]):
                    print(f"Unsupported content type for {url}: {content_type}")
                    return None

                return {
                    "url": str(response.url),
                    "content": response.text,
                    "content_type": content_type,
                    "status_code": response.status_code
                }

        except Exception as e:
            print(f"Error fetching {url}: {str(e)}")
            return None

    def extract_text_from_html(self, html: str) -> str:
        soup = BeautifulSoup(html, "html.parser")

        for element in soup(["script", "style", "nav", "footer", "header", "aside"]):
            element.decompose()

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

        lines = [line.strip() for line in text.split("\n") if line.strip()]
        return "\n".join(lines)

    def extract_title_from_html(self, html: str, fallback: str) -> str:
        soup = BeautifulSoup(html, "html.parser")

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

    async def index_url(
        self,
        url: str,
        vector_store,
        document_store: Dict[str, Document],
        custom_title: Optional[str] = None
    ) -> Optional[Document]:
        result = await self.fetch_url(url)
        if not result:
            return None

        content = result["content"]
        content_type = result["content_type"]
        final_url = result["url"]

        if "text/html" in content_type:
            text_content = self.extract_text_from_html(content)
            title = custom_title or self.extract_title_from_html(content, urlparse(final_url).netloc)
        else:
            text_content = content
            title = custom_title or urlparse(final_url).path.split("/")[-1] or final_url

        doc_id = vector_store.compute_content_hash(f"url:{final_url}")
        content_hash = vector_store.compute_content_hash(text_content)

        existing = document_store.get(doc_id)
        if existing and existing.content_hash == content_hash:
            return existing

        doc = Document(
            id=doc_id,
            title=title,
            source_type=SourceType.URL,
            source_url=final_url,
            content_hash=content_hash
        )

        chunks = self.chunk_content(text_content)
        vector_store.add_document_chunks(
            chunks=chunks,
            document_id=doc_id,
            metadata={
                "title": title,
                "source_type": SourceType.URL.value,
            },
            collection_key="assist"
        )

        document_store[doc_id] = doc
        return doc
