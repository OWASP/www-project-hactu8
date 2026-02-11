/**
 * Service for interacting with the IAC Copilot backend API.
 */

import type {
  ChatRequest,
  ChatResponse,
  CopilotDocument,
  DocumentListResponse,
  DocumentUploadResponse,
  OwaspSyncResponse,
  SourcesResponse,
  HealthResponse,
  CopilotTab,
} from '../types/copilot';
import type { ModelRegistryResponse } from '../types/modelProvider';
import { getModelProviderHeaders } from './modelProviderService';

// API base URL - configurable via environment variable
const RAW_COPILOT_API_BASE = import.meta.env.VITE_COPILOT_API_URL || '';

function normalizeApiBase(rawBase: string): string {
  const trimmed = rawBase.trim();
  if (!trimmed) {
    return '';
  }

  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    return trimmed;
  }

  if (trimmed.startsWith('/')) {
    return trimmed;
  }

  const protocol = typeof window !== 'undefined' ? window.location.protocol : 'http:';
  return `${protocol}//${trimmed}`;
}

export const COPILOT_API_BASE = normalizeApiBase(RAW_COPILOT_API_BASE);
const API_BASE = COPILOT_API_BASE;

/**
 * Generic fetch wrapper with error handling.
 */
async function fetchApi<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_BASE}${endpoint}`;

  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...getModelProviderHeaders(),
      ...options.headers,
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`API error (${response.status}): ${errorText}`);
  }

  return response.json();
}

/**
 * Check the health of the Copilot API.
 */
export async function checkHealth(): Promise<HealthResponse> {
  return fetchApi<HealthResponse>('/api/copilot/health');
}

/**
 * Send a chat message and get a RAG-enhanced response.
 */
export async function sendMessage(
  message: string,
  mode: CopilotTab,
  contextDocumentIds?: string[]
): Promise<ChatResponse> {
  const request: ChatRequest = {
    message,
    mode,
    contextDocumentIds,
  };

  return fetchApi<ChatResponse>('/api/copilot/chat', {
    method: 'POST',
    body: JSON.stringify(request),
  });
}

/**
 * List all indexed documents, optionally filtered by source type.
 */
export async function listDocuments(
  sourceType?: string
): Promise<DocumentListResponse> {
  const params = sourceType ? `?source_type=${sourceType}` : '';
  return fetchApi<DocumentListResponse>(`/api/copilot/documents${params}`);
}

/**
 * Upload a document file for indexing.
 */
export async function uploadDocument(
  file: File,
  title?: string
): Promise<DocumentUploadResponse> {
  const formData = new FormData();
  formData.append('file', file);
  if (title) {
    formData.append('title', title);
  }

  const url = `${API_BASE}/api/copilot/documents`;
  const response = await fetch(url, {
    method: 'POST',
    body: formData,
    headers: {
      ...getModelProviderHeaders(),
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Upload failed (${response.status}): ${errorText}`);
  }

  return response.json();
}

/**
 * Add a document from a URL for indexing.
 */
export async function addDocumentUrl(
  url: string,
  title?: string
): Promise<CopilotDocument> {
  return fetchApi<CopilotDocument>('/api/copilot/documents/url', {
    method: 'POST',
    body: JSON.stringify({ url, title }),
  });
}

/**
 * Delete a document and its indexed chunks.
 */
export async function deleteDocument(
  documentId: string
): Promise<{ deleted: boolean; chunksRemoved: number }> {
  return fetchApi<{ deleted: boolean; chunksRemoved: number }>(
    `/api/copilot/documents/${documentId}`,
    { method: 'DELETE' }
  );
}

/**
 * Sync OWASP documents from GitHub.
 */
export async function syncOwaspDocuments(): Promise<OwaspSyncResponse> {
  return fetchApi<OwaspSyncResponse>('/api/copilot/sync/owasp', {
    method: 'POST',
  });
}

/**
 * Get statistics about configured document sources.
 */
export async function getSources(): Promise<SourcesResponse> {
  return fetchApi<SourcesResponse>('/api/copilot/sources');
}

/**
 * Get overall statistics about the vector store and documents.
 */
export async function getStats(): Promise<{
  vectorStore: { name: string; count: number };
  documents: {
    total: number;
    byType: Record<string, number>;
  };
}> {
  return fetchApi('/api/copilot/stats');
}

/**
 * Get available model providers and models.
 */
export async function getModelRegistry(): Promise<ModelRegistryResponse> {
  return fetchApi<ModelRegistryResponse>('/api/copilot/models');
}

// Export service as default
const copilotService = {
  checkHealth,
  sendMessage,
  listDocuments,
  uploadDocument,
  addDocumentUrl,
  deleteDocument,
  syncOwaspDocuments,
  getSources,
  getStats,
  getModelRegistry,
};

export default copilotService;
