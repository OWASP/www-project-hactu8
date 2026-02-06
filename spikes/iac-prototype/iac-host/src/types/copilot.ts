/**
 * Type definitions for the IAC Copilot feature.
 */

/** Types of document sources */
export type SourceType = 'user_upload' | 'owasp' | 'url' | 'project';

/** Copilot tabs/modes */
export type CopilotTab = 'assist' | 'owasp' | 'project' | 'checklists';

/** A document in the Copilot library */
export interface CopilotDocument {
  id: string;
  title: string;
  sourceType: SourceType;
  sourceUrl?: string;
  contentHash?: string;
  fileName?: string;
  fileSize?: number;
  mimeType?: string;
  category?: string;
  description?: string;
  createdAt: string;
  updatedAt: string;
}

/** Reference to a document used as a source in a response */
export interface DocumentRef {
  id: string;
  title: string;
  sourceType: SourceType;
  relevance: number;
}

/** A message in the chat conversation */
export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  sources?: DocumentRef[];
  timestamp: Date;
}

/** Request to send a chat message */
export interface ChatRequest {
  message: string;
  mode: CopilotTab;
  contextDocumentIds?: string[];
}

/** Response from the chat endpoint */
export interface ChatResponse {
  reply: string;
  sources: DocumentRef[];
}

/** Response from document upload */
export interface DocumentUploadResponse {
  document: CopilotDocument;
  chunksCreated: number;
}

/** Response from OWASP sync */
export interface OwaspSyncResponse {
  documentsSynced: number;
  documentsUpdated: number;
  documentsAdded: number;
}

/** Document list response */
export interface DocumentListResponse {
  documents: CopilotDocument[];
  total: number;
}

/** Source statistics */
export interface SourceStats {
  count: number;
  documents: {
    id: string;
    title: string;
    createdAt: string;
  }[];
}

/** All sources response */
export interface SourcesResponse {
  sources: {
    user_upload: SourceStats;
    owasp: SourceStats;
    url: SourceStats;
    project: SourceStats;
  };
  totalDocuments: number;
  totalChunks: number;
}

/** Health check response */
export interface HealthResponse {
  status: string;
  vectorStoreCount: number;
  documentCount: number;
}

/** Copilot state */
export interface CopilotState {
  isExpanded: boolean;
  activeTab: CopilotTab;
  chatHistory: {
    assist: ChatMessage[];
    owasp: ChatMessage[];
    project: ChatMessage[];
  };
  documents: CopilotDocument[];
  isLoading: boolean;
  isSyncing: boolean;
  error: string | null;
}

/** Copilot context actions */
export interface CopilotActions {
  toggle: () => void;
  expand: () => void;
  collapse: () => void;
  setActiveTab: (tab: CopilotTab) => void;
  sendMessage: (message: string) => Promise<void>;
  clearChat: (tab?: CopilotTab) => void;
  uploadDocument: (file: File, title?: string) => Promise<CopilotDocument>;
  addDocumentUrl: (url: string, title?: string) => Promise<CopilotDocument>;
  removeDocument: (id: string) => Promise<void>;
  syncOwaspDocs: () => Promise<void>;
  refreshDocuments: () => Promise<void>;
}

/** Combined Copilot context value */
export interface CopilotContextValue extends CopilotState, CopilotActions {}
