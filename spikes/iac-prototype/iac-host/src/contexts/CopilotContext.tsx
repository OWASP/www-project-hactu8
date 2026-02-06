/**
 * Context provider for the IAC Copilot feature.
 * Manages copilot state, chat history, and document operations.
 */

import React, { createContext, useContext, useState, useCallback, useEffect } from 'react';
import type {
  CopilotState,
  CopilotContextValue,
  CopilotTab,
  ChatMessage,
  CopilotDocument,
} from '../types/copilot';
import copilotService from '../services/copilotService';
import { useFeatureFlags } from './FeatureFlagContext';

// Default state
const defaultState: CopilotState = {
  isExpanded: true,
  activeTab: 'assist',
  chatHistory: {
    assist: [],
    owasp: [],
    project: [],
  },
  documents: [],
  isLoading: false,
  isSyncing: false,
  error: null,
};

// Create context
const CopilotContext = createContext<CopilotContextValue | null>(null);

// Storage key for persisting state
const STORAGE_KEY = 'iac-copilot-state';

/**
 * Generate a unique ID for messages.
 */
function generateMessageId(): string {
  return `msg_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
}

/**
 * Load persisted state from localStorage.
 */
function loadPersistedState(): Partial<CopilotState> {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      const parsed = JSON.parse(stored);
      return {
        isExpanded: parsed.isExpanded ?? defaultState.isExpanded,
        activeTab: parsed.activeTab ?? defaultState.activeTab,
      };
    }
  } catch (error) {
    console.error('Error loading copilot state:', error);
  }
  return {};
}

/**
 * Save state to localStorage.
 */
function savePersistedState(state: Partial<CopilotState>): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      isExpanded: state.isExpanded,
      activeTab: state.activeTab,
    }));
  } catch (error) {
    console.error('Error saving copilot state:', error);
  }
}

/**
 * Provider component for the Copilot context.
 */
export const CopilotProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { flags } = useFeatureFlags();
  const copilotEnabled = flags.copilot?.enabled ?? false;
  const defaultExpanded = flags.copilot?.defaultExpanded ?? true;

  // Initialize state with persisted values
  const [state, setState] = useState<CopilotState>(() => {
    const persisted = loadPersistedState();
    return {
      ...defaultState,
      ...persisted,
      isExpanded: persisted.isExpanded ?? defaultExpanded,
    };
  });

  // Persist state changes
  useEffect(() => {
    savePersistedState({
      isExpanded: state.isExpanded,
      activeTab: state.activeTab,
    });
  }, [state.isExpanded, state.activeTab]);

  // Load documents on mount
  useEffect(() => {
    if (copilotEnabled) {
      refreshDocuments();
    }
  }, [copilotEnabled]);

  // Toggle sidebar expansion
  const toggle = useCallback(() => {
    setState(prev => ({ ...prev, isExpanded: !prev.isExpanded }));
  }, []);

  // Expand sidebar
  const expand = useCallback(() => {
    setState(prev => ({ ...prev, isExpanded: true }));
  }, []);

  // Collapse sidebar
  const collapse = useCallback(() => {
    setState(prev => ({ ...prev, isExpanded: false }));
  }, []);

  // Set active tab
  const setActiveTab = useCallback((tab: CopilotTab) => {
    setState(prev => ({ ...prev, activeTab: tab }));
  }, []);

  // Send a chat message
  const sendMessage = useCallback(async (message: string) => {
    const tab = state.activeTab;

    // Add user message to history
    const userMessage: ChatMessage = {
      id: generateMessageId(),
      role: 'user',
      content: message,
      timestamp: new Date(),
    };

    setState(prev => ({
      ...prev,
      isLoading: true,
      error: null,
      chatHistory: {
        ...prev.chatHistory,
        [tab]: [...prev.chatHistory[tab], userMessage],
      },
    }));

    try {
      // Get document IDs for context if in assist mode
      const contextDocumentIds = tab === 'assist'
        ? state.documents.filter(d => d.sourceType === 'user_upload').map(d => d.id)
        : undefined;

      // Send message to API
      const response = await copilotService.sendMessage(message, tab, contextDocumentIds);

      // Add assistant response to history
      const assistantMessage: ChatMessage = {
        id: generateMessageId(),
        role: 'assistant',
        content: response.reply,
        sources: response.sources,
        timestamp: new Date(),
      };

      setState(prev => ({
        ...prev,
        isLoading: false,
        chatHistory: {
          ...prev.chatHistory,
          [tab]: [...prev.chatHistory[tab], assistantMessage],
        },
      }));
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'An error occurred';

      // Add error message
      const errorResponse: ChatMessage = {
        id: generateMessageId(),
        role: 'assistant',
        content: `Sorry, I encountered an error: ${errorMessage}`,
        timestamp: new Date(),
      };

      setState(prev => ({
        ...prev,
        isLoading: false,
        error: errorMessage,
        chatHistory: {
          ...prev.chatHistory,
          [tab]: [...prev.chatHistory[tab], errorResponse],
        },
      }));
    }
  }, [state.activeTab, state.documents]);

  // Clear chat history for a tab
  const clearChat = useCallback((tab?: CopilotTab) => {
    setState(prev => {
      if (tab) {
        return {
          ...prev,
          chatHistory: {
            ...prev.chatHistory,
            [tab]: [],
          },
        };
      }
      return {
        ...prev,
        chatHistory: defaultState.chatHistory,
      };
    });
  }, []);

  // Upload a document
  const uploadDocument = useCallback(async (file: File, title?: string): Promise<CopilotDocument> => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const response = await copilotService.uploadDocument(file, title);

      // Convert API response to frontend format (handle both snake_case and camelCase)
      const apiDoc = response.document as any;
      const doc: CopilotDocument = {
        id: apiDoc.id,
        title: apiDoc.title,
        sourceType: (apiDoc.source_type || apiDoc.sourceType) as CopilotDocument['sourceType'],
        sourceUrl: apiDoc.source_url || apiDoc.sourceUrl,
        contentHash: apiDoc.content_hash || apiDoc.contentHash,
        fileName: apiDoc.file_name || apiDoc.fileName,
        fileSize: apiDoc.file_size || apiDoc.fileSize,
        mimeType: apiDoc.mime_type || apiDoc.mimeType,
        category: apiDoc.category,
        description: apiDoc.description,
        createdAt: apiDoc.created_at || apiDoc.createdAt,
        updatedAt: apiDoc.updated_at || apiDoc.updatedAt,
      };

      setState(prev => ({
        ...prev,
        isLoading: false,
        documents: [...prev.documents, doc],
      }));

      return doc;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Upload failed';
      setState(prev => ({ ...prev, isLoading: false, error: errorMessage }));
      throw error;
    }
  }, []);

  // Add document from URL
  const addDocumentUrl = useCallback(async (url: string, title?: string): Promise<CopilotDocument> => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const apiDoc = await copilotService.addDocumentUrl(url, title);

      // Convert API response to frontend format
      const doc: CopilotDocument = {
        id: apiDoc.id,
        title: apiDoc.title,
        sourceType: apiDoc.sourceType,
        sourceUrl: apiDoc.sourceUrl,
        contentHash: apiDoc.contentHash,
        fileName: apiDoc.fileName,
        fileSize: apiDoc.fileSize,
        mimeType: apiDoc.mimeType,
        category: apiDoc.category,
        description: apiDoc.description,
        createdAt: apiDoc.createdAt,
        updatedAt: apiDoc.updatedAt,
      };

      setState(prev => ({
        ...prev,
        isLoading: false,
        documents: [...prev.documents, doc],
      }));

      return doc;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to add URL';
      setState(prev => ({ ...prev, isLoading: false, error: errorMessage }));
      throw error;
    }
  }, []);

  // Remove a document
  const removeDocument = useCallback(async (id: string) => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      await copilotService.deleteDocument(id);

      setState(prev => ({
        ...prev,
        isLoading: false,
        documents: prev.documents.filter(d => d.id !== id),
      }));
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to remove document';
      setState(prev => ({ ...prev, isLoading: false, error: errorMessage }));
      throw error;
    }
  }, []);

  // Sync OWASP documents
  const syncOwaspDocs = useCallback(async () => {
    setState(prev => ({ ...prev, isSyncing: true, error: null }));

    try {
      await copilotService.syncOwaspDocuments();
      await refreshDocuments();

      setState(prev => ({ ...prev, isSyncing: false }));
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Sync failed';
      setState(prev => ({ ...prev, isSyncing: false, error: errorMessage }));
      throw error;
    }
  }, []);

  // Refresh documents list
  const refreshDocuments = useCallback(async () => {
    try {
      const response = await copilotService.listDocuments();

      // Convert API response to frontend format
      const docs: CopilotDocument[] = response.documents.map((d: any) => ({
        id: d.id,
        title: d.title,
        sourceType: d.source_type,
        sourceUrl: d.source_url,
        contentHash: d.content_hash,
        fileName: d.file_name,
        fileSize: d.file_size,
        mimeType: d.mime_type,
        category: d.category,
        description: d.description,
        createdAt: d.created_at,
        updatedAt: d.updated_at,
      }));

      setState(prev => ({ ...prev, documents: docs }));
    } catch (error) {
      console.error('Failed to refresh documents:', error);
    }
  }, []);

  // Context value
  const value: CopilotContextValue = {
    ...state,
    toggle,
    expand,
    collapse,
    setActiveTab,
    sendMessage,
    clearChat,
    uploadDocument,
    addDocumentUrl,
    removeDocument,
    syncOwaspDocs,
    refreshDocuments,
  };

  return (
    <CopilotContext.Provider value={value}>
      {children}
    </CopilotContext.Provider>
  );
};

/**
 * Hook to use the Copilot context.
 */
export const useCopilot = (): CopilotContextValue => {
  const context = useContext(CopilotContext);
  if (!context) {
    throw new Error('useCopilot must be used within a CopilotProvider');
  }
  return context;
};

export default CopilotContext;
