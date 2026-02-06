/**
 * Assist Panel - for uploading documents and URLs for active work assistance.
 */

import React, { useState, useRef, useCallback } from 'react';
import { useCopilot } from '../../../contexts/CopilotContext';

const AssistPanel: React.FC = () => {
  const { documents, uploadDocument, addDocumentUrl, removeDocument, isLoading } = useCopilot();
  const [urlInput, setUrlInput] = useState('');
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Filter to show only user uploaded documents
  const userDocs = documents.filter(d => d.sourceType === 'user_upload' || d.sourceType === 'url');

  const handleFileSelect = useCallback(async (files: FileList | null) => {
    if (!files || files.length === 0) return;

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      try {
        await uploadDocument(file);
      } catch (error) {
        console.error('Failed to upload file:', error);
      }
    }
  }, [uploadDocument]);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    handleFileSelect(e.dataTransfer.files);
  }, [handleFileSelect]);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
  }, []);

  const handleUrlSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmedUrl = urlInput.trim();
    if (!trimmedUrl) return;

    try {
      await addDocumentUrl(trimmedUrl);
      setUrlInput('');
    } catch (error) {
      console.error('Failed to add URL:', error);
    }
  };

  const handleDelete = async (id: string) => {
    if (window.confirm('Remove this document?')) {
      try {
        await removeDocument(id);
      } catch (error) {
        console.error('Failed to remove document:', error);
      }
    }
  };

  const getDocIcon = (doc: typeof userDocs[0]) => {
    if (doc.sourceType === 'url') return '🔗';
    if (doc.mimeType?.includes('pdf')) return '📕';
    if (doc.mimeType?.includes('markdown') || doc.fileName?.endsWith('.md')) return '📝';
    return '📄';
  };

  return (
    <div className="assist-panel">
      {/* Upload Area */}
      <div
        className={`copilot-upload-area ${isDragOver ? 'drag-over' : ''}`}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onClick={() => fileInputRef.current?.click()}
      >
        <div className="copilot-upload-icon">📎</div>
        <div className="copilot-upload-text">
          Drop files here or click to upload
        </div>
        <input
          ref={fileInputRef}
          type="file"
          multiple
          accept=".txt,.md,.pdf,.json"
          style={{ display: 'none' }}
          onChange={e => handleFileSelect(e.target.files)}
        />
      </div>

      {/* URL Input */}
      <form className="copilot-url-input" onSubmit={handleUrlSubmit}>
        <input
          type="url"
          value={urlInput}
          onChange={e => setUrlInput(e.target.value)}
          placeholder="Add URL..."
          disabled={isLoading}
        />
        <button type="submit" disabled={!urlInput.trim() || isLoading}>
          Add
        </button>
      </form>

      {/* Document List */}
      <div className="copilot-section-header">
        <span className="copilot-section-title">Your Documents ({userDocs.length})</span>
      </div>

      {userDocs.length === 0 ? (
        <div className="copilot-empty" style={{ padding: '20px' }}>
          <p className="copilot-empty-text" style={{ fontSize: '12px' }}>
            No documents yet. Upload files or add URLs to get started.
          </p>
        </div>
      ) : (
        <div className="copilot-doc-list">
          {userDocs.map(doc => (
            <div key={doc.id} className="copilot-doc-item">
              <div className="copilot-doc-info">
                <span className="copilot-doc-icon">{getDocIcon(doc)}</span>
                <span className="copilot-doc-title" title={doc.title}>
                  {doc.title}
                </span>
              </div>
              <button
                className="copilot-doc-delete"
                onClick={() => handleDelete(doc.id)}
                title="Remove document"
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default AssistPanel;
