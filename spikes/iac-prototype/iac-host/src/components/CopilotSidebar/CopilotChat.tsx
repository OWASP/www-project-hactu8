/**
 * Chat interface component for the Copilot.
 */

import React, { useState, useRef, useEffect } from 'react';
import { useCopilot } from '../../contexts/CopilotContext';

const CopilotChat: React.FC = () => {
  const { chatHistory, activeTab, isLoading, sendMessage } = useCopilot();
  const [input, setInput] = useState('');
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Get messages for current tab
  const messages = chatHistory[activeTab] || [];

  // Scroll to bottom when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'nearest' });
  }, [messages]);

  // Focus input on tab change
  useEffect(() => {
    inputRef.current?.focus({ preventScroll: true });
  }, [activeTab]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmedInput = input.trim();
    if (!trimmedInput || isLoading) return;

    setInput('');
    await sendMessage(trimmedInput);
  };

  const getPlaceholder = () => {
    switch (activeTab) {
      case 'assist':
        return 'Ask about your documents...';
      case 'owasp':
        return 'Ask about OWASP AI security...';
      case 'project':
        return 'Ask about HACTU8 project...';
      default:
        return 'Type a message...';
    }
  };

  return (
    <div className="copilot-chat">
      <div className="copilot-chat-messages">
        {messages.length === 0 && (
          <div className="copilot-empty">
            <div className="copilot-empty-icon">
              {activeTab === 'assist' && '📄'}
              {activeTab === 'owasp' && '🛡️'}
              {activeTab === 'project' && '📚'}
            </div>
            <p className="copilot-empty-text">
              {activeTab === 'assist' && 'Upload documents and ask questions about them. I can help with research, summarization, and analysis.'}
              {activeTab === 'owasp' && 'Ask me about OWASP AI security guidelines, Top 10 for LLM, and best practices.'}
              {activeTab === 'project' && 'Ask me about the HACTU8 project documentation, architecture, and implementation.'}
            </p>
          </div>
        )}

        {messages.map(message => (
          <div
            key={message.id}
            className={`copilot-message ${message.role}`}
          >
            <div className="copilot-message-content">
              {message.content}
            </div>
            {message.sources && message.sources.length > 0 && (
              <div className="copilot-message-sources">
                <span>Sources: </span>
                {message.sources.map((source, idx) => (
                  <span key={idx} className="copilot-message-source">
                    {source.title}
                  </span>
                ))}
              </div>
            )}
          </div>
        ))}

        {isLoading && (
          <div className="copilot-message assistant">
            <div className="copilot-loading">
              <div className="copilot-loading-dots">
                <span className="copilot-loading-dot" />
                <span className="copilot-loading-dot" />
                <span className="copilot-loading-dot" />
              </div>
              <span>Thinking...</span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      <form className="copilot-chat-input" onSubmit={handleSubmit}>
        <input
          ref={inputRef}
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder={getPlaceholder()}
          disabled={isLoading}
        />
        <button type="submit" disabled={!input.trim() || isLoading}>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <line x1="22" y1="2" x2="11" y2="13" />
            <polygon points="22 2 15 22 11 13 2 9 22 2" />
          </svg>
        </button>
      </form>
    </div>
  );
};

export default CopilotChat;
