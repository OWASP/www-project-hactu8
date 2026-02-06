/**
 * Header component for the Copilot sidebar.
 */

import React from 'react';
import { useCopilot } from '../../contexts/CopilotContext';

const CopilotHeader: React.FC = () => {
  const { collapse, clearChat, activeTab } = useCopilot();

  const handleClearChat = () => {
    if (window.confirm('Clear chat history for this tab?')) {
      clearChat(activeTab);
    }
  };

  return (
    <header className="copilot-header">
      <div className="copilot-header-title">
        {/* <svg className="copilot-header-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
        </svg> */}
        <span>IAC Copilot</span>
      </div>
      <div className="copilot-header-actions">
        <button
          className="copilot-header-btn"
          onClick={handleClearChat}
          title="Clear chat"
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="3 6 5 6 21 6" />
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
          </svg>
        </button>
        <button
          className="copilot-header-btn"
          onClick={collapse}
          title="Collapse sidebar"
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="9 18 15 12 9 6" />
          </svg>
        </button>
      </div>
    </header>
  );
};

export default CopilotHeader;
