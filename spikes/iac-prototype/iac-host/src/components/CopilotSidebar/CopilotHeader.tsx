/**
 * Header component for the Copilot sidebar.
 */

import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useCopilot } from '../../contexts/CopilotContext';

const SETTINGS_SECTION_KEY = 'iac-settings-section';

interface CopilotHeaderProps {
  isMaximized?: boolean;
  onToggleMaximize?: () => void;
  onCollapse?: () => void;
}

const CopilotHeader: React.FC<CopilotHeaderProps> = ({
  isMaximized = false,
  onToggleMaximize,
  onCollapse,
}) => {
  const { collapse, clearChat, activeTab } = useCopilot();
  const navigate = useNavigate();

  const handleClearChat = () => {
    if (window.confirm('Clear chat history for this tab?')) {
      clearChat(activeTab);
    }
  };

  const handleOpenModelProvider = () => {
    localStorage.setItem(SETTINGS_SECTION_KEY, 'modelProvider');
    navigate('/settings');
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
          onClick={handleOpenModelProvider}
          title="Open Model Provider settings"
          aria-label="Open Model Provider settings"
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="3" />
            <path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1 1.54V21a2 2 0 1 1-4 0v-.09a1.7 1.7 0 0 0-1-1.54 1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.7 1.7 0 0 0 4.6 15a1.7 1.7 0 0 0-1.54-1H3a2 2 0 1 1 0-4h.06a1.7 1.7 0 0 0 1.54-1 1.7 1.7 0 0 0-.34-1.87l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.7 1.7 0 0 0 9 4.6a1.7 1.7 0 0 0 1-1.54V3a2 2 0 1 1 4 0v.06a1.7 1.7 0 0 0 1 1.54 1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.7 1.7 0 0 0 19.4 9a1.7 1.7 0 0 0 1.54 1H21a2 2 0 1 1 0 4h-.06a1.7 1.7 0 0 0-1.54 1z" />
          </svg>
        </button>
        <button
          className="copilot-header-btn"
          onClick={onToggleMaximize}
          title={isMaximized ? 'Restore size' : 'Maximize Copilot'}
          aria-pressed={isMaximized}
        >
          {isMaximized ? (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="9 3 3 3 3 9" />
              <polyline points="15 21 21 21 21 15" />
              <line x1="3" y1="3" x2="10" y2="10" />
              <line x1="21" y1="21" x2="14" y2="14" />
            </svg>
          ) : (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="14 3 21 3 21 10" />
              <polyline points="10 21 3 21 3 14" />
              <line x1="21" y1="3" x2="14" y2="10" />
              <line x1="3" y1="21" x2="10" y2="14" />
            </svg>
          )}
        </button>
        <button
          className="copilot-header-btn"
          onClick={onCollapse ?? collapse}
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
