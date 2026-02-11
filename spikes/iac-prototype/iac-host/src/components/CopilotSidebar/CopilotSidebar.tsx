/**
 * Main CopilotSidebar component - the right-side panel for IAC Copilot.
 */

import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useCopilot } from '../../contexts/CopilotContext';
import { useFeatureFlags } from '../../contexts/FeatureFlagContext';
import { useModelProvider } from '../../contexts/ModelProviderContext';
import CopilotHeader from './CopilotHeader';
import CopilotTabs from './CopilotTabs';
import CopilotChat from './CopilotChat';
import AssistPanel from './panels/AssistPanel';
import OwaspDocsPanel from './panels/OwaspDocsPanel';
import ProjectDocsPanel from './panels/ProjectDocsPanel';
import './CopilotSidebar.css';

const CopilotSidebar: React.FC = () => {
  const { flags } = useFeatureFlags();
  const { isExpanded, activeTab, toggle } = useCopilot();
  const { config } = useModelProvider();
  const isProviderConfigured = Boolean(config?.model);
  const [isMaximized, setIsMaximized] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    if (!isExpanded && isMaximized) {
      setIsMaximized(false);
    }
  }, [isExpanded, isMaximized]);

  useEffect(() => {
    if (!isMaximized) return;

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsMaximized(false);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isMaximized]);

  const handleToggleMaximize = () => {
    setIsMaximized(prev => !prev);
  };

  const handleCollapse = () => {
    setIsMaximized(false);
    toggle();
  };

  const handleOpenModelProvider = (event: React.MouseEvent<HTMLAnchorElement>) => {
    event.preventDefault();
    localStorage.setItem('iac-settings-section', 'modelProvider');
    navigate('/settings');
  };

  // Don't render if copilot is disabled
  if (!flags.copilot?.enabled) {
    return null;
  }

  // Render collapsed state
  if (!isExpanded) {
    return (
      <aside className="copilot-sidebar collapsed">
        <button
          className="copilot-collapsed-toggle"
          onClick={toggle}
          title="Expand IAC Copilot"
        >
          <svg className="copilot-collapsed-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
          </svg>
          <span className="copilot-collapsed-label">IAC Copilot</span>
        </button>
      </aside>
    );
  }

  // Render the appropriate panel based on active tab
  const renderPanel = () => {
    switch (activeTab) {
      case 'assist':
        return flags.copilot?.assistMode !== false && <AssistPanel />;
      case 'owasp':
        return flags.copilot?.owaspDocs !== false && <OwaspDocsPanel />;
      case 'project':
        return flags.copilot?.projectDocs !== false && <ProjectDocsPanel />;
      default:
        return null;
    }
  };

  return (
    <>
      {isMaximized && (
        <div
          className="copilot-overlay"
          onClick={handleToggleMaximize}
          aria-hidden="true"
        />
      )}
      <aside className={`copilot-sidebar expanded${isMaximized ? ' maximized' : ''}`}>
        <CopilotHeader
          isMaximized={isMaximized}
          onToggleMaximize={handleToggleMaximize}
          onCollapse={handleCollapse}
        />
        {!isProviderConfigured && (
          <div className="copilot-provider-banner" role="status">
            <div className="copilot-provider-banner-title">Model provider not configured</div>
            <div className="copilot-provider-banner-text">
              Select a provider and model in Settings to enable responses.
            </div>
            <a
              className="copilot-provider-banner-link"
              href="/settings"
              onClick={handleOpenModelProvider}
            >
              Open Settings
            </a>
          </div>
        )}
        <CopilotTabs />
        <div className="copilot-panel-content">
          {renderPanel()}
        </div>
        <CopilotChat />
      </aside>
    </>
  );
};

export default CopilotSidebar;
