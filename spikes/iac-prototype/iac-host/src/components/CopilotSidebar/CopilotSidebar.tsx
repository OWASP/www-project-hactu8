/**
 * Main CopilotSidebar component - the right-side panel for IAC Copilot.
 */

import React from 'react';
import { useCopilot } from '../../contexts/CopilotContext';
import { useFeatureFlags } from '../../contexts/FeatureFlagContext';
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
    <aside className="copilot-sidebar expanded">
      <CopilotHeader />
      <CopilotTabs />
      <div className="copilot-panel-content">
        {renderPanel()}
      </div>
      <CopilotChat />
    </aside>
  );
};

export default CopilotSidebar;
