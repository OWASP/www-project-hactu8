/**
 * Tab navigation for the Copilot sidebar.
 */

import React from 'react';
import { useCopilot } from '../../contexts/CopilotContext';
import { useFeatureFlags } from '../../contexts/FeatureFlagContext';
import type { CopilotTab } from '../../types/copilot';

interface Tab {
  id: CopilotTab;
  label: string;
  featureFlag: 'assistMode' | 'owaspDocs' | 'projectDocs' | 'checkLists';
}

const tabs: Tab[] = [
  { id: 'assist', label: 'Assist', featureFlag: 'assistMode' },
  { id: 'owasp', label: 'OWASP', featureFlag: 'owaspDocs' },
  { id: 'project', label: 'Project', featureFlag: 'projectDocs' },
  { id: 'checklists', label: 'Checklists', featureFlag: 'checkLists' },
];

const CopilotTabs: React.FC = () => {
  const { flags } = useFeatureFlags();
  const { activeTab, setActiveTab } = useCopilot();

  // Filter tabs based on feature flags
  const visibleTabs = tabs.filter(
    tab => flags.copilot?.[tab.featureFlag] !== false
  );

  return (
    <nav className="copilot-tabs">
      {visibleTabs.map(tab => (
        <button
          key={tab.id}
          className={`copilot-tab ${activeTab === tab.id ? 'active' : ''}`}
          onClick={() => setActiveTab(tab.id)}
        >
          {tab.label}
        </button>
      ))}
    </nav>
  );
};

export default CopilotTabs;
