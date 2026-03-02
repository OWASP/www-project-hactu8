// src/components/Sidebar.tsx
import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import './Sidebar.css'; // optional styling
import { useFeatureFlags } from '../contexts/FeatureFlagContext';
import { useExtensions } from '../contexts/ExtensionContext';
import type { ExtensionCategory } from '../types/extensions';

// Placeholder SVG icons for demonstration
const icons = {
  dashboard: <svg width="20" height="20" fill="currentColor"><rect x="2" y="2" width="16" height="16" rx="4"/></svg>,
  assurance: <svg width="20" height="20" fill="currentColor"><circle cx="10" cy="10" r="8"/></svg>,
  extensions: <svg width="20" height="20" fill="currentColor"><rect x="4" y="4" width="12" height="12"/></svg>,
  workbench: <svg width="20" height="20" fill="currentColor"><path d="M2 10h16" stroke="currentColor" strokeWidth="2"/></svg>,
  registry: <svg width="20" height="20" fill="currentColor"><ellipse cx="10" cy="10" rx="8" ry="5"/></svg>,
  agents: <svg width="20" height="20" fill="currentColor"><circle cx="10" cy="7" r="3"/><rect x="7" y="12" width="6" height="5" rx="2"/></svg>,
  reports: <svg width="20" height="20" fill="currentColor"><rect x="4" y="4" width="12" height="12" rx="2"/><path d="M4 8h12" stroke="white" strokeWidth="2"/></svg>,
  logs: <svg width="20" height="20" fill="currentColor"><rect x="3" y="3" width="14" height="14" rx="3"/><path d="M7 7h6v6H7z" fill="white"/></svg>,
  users: <svg width="20" height="20" fill="currentColor"><circle cx="10" cy="7" r="3"/><rect x="5" y="12" width="10" height="5" rx="2"/></svg>,
  settings: <svg width="20" height="20" fill="currentColor"><circle cx="10" cy="10" r="8" stroke="currentColor" strokeWidth="2" fill="none"/><circle cx="10" cy="10" r="3"/></svg>,
  console: <svg width="20" height="20" fill="currentColor"><rect x="3" y="5" width="14" height="10" rx="2"/><path d="M6 9l2 2-2 2" stroke="white" strokeWidth="2" fill="none"/><rect x="12" y="11" width="2" height="2" fill="white"/></svg>,
  profile: <svg width="20" height="20" fill="currentColor" viewBox="0 0 20 20"><circle cx="10" cy="7" r="4"/><rect x="3" y="13" width="14" height="5" rx="2"/></svg>,
  library: <svg width="20" height="20" fill="currentColor" viewBox="0 0 20 20"><rect x="4" y="2" width="12" height="16" rx="1"/><path d="M7 6h6M7 9h6M7 12h4" stroke="white" strokeWidth="1.5"/></svg>,
  events: (
    <svg width="20" height="20" fill="currentColor" viewBox="0 0 20 20">
      <path d="M11 2L4 12h5l-1 6 7-10h-5l1-6z" fill="currentColor"/>
    </svg>
  ),
};


// Sidebar now loads Projects group dynamically after Monitoring

function useMockProjects() {
  const [projects, setProjects] = React.useState<any[]>([]);
  React.useEffect(() => {
    // Simulate API call
    setTimeout(() => {
      setProjects([
        { id: 'proj-1', name: 'Red Team Demo', path: '/projects/red-team' },
        { id: 'proj-2', name: 'Blue Team Demo', path: '/projects/blue-team' },
        { id: 'proj-3', name: 'Purple Team Demo', path: '/projects/purple-team' },
      ]);
    }, 600);
  }, []);
  return projects;
}

// Map extension categories to sidebar group headings.
// The extension's category in its manifest determines which sidebar group it appears in.
const CATEGORY_TO_GROUP: Record<ExtensionCategory, string> = {
  testing: 'Testing',
  linting: 'Tools',
  formatting: 'Tools',
  'security-scanning': 'Tools',
  integration: 'Other',
  reporting: 'Reporting',
  utility: 'Tools',
};

const Sidebar = () => {
  const location = useLocation();
  const { flags } = useFeatureFlags();
  const { installed: installedExtensions } = useExtensions();
  // sidebarState: 'collapsed' | 'expanded'
  const [sidebarState, setSidebarState] = useState('expanded');
  // Track expanded/collapsed state for each group
  const [expandedGroups, setExpandedGroups] = useState<Record<number, boolean>>(() => {
    // By default, all groups are expanded
    const state: Record<number, boolean> = {};
    // We'll set the right number of groups below
    return state;
  });

  const projects = useMockProjects();

  // Build extension nav items from installed extensions (persisted in localStorage)
  const extensionNavByGroup: Record<string, { path: string; label: string; icon: JSX.Element }[]> = {};
  for (const ext of installedExtensions) {
    const group = CATEGORY_TO_GROUP[ext.manifest.category] ?? 'Other';
    if (!extensionNavByGroup[group]) extensionNavByGroup[group] = [];
    extensionNavByGroup[group].push({
      path: `/ext/${ext.manifest.id}`,
      label: ext.manifest.name,
      icon: icons.extensions,
    });
  }

  // Compose navGroups with Projects injected after Monitoring
  const baseGroups = [
    {
      heading: '',
      items: [
        ...(flags.navigation.dashboard ? [{ path: '/', label: 'Dashboard', icon: icons.dashboard }] : []),
        ...(flags.navigation.registry ? [{ path: '/registry', label: 'Registry', icon: icons.registry }] : []),
        ...(flags.navigation.console ? [{ path: '/console', label: 'Console', icon: icons.console }] : []),
      ],
    },
    {
      heading: 'Monitoring',
      items: [
        ...(flags.monitoring.logs ? [{ path: '/logs', label: 'Logs', icon: icons.logs }] : []),
        ...(flags.monitoring.events ? [{ path: '/events', label: 'Events', icon: icons.events }] : []),
      ],
    },
  ];

  const projectsGroup = (flags.projects.enabled && projects.length > 0) ? {
    heading: 'Projects',
    items: projects.map((proj) => ({
      path: proj.path,
      label: proj.name,
      icon: icons.workbench, // Or a custom icon
    })),
  } : null;

  // Library is hidden when Copilot is enabled (Copilot replaces Library functionality)
  const libraryGroup = (flags.library.enabled && !flags.copilot?.enabled) ? {
    heading: 'Library',
    items: [
      { path: '/library?section=knowledge-base', label: 'Knowledge Base', icon: icons.library },
      ...(flags.library.projectDocs
        ? [{ path: '/library?section=project-docs', label: 'Project Documents', icon: icons.library }]
        : []),
      ...(flags.library.articles
        ? [{ path: '/library?section=research', label: 'Research', icon: icons.library }]
        : []),
    ],
  } : null;

  const restGroups = [
    {
      heading: 'Testing',
      items: [
        ...(flags.testing.promptInjection ? [{ path: '/prompt-injection', label: 'Prompt Injection Tester', icon: icons.assurance }] : []),
        ...(flags.testing.trainingLeak ? [{ path: '/training-leak', label: 'Training Data Leak Detector', icon: icons.assurance }] : []),
        ...(flags.testing.misbehaviorMonitor ? [{ path: '/misbehavior-monitor', label: 'Model Misbehavior Monitor', icon: icons.assurance }] : []),
        ...(flags.testing.overrelianceRisk ? [{ path: '/overreliance-risk', label: 'Overreliance Risk Analyzer', icon: icons.assurance }] : []),
        ...(flags.testing.agencyValidator ? [{ path: '/agency-validator', label: 'Excessive Agency Validator', icon: icons.assurance }] : []),
        ...(flags.testing.insecureOutput ? [{ path: '/insecure-output', label: 'Insecure Output Filter', icon: icons.assurance }] : []),
        ...(flags.testing.supplyChain ? [{ path: '/supply-chain', label: 'Supply Chain Trust Checker', icon: icons.assurance }] : []),
        ...(flags.testing.modelIdentity ? [{ path: '/model-identity', label: 'Model Identity & Version Tracker', icon: icons.assurance }] : []),
        ...(flags.testing.authContextAudit ? [{ path: '/auth-context-audit', label: 'Authorization & Context Audit', icon: icons.assurance }] : []),
        ...(flags.testing.privacyCompliance ? [{ path: '/privacy-compliance', label: 'Model Privacy Compliance Scanner', icon: icons.assurance }] : []),
        ...(extensionNavByGroup['Testing'] ?? []),
      ],
    },
    // Tools group — only appears when extensions with tool categories are installed
    ...((extensionNavByGroup['Tools'] ?? []).length > 0 ? [{
      heading: 'Tools',
      items: extensionNavByGroup['Tools'],
    }] : []),
    {
      heading: 'Reporting',
      items: [
        ...(flags.reporting.assuranceResults ? [{ path: '/assurance', label: 'Assurance Results', icon: icons.assurance }] : []),
        ...(flags.reporting.reports ? [{ path: '/reports', label: 'Reports', icon: icons.reports }] : []),
        ...(extensionNavByGroup['Reporting'] ?? []),
      ],
    },
    {
      heading: 'Other',
      items: [
        ...(flags.other.workbench ? [{ path: '/workbench', label: 'Workbench', icon: icons.workbench }] : []),
        ...(flags.other.agents ? [{ path: '/agents', label: 'Agents', icon: icons.agents }] : []),
        ...(flags.other.users ? [{ path: '/users', label: 'Users & Access', icon: icons.users }] : []),
        ...(extensionNavByGroup['Other'] ?? []),
      ],
    },
    {
      heading: 'User',
      items: [
        ...(flags.user.extensions ? [{ path: '/extensions', label: 'Extensions', icon: icons.extensions }] : []),
        ...(flags.user.profile ? [{ path: '/profile', label: 'Profile', icon: icons.profile }] : []),
        ...(flags.user.settings ? [{ path: '/settings', label: 'Settings', icon: icons.settings }] : []),
      ],
    },
  ];

  // Inject Projects group after Monitoring
  let navGroups = [...baseGroups];
  if (libraryGroup) navGroups.push(libraryGroup);
  if (projectsGroup) navGroups.push(projectsGroup);
  navGroups = [...navGroups, ...restGroups];

  // Ensure expandedGroups state matches navGroups length
  React.useEffect(() => {
    setExpandedGroups(prev => {
      const next: Record<number, boolean> = { ...prev };
      navGroups.forEach((_, i) => {
        if (!(i in next)) next[i] = true;
      });
      // Remove any extra keys (convert k to number)
      Object.keys(next).forEach(k => { if (parseInt(k, 10) >= navGroups.length) delete next[parseInt(k, 10)]; });
      return next;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [navGroups.length]);

  const handleToggle = () => {
    setSidebarState(prev => prev === 'expanded' ? 'collapsed' : 'expanded');
  };

  const handleGroupToggle = (idx: number) => {
    setExpandedGroups(prev => ({ ...prev, [idx]: !prev[idx] }));
  };

  // Define header and navbar heights as constants
  const HEADER_HEIGHT = 64;
  const NAVBAR_HEIGHT = 44;
  const SIDEBAR_VERTICAL_OFFSET = HEADER_HEIGHT + NAVBAR_HEIGHT;

  return (
    <div
      className={`sidebar ${sidebarState}`}
      style={{
        height: `calc(100vh - ${SIDEBAR_VERTICAL_OFFSET}px)`,
        maxHeight: `calc(100vh - ${SIDEBAR_VERTICAL_OFFSET}px)`,
      }}
    >
      <div className={`sidebar-header ${sidebarState}`}>
        {sidebarState === 'expanded' && <h2 className="sidebar-header__title">Menu</h2>}
        <div className="sidebar-header__buttons">
          <button className="sidebar-toggle-btn" onClick={handleToggle} title={sidebarState === 'expanded' ? 'Collapse' : 'Expand'}>
            {sidebarState === 'expanded' ? (
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="9 18 15 12 9 6" />
              </svg>
            ) : (
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="15 18 9 12 15 6" />
              </svg>
            )}
          </button>
        </div>
      </div>
      <ul className="sidebar-nav">
        {navGroups.map((group, groupIdx) => (
          <React.Fragment key={group.heading + groupIdx}>
            {sidebarState === 'expanded' && group.heading && (
              <li className="sidebar-nav__group-heading">
                {/* Only show toggle if group has items */}
                {group.items.length > 0 && (
                  <button
                    className="sidebar-nav__group-toggle"
                    onClick={() => handleGroupToggle(groupIdx)}
                    title={expandedGroups[groupIdx] ? 'Collapse' : 'Expand'}
                  >
                    {expandedGroups[groupIdx] ? (
                      // Down arrow
                      <svg className="sidebar-nav__group-toggle-icon" width="18" height="18" fill="#6b7280" viewBox="0 0 18 18">
                        <path d="M5 7l4 4 4-4" stroke="#6b7280" strokeWidth="2" fill="none"/>
                      </svg>
                    ) : (
                      // Right arrow
                      <svg className="sidebar-nav__group-toggle-icon" width="18" height="18" fill="#6b7280" viewBox="0 0 18 18">
                        <path d="M7 5l4 4-4 4" stroke="#6b7280" strokeWidth="2" fill="none"/>
                      </svg>
                    )}
                  </button>
                )}
                <span>{group.heading}</span>
              </li>
            )}
            {expandedGroups[groupIdx] !== false && group.items.map((item) => {
              const isActive = location.pathname === item.path;
              return (
                <li key={item.path} className="sidebar-nav__item">
                  <Link to={item.path} className={`sidebar-nav__link ${sidebarState} ${isActive ? 'active' : ''}`}>
                    <span className="sidebar-nav__link-icon">{item.icon}</span>
                    {sidebarState === 'expanded' && <span>{item.label}</span>}
                  </Link>
                </li>
              );
            })}
          </React.Fragment>
        ))}
      </ul>
    </div>
  );
};

export default Sidebar;

