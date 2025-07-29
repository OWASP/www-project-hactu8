// src/components/Sidebar.tsx
import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import './Sidebar.css'; // optional styling

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
  events: (
    <svg width="20" height="20" fill="currentColor" viewBox="0 0 20 20">
      <path d="M11 2L4 12h5l-1 6 7-10h-5l1-6z" fill="currentColor"/>
    </svg>
  ),
};

const navGroups = [
  {
    heading: '',
    items: [
      { path: '/', label: 'Dashboard', icon: icons.dashboard },
      { path: '/registry', label: 'Registry', icon: icons.registry },
      { path: '/console', label: 'Console', icon: icons.console },
    ],
  },
  {
    heading: 'Monitoring',
    items: [
      { path: '/logs', label: 'Logs', icon: icons.logs },
      { path: '/events', label: 'Events', icon: icons.events },
    ],
  },
  {
    heading: 'Testing',
    items: [
      { path: '/prompt-injection', label: 'Prompt Injection Tester', icon: icons.assurance },
      { path: '/training-leak', label: 'Training Data Leak Detector', icon: icons.assurance },
      { path: '/misbehavior-monitor', label: 'Model Misbehavior Monitor', icon: icons.assurance },
      { path: '/overreliance-risk', label: 'Overreliance Risk Analyzer', icon: icons.assurance },
      { path: '/agency-validator', label: 'Excessive Agency Validator', icon: icons.assurance },
      { path: '/insecure-output', label: 'Insecure Output Filter', icon: icons.assurance },
      { path: '/supply-chain', label: 'Supply Chain Trust Checker', icon: icons.assurance },
      { path: '/model-identity', label: 'Model Identity & Version Tracker', icon: icons.assurance },
      { path: '/auth-context-audit', label: 'Authorization & Context Audit', icon: icons.assurance },
      { path: '/privacy-compliance', label: 'Model Privacy Compliance Scanner', icon: icons.assurance },
    ],
  },
  {
    heading: 'Reporting',
    items: [
      { path: '/assurance', label: 'Assurance Results', icon: icons.assurance },
      { path: '/reports', label: 'Reports', icon: icons.reports },
    ],
  },
  {
    heading: 'Other',
    items: [
      { path: '/workbench', label: 'Workbench', icon: icons.workbench },
      { path: '/agents', label: 'Agents', icon: icons.agents },
      { path: '/users', label: 'Users & Access', icon: icons.users },
    ],
  },
    {
    heading: 'User',
    items: [
      { path: '/extensions', label: 'Extensions', icon: icons.extensions },
      { path: '/profile', label: 'Profile', icon: icons.profile },
      { path: '/settings', label: 'Settings', icon: icons.settings },
    ],
  },
];


const Sidebar = () => {
  const location = useLocation();
  // sidebarState: 'hidden' | 'collapsed' | 'expanded'
  const [sidebarState, setSidebarState] = useState('expanded');
  // Track expanded/collapsed state for each group
  const [expandedGroups, setExpandedGroups] = useState<Record<number, boolean>>(() => {
    // By default, all groups are expanded
    const state: Record<number, boolean> = {};
    navGroups.forEach((_, i) => { state[i] = true; });
    return state;
  });

  const handleToggle = () => {
    setSidebarState(prev => prev === 'expanded' ? 'collapsed' : 'expanded');
  };
  const handleHide = () => {
    setSidebarState('hidden');
  };
  const handleShow = () => {
    setSidebarState('expanded');
  };

  const handleGroupToggle = (idx: number) => {
    setExpandedGroups(prev => ({ ...prev, [idx]: !prev[idx] }));
  };

  if (sidebarState === 'hidden') {
    return (
      <button className="sidebar-show-btn" onClick={handleShow} title="Show Sidebar" style={{ position: 'absolute', top: 16, left: 0, zIndex: 50 }}>
        {/* Show icon */}
        <svg width="24" height="24" fill="currentColor"><path d="M4 12h16M4 6h16M4 18h16" stroke="currentColor" strokeWidth="2"/></svg>
      </button>
    );
  }

  // Define header and navbar heights as constants
  const HEADER_HEIGHT = 64;
  const NAVBAR_HEIGHT = 44;
  const SIDEBAR_VERTICAL_OFFSET = HEADER_HEIGHT + NAVBAR_HEIGHT;

  return (
    <div
      className={`sidebar ${sidebarState}`}
      style={{
        width: sidebarState === 'expanded' ? 400 : 60,
        transition: 'width 0.2s',
        minWidth: 0,
        height: `calc(100vh - ${SIDEBAR_VERTICAL_OFFSET}px)`, // 64px header + 44px navbar
        maxHeight: `calc(100vh - ${SIDEBAR_VERTICAL_OFFSET}px)`,
        overflowY: 'auto',
      }}
    >
      <div className="sidebar-header" style={{ display: 'flex', alignItems: 'center', justifyContent: sidebarState === 'expanded' ? 'space-between' : 'center', padding: '1rem 0.5rem' }}>
        {sidebarState === 'expanded' && <h2 style={{ margin: 0, fontSize: 20 }}>Menu</h2>}
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="sidebar-toggle-btn" onClick={handleToggle} title={sidebarState === 'expanded' ? 'Collapse' : 'Expand'} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 4 }}>
            {sidebarState === 'expanded' ? (
              <svg width="20" height="20" fill="currentColor"><path d="M14 10l-4 4V6z"/></svg>
            ) : (
              <svg width="20" height="20" fill="currentColor"><path d="M6 10l4-4v8z"/></svg>
            )}
          </button>
          <button className="sidebar-hide-btn" onClick={handleHide} title="Hide Sidebar" style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 4 }}>
            <svg width="20" height="20" fill="currentColor"><rect x="4" y="9" width="12" height="2"/></svg>
          </button>
        </div>
      </div>
      <ul className="sidebar-nav" style={{ listStyle: 'none', padding: 0, margin: 0, paddingBottom: '5rem' }}>
        {navGroups.map((group, groupIdx) => (
          <React.Fragment key={group.heading + groupIdx}>
            {sidebarState === 'expanded' && group.heading && (
              <li style={{ margin: '16px 0 4px 4px', fontWeight: 600, fontSize: 18, color: '#6b7280', letterSpacing: 0.5, display: 'flex', alignItems: 'center' }}>
                {/* Only show toggle if group has items */}
                {group.items.length > 0 && (
                  <button
                    onClick={() => handleGroupToggle(groupIdx)}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2, marginRight: 8, display: 'flex', alignItems: 'center' }}
                    title={expandedGroups[groupIdx] ? 'Collapse' : 'Expand'}
                  >
                    {expandedGroups[groupIdx] ? (
                      // Down arrow
                      <svg width="18" height="18" fill="#6b7280" viewBox="0 0 18 18" style={{ display: 'block' }}>
                        <path d="M5 7l4 4 4-4" stroke="#6b7280" strokeWidth="2" fill="none"/>
                      </svg>
                    ) : (
                      // Right arrow
                      <svg width="18" height="18" fill="#6b7280" viewBox="0 0 18 18" style={{ display: 'block' }}>
                        <path d="M7 5l4 4-4 4" stroke="#6b7280" strokeWidth="2" fill="none"/>
                      </svg>
                    )}
                  </button>
                )}
                <span>{group.heading}</span>
              </li>
            )}
            {expandedGroups[groupIdx] !== false && group.items.map((item) => {
              return (
                <li key={item.path} className={location.pathname === item.path ? 'active' : ''} style={{ marginBottom: 8 }}>
                  <Link to={item.path} style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 12,
                    padding: '8px 12px',
                    borderRadius: 6,
                    textDecoration: 'none',
                    color: 'inherit',
                    background: location.pathname === item.path ? '#213547' : 'none',
                    justifyContent: sidebarState === 'expanded' ? 'flex-start' : 'center',
                    transition: 'background 0.2s',
                    minWidth: 0
                  }}>
                    <span style={{ display: 'flex', alignItems: 'center', minWidth: 24 }}>{item.icon}</span>
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