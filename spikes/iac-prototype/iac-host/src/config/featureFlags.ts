// src/config/featureFlags.ts

export interface FeatureFlags {
  // Sidebar Navigation Items
  navigation: {
    dashboard: boolean;
    workbench: boolean;
    registry: boolean;
    console: boolean;
  };
  monitoring: {
    logs: boolean;
    events: boolean;
  };
  projects: {
    enabled: boolean;
  };
  library: {
    enabled: boolean;
    articles: boolean;
    projectDocs: boolean;
    owaspAI: boolean;
    references: boolean;
  };
  // IAC Copilot - Right sidebar with LLM-powered assistance
  copilot: {
    enabled: boolean;
    assistMode: boolean;      // Active work assistance (research, planning, summarization)
    owaspDocs: boolean;       // OWASP document lookup
    projectDocs: boolean;     // HACTU8 project documentation
    defaultExpanded: boolean; // Whether copilot is expanded on app load
  };
  testing: {
    promptInjection: boolean;
    trainingLeak: boolean;
    misbehaviorMonitor: boolean;
    overrelianceRisk: boolean;
    agencyValidator: boolean;
    insecureOutput: boolean;
    supplyChain: boolean;
    modelIdentity: boolean;
    authContextAudit: boolean;
    privacyCompliance: boolean;
  };
  reporting: {
    assuranceResults: boolean;
    reports: boolean;
  };
  skills: {
    enabled: boolean;
    creator: boolean;
    installed: boolean;
    explorer: boolean;
  };
  agents: {
    enabled: boolean;
    phases: boolean;
    skills: boolean;
    mcpClients: boolean;
    // Agent Catalog sub-pages (Explorer/Installed/Creator) — distinct from
    // the engagement-phase `skills` flag above. Mirrors `skills` below.
    catalog: {
      enabled: boolean;
      creator: boolean;
      installed: boolean;
      explorer: boolean;
    };
  };
  other: {
    users: boolean;
  };
  user: {
    extensions: boolean;
    profile: boolean;
    settings: boolean;
  };
  // Navbar Features
  navbar: {
    createNewResource: boolean;
  };
}

// Default feature flags configuration
// Set to true to enable a feature, false to disable
export const defaultFeatureFlags: FeatureFlags = {
  navigation: {
    dashboard: true,
    workbench: true,
    registry: true,
    console: true,
  },
  monitoring: {
    logs: true,
    events: true,
  },
  projects: {
    enabled: true,
  },
  library: {
    enabled: false, // Disabled - replaced by Copilot
    articles: true,
    projectDocs: true,
    owaspAI: true,
    references: true,
  },
  copilot: {
    enabled: true,
    assistMode: true,
    owaspDocs: true,
    projectDocs: true,
    defaultExpanded: true,
  },
  testing: {
    promptInjection: true,
    trainingLeak: true,
    misbehaviorMonitor: true,
    overrelianceRisk: true,
    agencyValidator: true,
    insecureOutput: true,
    supplyChain: true,
    modelIdentity: true,
    authContextAudit: true,
    privacyCompliance: true,
  },
  reporting: {
    assuranceResults: true,
    reports: true,
  },
  skills: {
    enabled: true,
    creator: true,
    installed: true,
    explorer: true,
  },
  agents: {
    enabled: true,
    phases: true,
    skills: true,
    mcpClients: false,
    catalog: {
      enabled: true,
      creator: true,
      installed: true,
      explorer: true,
    },
  },
  other: {
    users: true,
  },
  user: {
    extensions: true,
    profile: true,
    settings: true,
  },
  navbar: {
    createNewResource: true,
  },
};

// Helper function to check if a feature is enabled
export const isFeatureEnabled = (
  flags: FeatureFlags,
  category: keyof FeatureFlags,
  feature: string
): boolean => {
  const categoryFlags = flags[category] as any;
  return categoryFlags?.[feature] ?? false;
};

const FLAGS_SCHEMA_VERSION = 4; // Increment when flag shape changes to bust stale localStorage

// Helper to load feature flags from localStorage or environment
export const loadFeatureFlags = (): FeatureFlags => {
  try {
    // Bust stale localStorage if schema version changed
    const storedVersion = parseInt(localStorage.getItem('featureFlagsVersion') ?? '0', 10);
    if (storedVersion < FLAGS_SCHEMA_VERSION) {
      localStorage.removeItem('featureFlags');
      localStorage.setItem('featureFlagsVersion', String(FLAGS_SCHEMA_VERSION));
      return defaultFeatureFlags;
    }

    // Try to load from localStorage first
    const stored = localStorage.getItem('featureFlags');
    if (stored) {
      const parsed = JSON.parse(stored);
      //  Merge with defaults to ensure all flags exist
      const p = parsed;
      // Merge only known keys per group to prevent stale localStorage keys bleeding in
      return {
        navigation: {
          dashboard:  p.navigation?.dashboard  ?? defaultFeatureFlags.navigation.dashboard,
          workbench:  p.navigation?.workbench  ?? defaultFeatureFlags.navigation.workbench,
          registry:   p.navigation?.registry   ?? defaultFeatureFlags.navigation.registry,
          console:    p.navigation?.console    ?? defaultFeatureFlags.navigation.console,
        },
        monitoring: { ...defaultFeatureFlags.monitoring, ...p.monitoring },
        projects:   { ...defaultFeatureFlags.projects,   ...p.projects },
        library:    { ...defaultFeatureFlags.library,    ...p.library },
        copilot:    { ...defaultFeatureFlags.copilot,    ...p.copilot },
        testing:    { ...defaultFeatureFlags.testing,    ...p.testing },
        reporting:  { ...defaultFeatureFlags.reporting,  ...p.reporting },
        skills:     { ...defaultFeatureFlags.skills,     ...p.skills },
        agents: {
          enabled:    p.agents?.enabled    ?? defaultFeatureFlags.agents.enabled,
          phases:     p.agents?.phases     ?? defaultFeatureFlags.agents.phases,
          skills:     p.agents?.skills     ?? defaultFeatureFlags.agents.skills,
          mcpClients: p.agents?.mcpClients ?? defaultFeatureFlags.agents.mcpClients,
          catalog: {
            enabled:   p.agents?.catalog?.enabled   ?? defaultFeatureFlags.agents.catalog.enabled,
            creator:   p.agents?.catalog?.creator   ?? defaultFeatureFlags.agents.catalog.creator,
            installed: p.agents?.catalog?.installed ?? defaultFeatureFlags.agents.catalog.installed,
            explorer:  p.agents?.catalog?.explorer  ?? defaultFeatureFlags.agents.catalog.explorer,
          },
        },
        other: {
          users: p.other?.users ?? defaultFeatureFlags.other.users,
        },
        user:    { ...defaultFeatureFlags.user,    ...p.user },
        navbar:  { ...defaultFeatureFlags.navbar,  ...p.navbar },
      };
    }
  } catch (error) {
    console.error('Error loading feature flags from localStorage:', error);
  }

  // Fall back to defaults
  return defaultFeatureFlags;
};

// Helper to save feature flags to localStorage
export const saveFeatureFlags = (flags: FeatureFlags): void => {
  try {
    localStorage.setItem('featureFlags', JSON.stringify(flags));
  } catch (error) {
    console.error('Error saving feature flags to localStorage:', error);
  }
};
