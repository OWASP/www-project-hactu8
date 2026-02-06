// src/config/featureFlags.ts

export interface FeatureFlags {
  // Sidebar Navigation Items
  navigation: {
    dashboard: boolean;
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
  other: {
    workbench: boolean;
    agents: boolean;
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
  other: {
    workbench: true,
    agents: true,
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

// Helper to load feature flags from localStorage or environment
export const loadFeatureFlags = (): FeatureFlags => {
  try {
    // Try to load from localStorage first
    const stored = localStorage.getItem('featureFlags');
    if (stored) {
      const parsed = JSON.parse(stored);
      //  Merge with defaults to ensure all flags exist
      return {
        ...defaultFeatureFlags,
        ...parsed,
        navigation: { ...defaultFeatureFlags.navigation, ...parsed.navigation },
        library: { ...defaultFeatureFlags.library, ...parsed.library },
        copilot: { ...defaultFeatureFlags.copilot, ...parsed.copilot },
        monitoring: { ...defaultFeatureFlags.monitoring, ...parsed.monitoring },
        projects: { ...defaultFeatureFlags.projects, ...parsed.projects },
        testing: { ...defaultFeatureFlags.testing, ...parsed.testing },
        reporting: { ...defaultFeatureFlags.reporting, ...parsed.reporting },
        other: { ...defaultFeatureFlags.other, ...parsed.other },
        user: { ...defaultFeatureFlags.user, ...parsed.user },
        navbar: { ...defaultFeatureFlags.navbar, ...parsed.navbar },
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
