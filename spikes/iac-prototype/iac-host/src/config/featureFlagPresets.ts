// src/config/featureFlagPresets.ts
import type { FeatureFlags } from './featureFlags';

/**
 * Predefined feature flag presets for different use cases
 */

// Full access - all features enabled (default)
export const fullAccessPreset: FeatureFlags = {
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
    enabled: false,
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

// Minimal - only essential features
export const minimalPreset: FeatureFlags = {
  navigation: {
    dashboard: true,
    registry: false,
    console: false,
  },
  monitoring: {
    logs: false,
    events: false,
  },
  projects: {
    enabled: false,
  },
  library: {
    enabled: false,
    articles: false,
    projectDocs: false,
    owaspAI: false,
    references: false,
  },
  copilot: {
    enabled: true,
    assistMode: true,
    owaspDocs: true,
    projectDocs: true,
    defaultExpanded: false,
  },
  testing: {
    promptInjection: false,
    trainingLeak: false,
    misbehaviorMonitor: false,
    overrelianceRisk: false,
    agencyValidator: false,
    insecureOutput: false,
    supplyChain: false,
    modelIdentity: false,
    authContextAudit: false,
    privacyCompliance: false,
  },
  reporting: {
    assuranceResults: false,
    reports: false,
  },
  other: {
    workbench: false,
    agents: false,
    users: false,
  },
  user: {
    extensions: false,
    profile: true,
    settings: true,
  },
  navbar: {
    createNewResource: false,
  },
};

// Testing focus - only testing and monitoring features
export const testingFocusPreset: FeatureFlags = {
  navigation: {
    dashboard: true,
    registry: false,
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
    enabled: false,
    articles: false,
    projectDocs: false,
    owaspAI: false,
    references: false,
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
    workbench: false,
    agents: false,
    users: false,
  },
  user: {
    extensions: false,
    profile: true,
    settings: true,
  },
  navbar: {
    createNewResource: true,
  },
};

// Developer mode - focus on development tools
export const developerPreset: FeatureFlags = {
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
    enabled: false,
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
    promptInjection: false,
    trainingLeak: false,
    misbehaviorMonitor: false,
    overrelianceRisk: false,
    agencyValidator: false,
    insecureOutput: false,
    supplyChain: false,
    modelIdentity: false,
    authContextAudit: false,
    privacyCompliance: false,
  },
  reporting: {
    assuranceResults: false,
    reports: false,
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

// Security focus - only security-related features
export const securityFocusPreset: FeatureFlags = {
  navigation: {
    dashboard: true,
    registry: true,
    console: false,
  },
  monitoring: {
    logs: true,
    events: true,
  },
  projects: {
    enabled: false,
  },
  library: {
    enabled: false,
    articles: false,
    projectDocs: false,
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
    workbench: false,
    agents: false,
    users: true,
  },
  user: {
    extensions: false,
    profile: true,
    settings: true,
  },
  navbar: {
    createNewResource: false,
  },
};

export const presets = {
  full: fullAccessPreset,
  minimal: minimalPreset,
  testing: testingFocusPreset,
  developer: developerPreset,
  security: securityFocusPreset,
};

export type PresetName = keyof typeof presets;

export const presetDescriptions: Record<PresetName, string> = {
  full: 'All features enabled',
  minimal: 'Only essential features',
  testing: 'Testing and monitoring tools',
  developer: 'Development and management tools',
  security: 'Security testing and auditing tools',
};
