// src/data/cannedProjects.tsx
//
// "Canned" starter Projects: each of the 10 original point-solution Testing
// pages, reframed as a pre-scoped Project template.
//
// This is the single source of truth for canned-project metadata. Both the
// Sidebar (nav item generation) and Project.tsx (the framed Project view)
// read from this list, so adding/renaming/reordering a starter Project only
// requires touching this file.
//
// Each entry still points at the real, standalone tester page component and
// route — those pages are untouched and keep working on their own routes
// (e.g. /prompt-injection). The canned Project view at /projects/:id simply
// mounts the same component inside a Project-style frame.
import React from 'react';
import type { FeatureFlags } from '../config/featureFlags';

import PromptInjection from '../pages/PromptInjection';
import TrainingLeak from '../pages/TrainingLeak';
import MisbehaviorMonitor from '../pages/MisbehaviorMonitor';
import OverrelianceRisk from '../pages/OverrelianceRisk';
import AgencyValidator from '../pages/AgencyValidator';
import InsecureOutput from '../pages/InsecureOutput';
import SupplyChain from '../pages/SupplyChain';
import ModelIdentity from '../pages/ModelIdentity';
import AuthContextAudit from '../pages/AuthContextAudit';
import PrivacyCompliance from '../pages/PrivacyCompliance';

// Key into FeatureFlags['testing'] that gates this starter Project.
export type TestingFlagKey = keyof FeatureFlags['testing'];

export interface CannedProjectDef {
  /** Used as the :projectId route param, e.g. /projects/test-prompt-injection */
  id: string;
  /** Feature flag (flags.testing[flagKey]) that gates visibility of this starter Project. */
  flagKey: TestingFlagKey;
  /** Display name — matches the original standalone page/sidebar label. */
  name: string;
  /** One-line summary of what the starter Project tests. */
  description: string;
  /** Loose grouping label shown in the Project's Overview tab. */
  category: string;
  /** The original standalone route — still mounted in App.tsx and fully functional on its own. */
  route: string;
  /** The real tester page component; rendered as-is inside the Project frame's "Run" tab. */
  Component: React.ComponentType;
}

export const cannedProjects: CannedProjectDef[] = [
  {
    id: 'test-prompt-injection',
    flagKey: 'promptInjection',
    name: 'Prompt Injection Tester',
    description: 'Probe the target for direct and indirect prompt injection vulnerabilities.',
    category: 'Prompt Security',
    route: '/prompt-injection',
    Component: PromptInjection,
  },
  {
    id: 'test-training-leak',
    flagKey: 'trainingLeak',
    name: 'Training Data Leak Detector',
    description: 'Check whether the model exposes memorized training data or secrets.',
    category: 'Data Privacy',
    route: '/training-leak',
    Component: TrainingLeak,
  },
  {
    id: 'test-misbehavior-monitor',
    flagKey: 'misbehaviorMonitor',
    name: 'Model Misbehavior Monitor',
    description: 'Watch for unexpected or unsafe model behavior over the course of a session.',
    category: 'Model Behavior',
    route: '/misbehavior-monitor',
    Component: MisbehaviorMonitor,
  },
  {
    id: 'test-overreliance-risk',
    flagKey: 'overrelianceRisk',
    name: 'Overreliance Risk Analyzer',
    description: 'Assess how much users may over-trust model output without independent verification.',
    category: 'Model Behavior',
    route: '/overreliance-risk',
    Component: OverrelianceRisk,
  },
  {
    id: 'test-agency-validator',
    flagKey: 'agencyValidator',
    name: 'Excessive Agency Validator',
    description: 'Validate that agentic actions stay within their intended permissions and scope.',
    category: 'Agency & Autonomy',
    route: '/agency-validator',
    Component: AgencyValidator,
  },
  {
    id: 'test-insecure-output',
    flagKey: 'insecureOutput',
    name: 'Insecure Output Filter',
    description: 'Test downstream handling of model output for injection- and XSS-style risks.',
    category: 'Output Safety',
    route: '/insecure-output',
    Component: InsecureOutput,
  },
  {
    id: 'test-supply-chain',
    flagKey: 'supplyChain',
    name: 'Supply Chain Trust Checker',
    description: 'Audit model, plugin, and dependency provenance for supply chain risk.',
    category: 'Supply Chain',
    route: '/supply-chain',
    Component: SupplyChain,
  },
  {
    id: 'test-model-identity',
    flagKey: 'modelIdentity',
    name: 'Model Identity & Version Tracker',
    description: 'Track and verify which model and version is actually serving requests.',
    category: 'Model Governance',
    route: '/model-identity',
    Component: ModelIdentity,
  },
  {
    id: 'test-auth-context-audit',
    flagKey: 'authContextAudit',
    name: 'Authorization & Context Audit',
    description: 'Audit authorization boundaries and context handling across requests.',
    category: 'Identity & Access',
    route: '/auth-context-audit',
    Component: AuthContextAudit,
  },
  {
    id: 'test-privacy-compliance',
    flagKey: 'privacyCompliance',
    name: 'Model Privacy Compliance Scanner',
    description: 'Scan model interactions for privacy and regulatory compliance issues.',
    category: 'Compliance',
    route: '/privacy-compliance',
    Component: PrivacyCompliance,
  },
];

export function getCannedProject(id: string): CannedProjectDef | undefined {
  return cannedProjects.find((p) => p.id === id);
}
