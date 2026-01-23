// src/examples/FeatureFlagExample.tsx
// This is an example component showing how to use feature flags

import React from 'react';
import { useFeatureFlags } from '../contexts/FeatureFlagContext';

/**
 * Example 1: Conditional rendering based on feature flags
 */
export const ConditionalRenderExample: React.FC = () => {
  const { flags } = useFeatureFlags();

  return (
    <div>
      <h2>Available Features</h2>

      {/* Only render if dashboard is enabled */}
      {flags.navigation.dashboard && (
        <div>Dashboard is available!</div>
      )}

      {/* Only render if prompt injection testing is enabled */}
      {flags.testing.promptInjection && (
        <div>Prompt Injection Tester is available!</div>
      )}
    </div>
  );
};

/**
 * Example 2: Using the isEnabled helper function
 */
export const HelperFunctionExample: React.FC = () => {
  const { isEnabled } = useFeatureFlags();

  return (
    <div>
      <h2>Feature Status</h2>

      <ul>
        <li>
          Dashboard: {isEnabled('navigation', 'dashboard') ? 'Enabled' : 'Disabled'}
        </li>
        <li>
          Registry: {isEnabled('navigation', 'registry') ? 'Enabled' : 'Disabled'}
        </li>
        <li>
          Console: {isEnabled('navigation', 'console') ? 'Enabled' : 'Disabled'}
        </li>
      </ul>
    </div>
  );
};

/**
 * Example 3: Programmatically updating feature flags
 */
export const UpdateFlagsExample: React.FC = () => {
  const { flags, updateFlags } = useFeatureFlags();

  const enableAllTesting = () => {
    updateFlags({
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
    });
  };

  const disableAllTesting = () => {
    updateFlags({
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
    });
  };

  return (
    <div>
      <h2>Bulk Flag Management</h2>

      <div>
        <button onClick={enableAllTesting}>Enable All Testing Tools</button>
        <button onClick={disableAllTesting}>Disable All Testing Tools</button>
      </div>

      <div>
        <h3>Current Testing Flags Status:</h3>
        <pre>{JSON.stringify(flags.testing, null, 2)}</pre>
      </div>
    </div>
  );
};

/**
 * Example 4: Filtering arrays based on feature flags
 */
export const FilteredListExample: React.FC = () => {
  const { flags } = useFeatureFlags();

  const allNavigationItems = [
    { id: 'dashboard', label: 'Dashboard', enabled: flags.navigation.dashboard },
    { id: 'registry', label: 'Registry', enabled: flags.navigation.registry },
    { id: 'console', label: 'Console', enabled: flags.navigation.console },
  ];

  // Filter to only show enabled items
  const enabledItems = allNavigationItems.filter(item => item.enabled);

  return (
    <div>
      <h2>Enabled Navigation Items</h2>
      <ul>
        {enabledItems.map(item => (
          <li key={item.id}>{item.label}</li>
        ))}
      </ul>
    </div>
  );
};

/**
 * Example 5: Reset to defaults
 */
export const ResetExample: React.FC = () => {
  const { resetFlags } = useFeatureFlags();

  return (
    <div>
      <h2>Reset Configuration</h2>
      <button onClick={resetFlags}>
        Reset All Flags to Default Values
      </button>
    </div>
  );
};

/**
 * Example 6: Complete feature flag demo
 */
export const CompleteExample: React.FC = () => {
  return (
    <div style={{ padding: '2rem' }}>
      <h1>Feature Flags Examples</h1>

      <section style={{ marginBottom: '2rem' }}>
        <ConditionalRenderExample />
      </section>

      <section style={{ marginBottom: '2rem' }}>
        <HelperFunctionExample />
      </section>

      <section style={{ marginBottom: '2rem' }}>
        <UpdateFlagsExample />
      </section>

      <section style={{ marginBottom: '2rem' }}>
        <FilteredListExample />
      </section>

      <section style={{ marginBottom: '2rem' }}>
        <ResetExample />
      </section>
    </div>
  );
};

export default CompleteExample;
