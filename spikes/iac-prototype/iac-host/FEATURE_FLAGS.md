# Feature Flags Configuration

This document describes the feature flag system implemented in the IAC Host application.

## Overview

The feature flag system allows you to enable or disable specific features throughout the application. All navigation sidebar items and navbar functions are controlled by feature flags.

## Architecture

The feature flag system consists of:

1. **Configuration** (`src/config/featureFlags.ts`)
   - Defines the `FeatureFlags` interface
   - Provides default feature flag values
   - Helper functions for loading/saving flags

2. **Context Provider** (`src/contexts/FeatureFlagContext.tsx`)
   - React context for managing feature flags globally
   - Provides hooks for accessing and updating flags
   - Persists flags to localStorage

3. **UI Integration**
   - Sidebar navigation items filtered by flags
   - Navbar features controlled by flags
   - Settings page for managing flags

## Feature Flag Categories

### Navigation
- `dashboard` - Dashboard page
- `registry` - Registry page
- `console` - Console page

### Monitoring
- `logs` - Logs page
- `events` - Events page

### Projects
- `enabled` - Enable/disable entire projects section

### Testing Tools
- `promptInjection` - Prompt Injection Tester
- `trainingLeak` - Training Data Leak Detector
- `misbehaviorMonitor` - Model Misbehavior Monitor
- `overrelianceRisk` - Overreliance Risk Analyzer
- `agencyValidator` - Excessive Agency Validator
- `insecureOutput` - Insecure Output Filter
- `supplyChain` - Supply Chain Trust Checker
- `modelIdentity` - Model Identity & Version Tracker
- `authContextAudit` - Authorization & Context Audit
- `privacyCompliance` - Model Privacy Compliance Scanner

### Reporting
- `assuranceResults` - Assurance Results page
- `reports` - Reports page

### Other Features
- `workbench` - Workbench page
- `agents` - Agents page
- `users` - Users & Access page

### User Menu
- `extensions` - Extensions page
- `profile` - Profile page
- `settings` - Settings page

### Navigation Bar
- `createNewResource` - "Create New Resource" button

## Usage

### Accessing Feature Flags in Components

```typescript
import { useFeatureFlags } from '../contexts/FeatureFlagContext';

function MyComponent() {
  const { flags, isEnabled } = useFeatureFlags();

  // Check if a feature is enabled
  if (flags.navigation.dashboard) {
    // Render dashboard-related UI
  }

  // Or use the helper function
  if (isEnabled('testing', 'promptInjection')) {
    // Render prompt injection UI
  }
}
```

### Updating Feature Flags Programmatically

```typescript
import { useFeatureFlags } from '../contexts/FeatureFlagContext';

function MyComponent() {
  const { updateFlags } = useFeatureFlags();

  const disablePromptInjection = () => {
    updateFlags({
      testing: {
        promptInjection: false,
      },
    });
  };
}
```

### Managing Flags via UI

Users can manage feature flags through the Settings page:
1. Navigate to Settings (sidebar)
2. Select "Feature Flags" section
3. Toggle individual features on/off
4. Click "Reset to Defaults" to restore default configuration

## Persistence

Feature flags are automatically saved to browser localStorage and persist across sessions. The key used is `featureFlags`.

## Default Configuration

By default, all features are enabled. You can modify the defaults in `src/config/featureFlags.ts` by editing the `defaultFeatureFlags` object.

## Adding New Feature Flags

To add a new feature flag:

1. Update the `FeatureFlags` interface in `src/config/featureFlags.ts`:
```typescript
export interface FeatureFlags {
  // ... existing categories
  myNewCategory: {
    myNewFeature: boolean;
  };
}
```

2. Add the default value:
```typescript
export const defaultFeatureFlags: FeatureFlags = {
  // ... existing defaults
  myNewCategory: {
    myNewFeature: true,
  },
};
```

3. Update the `loadFeatureFlags` function to include the new category in the merge logic.

4. Use the flag in your components:
```typescript
const { flags } = useFeatureFlags();
if (flags.myNewCategory.myNewFeature) {
  // Render feature
}
```

## Testing

To test feature flags:

1. Open the application
2. Navigate to Settings > Feature Flags
3. Toggle features on/off
4. Verify that UI elements appear/disappear accordingly
5. Refresh the page to verify persistence

## Notes

- Feature flags are client-side only and stored in localStorage
- Disabling a feature hides it from the UI but doesn't prevent direct URL access
- Consider implementing server-side feature flags for production environments
- The Settings page itself is controlled by the `user.settings` flag
