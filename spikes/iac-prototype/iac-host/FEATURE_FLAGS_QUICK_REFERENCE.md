# Feature Flags Quick Reference

## How to Use

### Via UI (Recommended)
1. Open the application
2. Click **Settings** in the sidebar
3. Select **Feature Flags** section
4. Toggle features or choose a preset

### Programmatically
```typescript
import { useFeatureFlags } from './contexts/FeatureFlagContext';

const { flags, updateFlags, resetFlags, isEnabled } = useFeatureFlags();
```

## All Available Flags

| Category | Flag | Description |
|----------|------|-------------|
| **navigation** | dashboard | Dashboard page |
| | registry | Registry page |
| | console | Console page |
| **monitoring** | logs | Logs page |
| | events | Events page |
| **projects** | enabled | Projects section |
| **testing** | promptInjection | Prompt Injection Tester |
| | trainingLeak | Training Data Leak Detector |
| | misbehaviorMonitor | Model Misbehavior Monitor |
| | overrelianceRisk | Overreliance Risk Analyzer |
| | agencyValidator | Excessive Agency Validator |
| | insecureOutput | Insecure Output Filter |
| | supplyChain | Supply Chain Trust Checker |
| | modelIdentity | Model Identity & Version Tracker |
| | authContextAudit | Authorization & Context Audit |
| | privacyCompliance | Model Privacy Compliance Scanner |
| **reporting** | assuranceResults | Assurance Results page |
| | reports | Reports page |
| **other** | workbench | Workbench page |
| | agents | Agents page |
| | users | Users & Access page |
| **user** | extensions | Extensions page |
| | profile | Profile page |
| | settings | Settings page |
| **navbar** | createNewResource | "Create New Resource" button |

## Quick Presets

| Preset | Features Enabled |
|--------|-----------------|
| **Full** | All features (default) |
| **Minimal** | Dashboard, Profile, Settings only |
| **Testing** | Testing tools + Monitoring + Projects |
| **Developer** | Development tools + Management |
| **Security** | Security testing + Auditing |

## Code Examples

### Check if feature is enabled
```typescript
// Method 1: Direct access
if (flags.navigation.dashboard) {
  // Render dashboard
}

// Method 2: Helper function
if (isEnabled('testing', 'promptInjection')) {
  // Render prompt injection tool
}
```

### Enable/disable a feature
```typescript
updateFlags({
  testing: { promptInjection: false }
});
```

### Enable multiple features
```typescript
updateFlags({
  testing: {
    promptInjection: true,
    trainingLeak: true,
  }
});
```

### Load a preset
```typescript
import { presets } from './config/featureFlagPresets';

updateFlags(presets.minimal);
```

### Reset to defaults
```typescript
resetFlags();
```

## localStorage

Feature flags are stored at: `localStorage.featureFlags`

### View current flags
```javascript
// In browser console
console.log(JSON.parse(localStorage.getItem('featureFlags')));
```

### Clear all flags
```javascript
// In browser console
localStorage.removeItem('featureFlags');
// Then refresh the page
```

## Default State

All flags default to `true` (enabled).

## Common Tasks

### Hide all testing tools
Settings > Feature Flags > Testing Tools > Uncheck all

### Show only dashboard
Settings > Feature Flags > Click "Minimal" preset

### Enable everything
Settings > Feature Flags > Click "Reset to Defaults" or "Full" preset

### Custom configuration
1. Load a preset close to what you want
2. Manually toggle individual features
3. Changes auto-save to localStorage

## Files to Know

| File | Purpose |
|------|---------|
| `src/config/featureFlags.ts` | Main config & defaults |
| `src/config/featureFlagPresets.ts` | Preset configurations |
| `src/contexts/FeatureFlagContext.tsx` | React context & hooks |
| `src/pages/Settings.tsx` | UI for managing flags |
| `FEATURE_FLAGS.md` | Full documentation |

## Tips

- Changes take effect immediately
- Flags persist across browser sessions
- Each browser has independent settings
- Incognito mode won't save flags
- Export/import not yet supported (copy localStorage value manually)
