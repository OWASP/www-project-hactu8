# Environment Configuration

## Overview

The application automatically detects and displays the current environment with visual indicators in the Navigation Bar. This helps users immediately identify which environment they're working in (development, test, staging, or production).

## Features

- **Auto-Detection**: Automatically detects environment based on hostname or environment variables
- **Visual Indicators**: Color-coded navbar for quick environment identification
- **Default Messages**: Shows environment-specific messages on load
- **Manual Override**: Override detected environment for testing/demos
- **Configurable**: Easily customize messages and colors per environment

## Environment Colors

| Environment | Navbar Color | Text Color | Message Type |
|-------------|--------------|------------|--------------|
| **Local** | Light Blue | Dark Blue | Info |
| **Development** | Light Green | Dark Green | Success |
| **Test** | Light Yellow | Dark Orange | Warning |
| **Staging** | Light Orange | Dark Orange | Warning |
| **Production** | Light Red | Dark Red | Error |

## Visual Examples

- **Local**: Blue navbar with "Running on Local Machine"
- **Development**: Green navbar with "Running in Development Environment"
- **Test**: Yellow navbar with "Running in Test Environment"
- **Staging**: Orange navbar with "Running in Staging Environment - Use with caution"
- **Production**: Red navbar with "Production Environment"

## Environment Detection

The system detects environments in this order:

1. **Environment Override** (localStorage) - Manual override for testing
2. **Environment Variable** - `VITE_APP_ENV`
3. **Hostname Detection**:
   - `localhost` or `127.0.0.1` → **local**
   - `dev.` or `-dev.` in hostname → **development**
   - `test.` or `-test.` in hostname → **test**
   - `staging.` or `-staging.` in hostname → **staging**
   - `prod.` or `-prod.` in hostname → **production**
4. **Build Mode** - Falls back to `local` for dev builds, `production` for prod builds

## Configuration File

All environment configurations are defined in `src/config/environmentConfig.ts`:

```typescript
export const environmentConfigs: Record<Environment, EnvironmentConfig> = {
  development: {
    name: 'development',
    displayName: 'Development',
    message: 'Running in Development Environment',
    messageType: 'success',
    navbarColor: '#d1fae5',       // Light green
    navbarTextColor: '#065f46',   // Dark green
    showOnLoad: true,
  },
  // ... other environments
};
```

## Customizing Environments

### Change Default Message

Edit `src/config/environmentConfig.ts`:

```typescript
development: {
  // ...
  message: 'DEV - All features enabled',
  // ...
}
```

### Change Colors

```typescript
test: {
  // ...
  navbarColor: '#fef3c7',       // Light yellow
  navbarTextColor: '#92400e',   // Dark orange
  // ...
}
```

### Disable Message on Load

```typescript
production: {
  // ...
  showOnLoad: false,  // Don't show environment message
  // ...
}
```

### Add New Environment

```typescript
export const environmentConfigs = {
  // ... existing environments
  demo: {
    name: 'demo',
    displayName: 'Demo',
    message: 'Demo Environment - Sample Data Only',
    messageType: 'info',
    navbarColor: '#e0e7ff',
    navbarTextColor: '#3730a3',
    showOnLoad: true,
  },
};
```

## Using Environment Variables

Set the environment via `.env` file:

```bash
# .env.development
VITE_APP_ENV=development

# .env.test
VITE_APP_ENV=test

# .env.staging
VITE_APP_ENV=staging

# .env.production
VITE_APP_ENV=production
```

## Manual Override (Testing/Demos)

Use browser console to override environment:

```javascript
// Override to test environment
import { setEnvironmentOverride } from './config/environmentConfig';
setEnvironmentOverride('test');

// Check current environment
import { getEffectiveEnvironment } from './config/environmentConfig';
console.log(getEffectiveEnvironment());

// Clear override
import { clearEnvironmentOverride } from './config/environmentConfig';
clearEnvironmentOverride();
```

Or use localStorage directly:

```javascript
// Set override
localStorage.setItem('environmentOverride', 'staging');
location.reload();

// Clear override
localStorage.removeItem('environmentOverride');
location.reload();
```

## Programmatic Access

### Get Current Environment

```typescript
import { getEffectiveEnvironment, getEffectiveConfig } from '../config/environmentConfig';

function MyComponent() {
  const env = getEffectiveEnvironment(); // 'development' | 'test' | etc.
  const config = getEffectiveConfig();

  console.log(`Running in ${config.displayName}`);
  console.log(`Message: ${config.message}`);
}
```

### Check Specific Environment

```typescript
import { getEffectiveEnvironment } from '../config/environmentConfig';

const isProduction = getEffectiveEnvironment() === 'production';

if (isProduction) {
  // Production-only logic
}
```

### Conditional Features

```typescript
import { getEffectiveEnvironment } from '../config/environmentConfig';

function DebugPanel() {
  const env = getEffectiveEnvironment();

  // Only show in non-production
  if (env === 'production') {
    return null;
  }

  return <div>Debug Info...</div>;
}
```

## Integration with System Messages

Environment messages are shown on load and persist until cleared:

```typescript
import { useSystemMessage } from '../contexts/SystemMessageContext';

function MyComponent() {
  const { clearMessage, showInfo } = useSystemMessage();

  // Clear environment message
  const handleStart = () => {
    clearMessage();
    showInfo('Starting workflow...');
  };
}
```

## Best Practices

1. **Production Safety**: Keep production navbar red to prevent accidental actions
2. **Consistent Colors**: Use the default color scheme for familiarity
3. **Clear Messages**: Keep environment messages concise and descriptive
4. **Override Sparingly**: Only override for testing/demos, not regular development
5. **Document Changes**: Document any custom environment configurations

## Troubleshooting

### Wrong environment detected?
1. Check `VITE_APP_ENV` environment variable
2. Check hostname matches expected pattern
3. Check for localStorage override: `localStorage.getItem('environmentOverride')`

### Environment message not showing?
1. Verify `showOnLoad: true` in config
2. Check SystemMessageContext is properly set up
3. Ensure app is wrapped with SystemMessageProvider

### Colors not applying?
1. Verify Navbar component receives backgroundColor and textColor props
2. Check config values are valid CSS colors
3. Clear browser cache

### Override not working?
1. Ensure you reload the page after setting override
2. Check localStorage value is valid environment name
3. Try clearing override and setting again

## Security Considerations

- Environment detection is client-side and can be manipulated
- Don't rely on environment detection for security decisions
- Always validate on the server side for critical operations
- Production environment should still enforce authentication/authorization

## Future Enhancements

Potential improvements:
1. Server-side environment detection
2. Environment-specific feature flags
3. Environment switching UI in settings
4. Environment history/logging
5. API endpoint configuration per environment
6. Environment-specific themes
7. Deployment environment metadata
8. Environment health checks
