# Environment Configuration - Quick Reference

## At a Glance

When you load the application, the Navigation Bar will be color-coded to show which environment you're in:

| Environment | Navbar Color | Default Message |
|-------------|--------------|-----------------|
| **Local** | 🔵 Blue | "Running on Local Machine" |
| **Development** | 🟢 Green | "Running in Development Environment" |
| **Test** | 🟡 Yellow | "Running in Test Environment" |
| **Staging** | 🟠 Orange | "Running in Staging Environment - Use with caution" |
| **Production** | 🔴 Red | "Production Environment" |

## How It Works

The app automatically detects your environment from:
1. Environment variable `VITE_APP_ENV`
2. URL hostname (e.g., `dev.example.com` → development)
3. Build mode (local for dev, production for prod builds)

## Quick Setup

### Set Environment via .env File

Create a `.env.local` file:
```bash
VITE_APP_ENV=development
```

Restart your dev server:
```bash
npm run dev
```

The navbar will now be GREEN with "Running in Development Environment"

### Other Environment Files

```bash
# .env.development
VITE_APP_ENV=development

# .env.test
VITE_APP_ENV=test

# .env.production
VITE_APP_ENV=production
```

## Testing Different Environments

### Option 1: Browser Console (Quick)

```javascript
// Test production look
localStorage.setItem('environmentOverride', 'production');
location.reload();
// Navbar turns RED

// Test staging look
localStorage.setItem('environmentOverride', 'staging');
location.reload();
// Navbar turns ORANGE

// Clear override
localStorage.removeItem('environmentOverride');
location.reload();
```

### Option 2: Change .env File

1. Edit `.env.local`
2. Change `VITE_APP_ENV=test`
3. Restart dev server
4. Navbar turns YELLOW

## Customizing Messages

Edit `src/config/environmentConfig.ts`:

```typescript
development: {
  message: 'DEV MODE - All features enabled',
  navbarColor: '#d1fae5',
  navbarTextColor: '#065f46',
}
```

## Common Tasks

### Hide environment message
```typescript
// In environmentConfig.ts
development: {
  showOnLoad: false,  // Don't show message
}
```

### Change production color
```typescript
// In environmentConfig.ts
production: {
  navbarColor: '#fee2e2',     // Your preferred color
  navbarTextColor: '#991b1b',
}
```

### Add custom environment
```typescript
// In environmentConfig.ts
demo: {
  name: 'demo',
  message: 'Demo Mode',
  navbarColor: '#e0e7ff',
  navbarTextColor: '#3730a3',
  showOnLoad: true,
}
```

## Troubleshooting

**Q: Navbar is wrong color?**
- Check `.env` file
- Check localStorage: `localStorage.getItem('environmentOverride')`
- Try clearing: `localStorage.removeItem('environmentOverride')`

**Q: Message not showing?**
- Check `showOnLoad: true` in config
- Message persists until you manually clear it

**Q: Want to clear environment message?**
```typescript
import { useSystemMessage } from '../contexts/SystemMessageContext';

const { clearMessage } = useSystemMessage();
clearMessage();
```

## Integration with Code

```typescript
import { getEffectiveEnvironment } from '../config/environmentConfig';

// Check environment
const isProd = getEffectiveEnvironment() === 'production';

// Conditional logic
if (!isProd) {
  console.log('Debug info...');
}
```

## Files

- **Config**: `src/config/environmentConfig.ts`
- **Context**: `src/contexts/SystemMessageContext.tsx`
- **Navbar**: `src/components/Navbar.tsx`
- **App**: `src/App.tsx`
- **Docs**: `ENVIRONMENT_CONFIGURATION.md`

## Color Codes Reference

```typescript
// Copy these for custom environments
Local:       { bg: '#dbeafe', text: '#1e40af' }
Development: { bg: '#d1fae5', text: '#065f46' }
Test:        { bg: '#fef3c7', text: '#92400e' }
Staging:     { bg: '#fed7aa', text: '#7c2d12' }
Production:  { bg: '#fee2e2', text: '#991b1b' }
```

## Tips

✅ **DO**
- Use production red color for prod environments
- Test different environments before deployment
- Document custom environment configurations

❌ **DON'T**
- Rely on client-side env detection for security
- Override environment in production
- Use similar colors for different environments
