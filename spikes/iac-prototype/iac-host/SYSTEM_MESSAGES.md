# System Messages Documentation

## Overview

The Navigation Bar supports displaying system messages to provide users with important information, notifications, and status updates.

## Features

- **Multiple message types**: info, warning, error, success
- **Auto-dismiss**: Messages can auto-clear after a specified duration
- **Persistent messages**: Set duration to 0 to keep message visible
- **Global access**: Use system messages from any component
- **Color-coded**: Visual indicators for different message types

## Usage

### In Components

```typescript
import { useSystemMessage } from '../contexts/SystemMessageContext';

function MyComponent() {
  const { showInfo, showWarning, showError, showSuccess, clearMessage } = useSystemMessage();

  const handleAction = () => {
    // Show an info message (auto-clears in 5 seconds)
    showInfo('Processing your request...');

    // Show a warning (auto-clears in 8 seconds)
    showWarning('This action may take a while');

    // Show an error (auto-clears in 10 seconds)
    showError('Failed to process request');

    // Show success (auto-clears in 5 seconds)
    showSuccess('Operation completed successfully');

    // Manually clear any message
    clearMessage();
  };
}
```

### Custom Duration

```typescript
// Auto-clear after 3 seconds
showInfo('Quick notification', 3000);

// Persist until manually cleared (duration = 0)
showWarning('Important: Read this carefully', 0);

// Clear a persistent message later
setTimeout(() => clearMessage(), 10000);
```

### Advanced Usage

```typescript
const { setMessage } = useSystemMessage();

// Full control over message
setMessage('Custom message', 'info', 5000);
```

## Message Types

### Info (Blue)
- Default message type
- Use for: General information, status updates
- Auto-clear: 5 seconds (default)
- Color: Blue background with dark blue text

```typescript
showInfo('System initialized successfully');
```

### Warning (Yellow)
- Use for: Caution, non-critical issues
- Auto-clear: 8 seconds (default)
- Color: Yellow background with dark orange text

```typescript
showWarning('Network connection unstable');
```

### Error (Red)
- Use for: Errors, failures, critical issues
- Auto-clear: 10 seconds (default)
- Color: Red background with dark red text

```typescript
showError('Failed to save changes');
```

### Success (Green)
- Use for: Successful operations, confirmations
- Auto-clear: 5 seconds (default)
- Color: Green background with dark green text

```typescript
showSuccess('Settings saved successfully');
```

## Examples

### Example 1: Form Submission
```typescript
function FormComponent() {
  const { showSuccess, showError } = useSystemMessage();

  const handleSubmit = async (data) => {
    try {
      await saveData(data);
      showSuccess('Form submitted successfully');
    } catch (error) {
      showError('Failed to submit form. Please try again.');
    }
  };
}
```

### Example 2: Loading State
```typescript
function DataLoader() {
  const { showInfo, clearMessage } = useSystemMessage();

  const loadData = async () => {
    showInfo('Loading data...', 0); // Persistent
    try {
      await fetchData();
      clearMessage();
    } catch (error) {
      // Error message will replace loading message
      showError('Failed to load data');
    }
  };
}
```

### Example 3: Feature Toggle Feedback
```typescript
function FeatureToggle() {
  const { showSuccess, showWarning } = useSystemMessage();
  const { updateFlags } = useFeatureFlags();

  const toggleFeature = (feature: string, enabled: boolean) => {
    updateFlags({ testing: { [feature]: enabled } });

    if (enabled) {
      showSuccess(`${feature} enabled`);
    } else {
      showWarning(`${feature} disabled`);
    }
  };
}
```

### Example 4: Session Timeout Warning
```typescript
function SessionMonitor() {
  const { showWarning, showError } = useSystemMessage();

  useEffect(() => {
    // Warn 5 minutes before timeout
    const warningTimer = setTimeout(() => {
      showWarning('Session expires in 5 minutes', 0);
    }, 25 * 60 * 1000);

    // Show error on timeout
    const timeoutTimer = setTimeout(() => {
      showError('Session expired. Please log in again.');
    }, 30 * 60 * 1000);

    return () => {
      clearTimeout(warningTimer);
      clearTimeout(timeoutTimer);
    };
  }, []);
}
```

## API Reference

### useSystemMessage Hook

Returns an object with the following properties and methods:

| Property/Method | Type | Description |
|----------------|------|-------------|
| `message` | `string` | Current message text |
| `messageType` | `'info' \| 'warning' \| 'error' \| 'success'` | Current message type |
| `setMessage` | `(text: string, type?: MessageType, duration?: number) => void` | Set a message with full control |
| `clearMessage` | `() => void` | Clear the current message |
| `showInfo` | `(text: string, duration?: number) => void` | Show info message (default: 5s) |
| `showWarning` | `(text: string, duration?: number) => void` | Show warning message (default: 8s) |
| `showError` | `(text: string, duration?: number) => void` | Show error message (default: 10s) |
| `showSuccess` | `(text: string, duration?: number) => void` | Show success message (default: 5s) |

### Default Auto-Clear Durations

- **Info**: 5,000ms (5 seconds)
- **Warning**: 8,000ms (8 seconds)
- **Error**: 10,000ms (10 seconds)
- **Success**: 5,000ms (5 seconds)
- **Persistent**: Set duration to `0` to disable auto-clear

## Best Practices

1. **Keep messages concise**: Navigation bar has limited space
2. **Use appropriate types**: Match severity to message type
3. **Auto-clear transient messages**: Let temporary messages disappear automatically
4. **Persist critical messages**: Use duration=0 for important messages
5. **Clear before setting**: New messages automatically replace old ones
6. **Avoid message spam**: Don't show too many messages in quick succession
7. **Provide context**: Messages should be clear without requiring additional explanation

## Styling

Messages are color-coded for quick recognition:

- **Info**: `#dbeafe` background, `#1e40af` text, `#60a5fa` border
- **Warning**: `#fef3c7` background, `#92400e` text, `#fbbf24` border
- **Error**: `#fee2e2` background, `#991b1b` text, `#f87171` border
- **Success**: `#d1fae5` background, `#065f46` text, `#34d399` border

## Integration with Feature Flags

System messages work seamlessly with feature flags. The Navigation Bar itself can be hidden via feature flags, which will also hide system messages.

```typescript
// In feature flags config
navbar: {
  createNewResource: true, // Controls "Create New Resource" button
}
```

When the navbar is hidden, system messages won't be visible. Consider using alternative notification methods (modals, toasts) if you need persistent notifications when the navbar is hidden.
