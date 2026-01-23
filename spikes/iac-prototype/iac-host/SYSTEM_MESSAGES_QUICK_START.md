# System Messages Quick Start

## What Are System Messages?

System messages appear in the Navigation Bar to provide users with real-time feedback, notifications, and status updates.

## Quick Setup

The system is already integrated! Just import and use the hook:

```typescript
import { useSystemMessage } from '../contexts/SystemMessageContext';
```

## 5-Minute Tutorial

### Step 1: Import the Hook

```typescript
import { useSystemMessage } from '../contexts/SystemMessageContext';

function MyComponent() {
  const { showSuccess } = useSystemMessage();
  // ...
}
```

### Step 2: Show a Message

```typescript
const handleClick = () => {
  showSuccess('Action completed!');
};
```

That's it! The message appears in the Navigation Bar and auto-dismisses after 5 seconds.

## Common Use Cases

### 1. Form Submission
```typescript
const handleSubmit = async (data) => {
  try {
    await saveData(data);
    showSuccess('Saved successfully');
  } catch (error) {
    showError('Failed to save');
  }
};
```

### 2. Loading State
```typescript
const loadData = async () => {
  showInfo('Loading...', 0); // 0 = don't auto-dismiss
  await fetchData();
  clearMessage();
};
```

### 3. Warning User
```typescript
const deleteItem = () => {
  showWarning('This action cannot be undone', 10000); // Show for 10 seconds
  // ... proceed with deletion
};
```

### 4. Quick Feedback
```typescript
const copyToClipboard = (text) => {
  navigator.clipboard.writeText(text);
  showSuccess('Copied!', 2000); // Auto-dismiss in 2 seconds
};
```

## All Available Methods

```typescript
const {
  showInfo,      // Blue - general info
  showWarning,   // Yellow - cautions
  showError,     // Red - errors
  showSuccess,   // Green - success
  clearMessage,  // Remove message
} = useSystemMessage();
```

## Duration Guide

```typescript
// Auto-dismiss after 3 seconds
showInfo('Quick message', 3000);

// Use default duration (5s for info/success, 8s for warning, 10s for error)
showInfo('Standard message');

// Persist until manually cleared
showWarning('Important notice', 0);
```

## Try It Now

1. Navigate to any page in the app
2. Add this code to a component:

```typescript
import { useSystemMessage } from '../contexts/SystemMessageContext';

function TestButton() {
  const { showSuccess } = useSystemMessage();

  return (
    <button onClick={() => showSuccess('It works!')}>
      Test System Message
    </button>
  );
}
```

3. Click the button and watch the Navigation Bar!

## Live Examples

To see all examples in action:
1. Import the example component
2. Add it to your route

```typescript
import SystemMessageExample from './examples/SystemMessageExample';

// In your routes
<Route path="/examples/system-messages" element={<SystemMessageExample />} />
```

## Best Practices

✅ **DO**
- Use appropriate message types (info, warning, error, success)
- Keep messages short and clear
- Let transient messages auto-dismiss
- Clear loading messages when done

❌ **DON'T**
- Show multiple messages rapidly
- Use long, complex messages
- Forget to clear persistent messages
- Use wrong message type for severity

## Troubleshooting

### Message not appearing?
- Check that `SystemMessageProvider` wraps your app (already done in App.tsx)
- Verify you're using the hook inside a component, not at module level

### Message disappears too quickly?
- Increase duration: `showInfo('Message', 10000)` for 10 seconds
- Or make persistent: `showInfo('Message', 0)`

### Message won't clear?
- Use `clearMessage()` to manually remove any message

## Next Steps

- Read full documentation: `SYSTEM_MESSAGES.md`
- View code examples: `src/examples/SystemMessageExample.tsx`
- Explore message types and styling options
