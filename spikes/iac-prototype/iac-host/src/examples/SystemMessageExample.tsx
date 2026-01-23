// src/examples/SystemMessageExample.tsx
// Example component demonstrating system message usage

import React, { useEffect } from 'react';
import { useSystemMessage } from '../contexts/SystemMessageContext';

/**
 * Example 1: Basic message types
 */
export const BasicMessageExample: React.FC = () => {
  const { showInfo, showWarning, showError, showSuccess, clearMessage } = useSystemMessage();

  return (
    <div style={{ padding: '2rem' }}>
      <h2>Basic System Messages</h2>
      <div style={{ display: 'flex', gap: '1rem', marginTop: '1rem', flexWrap: 'wrap' }}>
        <button
          onClick={() => showInfo('This is an informational message')}
          style={{ padding: '0.5rem 1rem', background: '#3b82f6', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
        >
          Show Info
        </button>
        <button
          onClick={() => showWarning('This is a warning message')}
          style={{ padding: '0.5rem 1rem', background: '#f59e0b', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
        >
          Show Warning
        </button>
        <button
          onClick={() => showError('This is an error message')}
          style={{ padding: '0.5rem 1rem', background: '#ef4444', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
        >
          Show Error
        </button>
        <button
          onClick={() => showSuccess('This is a success message')}
          style={{ padding: '0.5rem 1rem', background: '#10b981', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
        >
          Show Success
        </button>
        <button
          onClick={() => clearMessage()}
          style={{ padding: '0.5rem 1rem', background: '#6b7280', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
        >
          Clear Message
        </button>
      </div>
    </div>
  );
};

/**
 * Example 2: Custom duration messages
 */
export const CustomDurationExample: React.FC = () => {
  const { showInfo, showWarning } = useSystemMessage();

  return (
    <div style={{ padding: '2rem' }}>
      <h2>Custom Duration Messages</h2>
      <div style={{ display: 'flex', gap: '1rem', marginTop: '1rem', flexWrap: 'wrap' }}>
        <button
          onClick={() => showInfo('Quick message (2 seconds)', 2000)}
          style={{ padding: '0.5rem 1rem', background: '#3b82f6', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
        >
          2 Second Message
        </button>
        <button
          onClick={() => showInfo('Standard message (5 seconds)')}
          style={{ padding: '0.5rem 1rem', background: '#3b82f6', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
        >
          5 Second Message
        </button>
        <button
          onClick={() => showWarning('Persistent message (must clear manually)', 0)}
          style={{ padding: '0.5rem 1rem', background: '#f59e0b', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
        >
          Persistent Message
        </button>
      </div>
    </div>
  );
};

/**
 * Example 3: Simulated async operation
 */
export const AsyncOperationExample: React.FC = () => {
  const { showInfo, showSuccess, showError, clearMessage } = useSystemMessage();

  const simulateOperation = async (shouldSucceed: boolean) => {
    // Show loading message
    showInfo('Processing request...', 0); // Persistent

    // Simulate async work
    await new Promise(resolve => setTimeout(resolve, 2000));

    if (shouldSucceed) {
      showSuccess('Operation completed successfully');
    } else {
      showError('Operation failed. Please try again.');
    }
  };

  return (
    <div style={{ padding: '2rem' }}>
      <h2>Async Operation Messages</h2>
      <div style={{ display: 'flex', gap: '1rem', marginTop: '1rem', flexWrap: 'wrap' }}>
        <button
          onClick={() => simulateOperation(true)}
          style={{ padding: '0.5rem 1rem', background: '#10b981', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
        >
          Simulate Success
        </button>
        <button
          onClick={() => simulateOperation(false)}
          style={{ padding: '0.5rem 1rem', background: '#ef4444', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
        >
          Simulate Failure
        </button>
        <button
          onClick={() => clearMessage()}
          style={{ padding: '0.5rem 1rem', background: '#6b7280', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
        >
          Cancel/Clear
        </button>
      </div>
    </div>
  );
};

/**
 * Example 4: Form validation feedback
 */
export const FormValidationExample: React.FC = () => {
  const { showError, showSuccess } = useSystemMessage();
  const [email, setEmail] = React.useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    // Simple email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!email) {
      showError('Email is required');
      return;
    }

    if (!emailRegex.test(email)) {
      showError('Please enter a valid email address');
      return;
    }

    showSuccess('Email saved successfully');
    setEmail('');
  };

  return (
    <div style={{ padding: '2rem' }}>
      <h2>Form Validation Messages</h2>
      <form onSubmit={handleSubmit} style={{ marginTop: '1rem' }}>
        <input
          type="text"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="Enter your email"
          style={{ padding: '0.5rem', borderRadius: '4px', border: '1px solid #d1d5db', marginRight: '0.5rem', minWidth: '250px' }}
        />
        <button
          type="submit"
          style={{ padding: '0.5rem 1rem', background: '#3b82f6', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
        >
          Validate & Submit
        </button>
      </form>
    </div>
  );
};

/**
 * Example 5: Auto-cycling messages
 */
export const AutoCyclingExample: React.FC = () => {
  const { showInfo } = useSystemMessage();
  const [isRunning, setIsRunning] = React.useState(false);

  useEffect(() => {
    if (!isRunning) return;

    const messages = [
      'Checking system status...',
      'Verifying connections...',
      'Running diagnostics...',
      'Optimizing performance...',
      'All systems operational',
    ];

    let index = 0;
    const interval = setInterval(() => {
      showInfo(messages[index], 3000);
      index++;
      if (index >= messages.length) {
        setIsRunning(false);
        clearInterval(interval);
      }
    }, 3000);

    return () => clearInterval(interval);
  }, [isRunning, showInfo]);

  return (
    <div style={{ padding: '2rem' }}>
      <h2>Auto-Cycling Messages</h2>
      <button
        onClick={() => setIsRunning(true)}
        disabled={isRunning}
        style={{
          padding: '0.5rem 1rem',
          background: isRunning ? '#9ca3af' : '#3b82f6',
          color: 'white',
          border: 'none',
          borderRadius: '4px',
          cursor: isRunning ? 'not-allowed' : 'pointer',
          marginTop: '1rem',
        }}
      >
        {isRunning ? 'Running...' : 'Start System Check'}
      </button>
    </div>
  );
};

/**
 * Complete example combining all demonstrations
 */
export const CompleteSystemMessageExample: React.FC = () => {
  return (
    <div style={{ padding: '2rem', maxWidth: '1200px', margin: '0 auto' }}>
      <h1>System Message Examples</h1>
      <p style={{ color: '#6b7280', marginBottom: '2rem' }}>
        Look at the Navigation Bar above to see the messages appear when you interact with the buttons below.
      </p>

      <div style={{ display: 'grid', gap: '2rem' }}>
        <div style={{ border: '1px solid #e5e7eb', borderRadius: '8px', padding: '1rem' }}>
          <BasicMessageExample />
        </div>

        <div style={{ border: '1px solid #e5e7eb', borderRadius: '8px', padding: '1rem' }}>
          <CustomDurationExample />
        </div>

        <div style={{ border: '1px solid #e5e7eb', borderRadius: '8px', padding: '1rem' }}>
          <AsyncOperationExample />
        </div>

        <div style={{ border: '1px solid #e5e7eb', borderRadius: '8px', padding: '1rem' }}>
          <FormValidationExample />
        </div>

        <div style={{ border: '1px solid #e5e7eb', borderRadius: '8px', padding: '1rem' }}>
          <AutoCyclingExample />
        </div>
      </div>
    </div>
  );
};

export default CompleteSystemMessageExample;
