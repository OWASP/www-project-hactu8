/**
 * Context + hook for the IAC Copilot feature (provider: CopilotProvider.tsx).
 * Manages copilot state, chat history, and document operations.
 */
import { createContext, useContext } from 'react';
import type { CopilotContextValue } from '../types/copilot';

// Create context
export const CopilotContext = createContext<CopilotContextValue | null>(null);

/**
 * Hook to use the Copilot context.
 */
export const useCopilot = (): CopilotContextValue => {
  const context = useContext(CopilotContext);
  if (!context) {
    throw new Error('useCopilot must be used within a CopilotProvider');
  }
  return context;
};

export default CopilotContext;
