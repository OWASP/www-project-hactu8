// src/contexts/AgentCatalogContext.ts
//
// Context + hook for the Agent Catalog (browsable/installable agent *definitions*).
// Mirrors `SkillContext.tsx`. NOT to be confused with `AgentContext.tsx`,
// which drives a single live engagement — this context only manages which
// agent definitions are installed on this host, exactly like Skills.
import { createContext, useContext } from 'react';
import type { AgentCatalogContextValue } from '../types/agentCatalog';

export const AgentCatalogContext = createContext<AgentCatalogContextValue | undefined>(undefined);

export const useAgentCatalog = (): AgentCatalogContextValue => {
  const context = useContext(AgentCatalogContext);
  if (!context) {
    throw new Error('useAgentCatalog must be used within an AgentCatalogProvider');
  }
  return context;
};
