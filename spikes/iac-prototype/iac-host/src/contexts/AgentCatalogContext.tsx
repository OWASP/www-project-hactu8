// src/contexts/AgentCatalogContext.tsx
//
// Provider for the Agent Catalog (browsable/installable agent *definitions*).
// Mirrors `SkillContext.tsx`. NOT to be confused with `AgentContext.tsx`,
// which drives a single live engagement — this context only manages which
// agent definitions are installed on this host, exactly like Skills.
import React, { createContext, useContext, useState, useCallback, useEffect } from 'react';
import type {
  AgentCatalogContextValue,
  AgentDefinitionStatus,
  AgentManifest,
  AgentRegistryEntry,
  InstalledAgent,
} from '../types/agentCatalog';
import agentCatalogService from '../services/agentCatalogService';

const AgentCatalogContext = createContext<AgentCatalogContextValue | undefined>(undefined);

export const AgentCatalogProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [installed, setInstalled] = useState<InstalledAgent[]>(() => agentCatalogService.loadInstalled());

  const refreshInstalled = useCallback(() => {
    setInstalled(agentCatalogService.loadInstalled());
  }, []);

  useEffect(() => {
    refreshInstalled();
  }, [refreshInstalled]);

  const installFromRegistry = useCallback(
    (entry: AgentRegistryEntry) =>
      agentCatalogService.installFromRegistry(entry, installed).then((updated) => {
        setInstalled(updated);
        return updated;
      }),
    [installed]
  );

  const uninstallAgent = useCallback(
    (agentId: string) => {
      const updated = agentCatalogService.uninstallAgent(agentId, installed);
      setInstalled(updated);
      return updated;
    },
    [installed]
  );

  const saveDraft = useCallback(
    (manifest: AgentManifest, instructions: string) =>
      agentCatalogService.saveDraft(manifest, instructions, installed).then((updated) => {
        setInstalled(updated);
        return updated;
      }),
    [installed]
  );

  const updateStatus = useCallback(
    (agentId: string, status: AgentDefinitionStatus, errMsg?: string) => {
      const updated = agentCatalogService.updateStatus(agentId, status, installed, errMsg);
      setInstalled(updated);
      return updated;
    },
    [installed]
  );

  return (
    <AgentCatalogContext.Provider
      value={{ installed, refreshInstalled, installFromRegistry, uninstallAgent, saveDraft, updateStatus }}
    >
      {children}
    </AgentCatalogContext.Provider>
  );
};

export const useAgentCatalog = (): AgentCatalogContextValue => {
  const context = useContext(AgentCatalogContext);
  if (!context) {
    throw new Error('useAgentCatalog must be used within an AgentCatalogProvider');
  }
  return context;
};
