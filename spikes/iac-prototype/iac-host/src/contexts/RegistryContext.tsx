// src/contexts/RegistryContext.tsx
import React, { createContext, useContext, useState, useCallback, useEffect } from 'react';
import type { NewRegistryEntryInput, RegistryContextValue, RegistryEntry } from '../types/registry';
import registryService from '../services/registryService';

const RegistryContext = createContext<RegistryContextValue | undefined>(undefined);

export const RegistryProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [entries, setEntries] = useState<RegistryEntry[]>(() => registryService.loadEntries());

  const refreshEntries = useCallback(() => {
    setEntries(registryService.loadEntries());
  }, []);

  useEffect(() => {
    refreshEntries();
  }, [refreshEntries]);

  const addEntry = useCallback(
    (input: NewRegistryEntryInput) => {
      const updated = registryService.addEntry(input, entries);
      setEntries(updated);
      return updated;
    },
    [entries]
  );

  const updateEntry = useCallback(
    (id: string, patch: Partial<RegistryEntry>) => {
      const updated = registryService.updateEntry(id, patch, entries);
      setEntries(updated);
      return updated;
    },
    [entries]
  );

  const removeEntry = useCallback(
    (id: string) => {
      const updated = registryService.removeEntry(id, entries);
      setEntries(updated);
      return updated;
    },
    [entries]
  );

  return (
    <RegistryContext.Provider value={{ entries, refreshEntries, addEntry, updateEntry, removeEntry }}>
      {children}
    </RegistryContext.Provider>
  );
};

export const useRegistry = (): RegistryContextValue => {
  const context = useContext(RegistryContext);
  if (!context) {
    throw new Error('useRegistry must be used within a RegistryProvider');
  }
  return context;
};
