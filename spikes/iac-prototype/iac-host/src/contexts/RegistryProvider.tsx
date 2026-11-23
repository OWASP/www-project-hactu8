// src/contexts/RegistryProvider.tsx
import React, { useState, useCallback, useEffect } from 'react';
import type { NewRegistryEntryInput, RegistryEntry } from '../types/registry';
import registryService from '../services/registryService';
import { RegistryContext } from './RegistryContext';

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
