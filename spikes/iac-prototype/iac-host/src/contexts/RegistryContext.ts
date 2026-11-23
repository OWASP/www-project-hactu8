// src/contexts/RegistryContext.ts
import { createContext, useContext } from 'react';
import type { RegistryContextValue } from '../types/registry';

export const RegistryContext = createContext<RegistryContextValue | undefined>(undefined);

export const useRegistry = (): RegistryContextValue => {
  const context = useContext(RegistryContext);
  if (!context) {
    throw new Error('useRegistry must be used within a RegistryProvider');
  }
  return context;
};
