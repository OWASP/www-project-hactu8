// src/contexts/ExtensionContext.ts
import { createContext, useContext } from 'react';
import type { InstalledExtension, RegistryEntry } from '../types/extensions';

export interface ExtensionContextType {
  installed: InstalledExtension[];
  refreshInstalled: () => void;
  installExtension: (entry: RegistryEntry, installPath?: string) => Promise<InstalledExtension[]>;
  uninstallExtension: (extensionId: string) => Promise<InstalledExtension[]>;
  updateSettings: (extensionId: string, settings: Record<string, string | number | boolean>) => InstalledExtension[];
  updateStatus: (extensionId: string, status: 'active' | 'error', errMsg?: string) => InstalledExtension[];
}

export const ExtensionContext = createContext<ExtensionContextType | undefined>(undefined);

export const useExtensions = (): ExtensionContextType => {
  const context = useContext(ExtensionContext);
  if (!context) {
    throw new Error('useExtensions must be used within an ExtensionProvider');
  }
  return context;
};
