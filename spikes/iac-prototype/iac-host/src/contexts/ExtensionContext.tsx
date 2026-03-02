// src/contexts/ExtensionContext.tsx
import React, { createContext, useContext, useState, useCallback, useEffect } from 'react';
import type { InstalledExtension } from '../types/extensions';
import extensionService from '../services/extensionService';

interface ExtensionContextType {
  installed: InstalledExtension[];
  refreshInstalled: () => void;
  installExtension: (entry: any, installPath?: string) => Promise<InstalledExtension[]>;
  uninstallExtension: (extensionId: string) => Promise<InstalledExtension[]>;
  updateSettings: (extensionId: string, settings: Record<string, string | number | boolean>) => InstalledExtension[];
  updateStatus: (extensionId: string, status: 'active' | 'error', errMsg?: string) => InstalledExtension[];
}

const ExtensionContext = createContext<ExtensionContextType | undefined>(undefined);

export const ExtensionProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [installed, setInstalled] = useState<InstalledExtension[]>(() =>
    extensionService.loadInstalled()
  );

  const refreshInstalled = useCallback(() => {
    setInstalled(extensionService.loadInstalled());
  }, []);

  // Load installed extensions on mount
  useEffect(() => {
    refreshInstalled();
  }, [refreshInstalled]);

  const installExtension = useCallback((entry: any, installPath?: string) => {
    return extensionService.installExtension(entry, installed, installPath).then((updated) => {
      setInstalled(updated);
      return updated;
    });
  }, [installed]);

  const uninstallExtension = useCallback((extensionId: string) => {
    return extensionService.uninstallExtension(extensionId, installed).then((updated) => {
      setInstalled(updated);
      return updated;
    });
  }, [installed]);

  const updateSettings = useCallback(
    (extensionId: string, settings: Record<string, string | number | boolean>) => {
      const updated = extensionService.updateSettings(extensionId, settings, installed);
      setInstalled(updated);
      return updated;
    },
    [installed]
  );

  const updateStatus = useCallback(
    (extensionId: string, status: 'active' | 'error', errMsg?: string) => {
      const updated = extensionService.updateStatus(extensionId, status, installed, errMsg);
      setInstalled(updated);
      return updated;
    },
    [installed]
  );

  return (
    <ExtensionContext.Provider
      value={{
        installed,
        refreshInstalled,
        installExtension,
        uninstallExtension,
        updateSettings,
        updateStatus,
      }}
    >
      {children}
    </ExtensionContext.Provider>
  );
};

export const useExtensions = (): ExtensionContextType => {
  const context = useContext(ExtensionContext);
  if (!context) {
    throw new Error('useExtensions must be used within an ExtensionProvider');
  }
  return context;
};
