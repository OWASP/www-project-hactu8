// src/contexts/ExtensionProvider.tsx
import React, { useState, useCallback, useEffect } from 'react';
import type { InstalledExtension, RegistryEntry } from '../types/extensions';
import extensionService from '../services/extensionService';
import { ExtensionContext } from './ExtensionContext';

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

  const installExtension = useCallback((entry: RegistryEntry, installPath?: string) => {
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
