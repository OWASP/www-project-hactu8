// src/contexts/SkillPackageContext.tsx
import React, { createContext, useContext, useState, useCallback, useEffect } from 'react';
import type { InstalledSkillPackage, SkillPackageContextValue } from '../types/skillPackage';
import skillPackageService from '../services/skillPackageService';

const SkillPackageContext = createContext<SkillPackageContextValue | undefined>(undefined);

export const SkillPackageProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [installed, setInstalled] = useState<InstalledSkillPackage[]>(() => skillPackageService.loadCached());
  const [isLoading, setIsLoading] = useState(false);
  const [isInstalling, setIsInstalling] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refreshInstalled = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const skills = await skillPackageService.listSkillPackages();
      setInstalled(skills);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load skill packages');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshInstalled();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const installFromFile = useCallback(
    async (file: File, overwrite = false) => {
      setIsInstalling(true);
      setError(null);
      try {
        const { skill } = await skillPackageService.uploadSkillPackage(file, overwrite);
        await refreshInstalled();
        return skill;
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Install failed';
        setError(message);
        throw err;
      } finally {
        setIsInstalling(false);
      }
    },
    [refreshInstalled]
  );

  const uninstall = useCallback(
    async (name: string) => {
      setError(null);
      try {
        await skillPackageService.uninstallSkillPackage(name);
        await refreshInstalled();
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Uninstall failed');
        throw err;
      }
    },
    [refreshInstalled]
  );

  return (
    <SkillPackageContext.Provider
      value={{ installed, isLoading, isInstalling, error, refreshInstalled, installFromFile, uninstall }}
    >
      {children}
    </SkillPackageContext.Provider>
  );
};

export const useSkillPackages = (): SkillPackageContextValue => {
  const context = useContext(SkillPackageContext);
  if (!context) {
    throw new Error('useSkillPackages must be used within a SkillPackageProvider');
  }
  return context;
};
