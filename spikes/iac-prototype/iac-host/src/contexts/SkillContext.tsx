// src/contexts/SkillContext.tsx
import React, { createContext, useContext, useState, useCallback, useEffect } from 'react';
import type { InstalledSkill, SkillManifest, SkillRegistryEntry, SkillStatus } from '../types/skills';
import skillService from '../services/skillService';

interface SkillContextType {
  installed: InstalledSkill[];
  refreshInstalled: () => void;
  installFromRegistry: (entry: SkillRegistryEntry) => Promise<InstalledSkill[]>;
  uninstallSkill: (skillId: string) => InstalledSkill[];
  saveDraft: (manifest: SkillManifest, content: string) => Promise<InstalledSkill[]>;
  updateStatus: (skillId: string, status: SkillStatus, errMsg?: string) => InstalledSkill[];
}

const SkillContext = createContext<SkillContextType | undefined>(undefined);

export const SkillProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [installed, setInstalled] = useState<InstalledSkill[]>(() => skillService.loadInstalled());

  const refreshInstalled = useCallback(() => {
    setInstalled(skillService.loadInstalled());
  }, []);

  useEffect(() => {
    refreshInstalled();
  }, [refreshInstalled]);

  const installFromRegistry = useCallback(
    (entry: SkillRegistryEntry) =>
      skillService.installFromRegistry(entry, installed).then((updated) => {
        setInstalled(updated);
        return updated;
      }),
    [installed]
  );

  const uninstallSkill = useCallback(
    (skillId: string) => {
      const updated = skillService.uninstallSkill(skillId, installed);
      setInstalled(updated);
      return updated;
    },
    [installed]
  );

  const saveDraft = useCallback(
    (manifest: SkillManifest, content: string) =>
      skillService.saveDraft(manifest, content, installed).then((updated) => {
        setInstalled(updated);
        return updated;
      }),
    [installed]
  );

  const updateStatus = useCallback(
    (skillId: string, status: SkillStatus, errMsg?: string) => {
      const updated = skillService.updateStatus(skillId, status, installed, errMsg);
      setInstalled(updated);
      return updated;
    },
    [installed]
  );

  return (
    <SkillContext.Provider
      value={{ installed, refreshInstalled, installFromRegistry, uninstallSkill, saveDraft, updateStatus }}
    >
      {children}
    </SkillContext.Provider>
  );
};

export const useSkills = (): SkillContextType => {
  const context = useContext(SkillContext);
  if (!context) {
    throw new Error('useSkills must be used within a SkillProvider');
  }
  return context;
};
