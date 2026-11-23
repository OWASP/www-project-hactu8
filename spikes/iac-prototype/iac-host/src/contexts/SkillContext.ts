// src/contexts/SkillContext.ts
import { createContext, useContext } from 'react';
import type { InstalledSkill, SkillManifest, SkillRegistryEntry, SkillStatus } from '../types/skills';

export interface SkillContextType {
  installed: InstalledSkill[];
  refreshInstalled: () => void;
  installFromRegistry: (entry: SkillRegistryEntry) => Promise<InstalledSkill[]>;
  uninstallSkill: (skillId: string) => InstalledSkill[];
  saveDraft: (manifest: SkillManifest, content: string) => Promise<InstalledSkill[]>;
  updateStatus: (skillId: string, status: SkillStatus, errMsg?: string) => InstalledSkill[];
}

export const SkillContext = createContext<SkillContextType | undefined>(undefined);

export const useSkills = (): SkillContextType => {
  const context = useContext(SkillContext);
  if (!context) {
    throw new Error('useSkills must be used within a SkillProvider');
  }
  return context;
};
