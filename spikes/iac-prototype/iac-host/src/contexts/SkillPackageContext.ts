// src/contexts/SkillPackageContext.ts
import { createContext, useContext } from 'react';
import type { SkillPackageContextValue } from '../types/skillPackage';

export const SkillPackageContext = createContext<SkillPackageContextValue | undefined>(undefined);

export const useSkillPackages = (): SkillPackageContextValue => {
  const context = useContext(SkillPackageContext);
  if (!context) {
    throw new Error('useSkillPackages must be used within a SkillPackageProvider');
  }
  return context;
};
