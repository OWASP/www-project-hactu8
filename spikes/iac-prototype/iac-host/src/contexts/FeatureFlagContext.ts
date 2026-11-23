// src/contexts/FeatureFlagContext.ts
import { createContext, useContext } from 'react';
import type { FeatureFlags } from '../config/featureFlags';

export interface FeatureFlagContextType {
  flags: FeatureFlags;
  updateFlags: (flags: Partial<FeatureFlags>) => void;
  resetFlags: () => void;
  isEnabled: (category: keyof FeatureFlags, feature: string) => boolean;
}

export const FeatureFlagContext = createContext<FeatureFlagContextType | undefined>(undefined);

export const useFeatureFlags = (): FeatureFlagContextType => {
  const context = useContext(FeatureFlagContext);
  if (!context) {
    throw new Error('useFeatureFlags must be used within a FeatureFlagProvider');
  }
  return context;
};
