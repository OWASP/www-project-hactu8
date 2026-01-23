// src/contexts/FeatureFlagContext.tsx
import React, { createContext, useContext, useState, useEffect } from 'react';
import type { FeatureFlags } from '../config/featureFlags';
import {
  defaultFeatureFlags,
  loadFeatureFlags,
  saveFeatureFlags,
} from '../config/featureFlags';

interface FeatureFlagContextType {
  flags: FeatureFlags;
  updateFlags: (flags: Partial<FeatureFlags>) => void;
  resetFlags: () => void;
  isEnabled: (category: keyof FeatureFlags, feature: string) => boolean;
}

const FeatureFlagContext = createContext<FeatureFlagContextType | undefined>(undefined);

export const FeatureFlagProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [flags, setFlags] = useState<FeatureFlags>(loadFeatureFlags());

  // Save to localStorage whenever flags change
  useEffect(() => {
    saveFeatureFlags(flags);
  }, [flags]);

  const updateFlags = (updates: Partial<FeatureFlags>) => {
    setFlags((prev) => {
      const updated = { ...prev };
      Object.keys(updates).forEach((category) => {
        const categoryKey = category as keyof FeatureFlags;
        updated[categoryKey] = {
          ...prev[categoryKey],
          ...updates[categoryKey],
        } as any;
      });
      return updated;
    });
  };

  const resetFlags = () => {
    setFlags(defaultFeatureFlags);
  };

  const isEnabled = (category: keyof FeatureFlags, feature: string): boolean => {
    const categoryFlags = flags[category] as any;
    return categoryFlags?.[feature] ?? false;
  };

  return (
    <FeatureFlagContext.Provider value={{ flags, updateFlags, resetFlags, isEnabled }}>
      {children}
    </FeatureFlagContext.Provider>
  );
};

export const useFeatureFlags = (): FeatureFlagContextType => {
  const context = useContext(FeatureFlagContext);
  if (!context) {
    throw new Error('useFeatureFlags must be used within a FeatureFlagProvider');
  }
  return context;
};
