// src/contexts/FeatureFlagProvider.tsx
import React, { useState, useEffect } from 'react';
import type { FeatureFlags } from '../config/featureFlags';
import {
  defaultFeatureFlags,
  isFeatureEnabled,
  loadFeatureFlags,
  saveFeatureFlags,
} from '../config/featureFlags';
import { FeatureFlagContext } from './FeatureFlagContext';

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
        (updated as Record<keyof FeatureFlags, unknown>)[categoryKey] = {
          ...prev[categoryKey],
          ...updates[categoryKey],
        };
      });
      return updated;
    });
  };

  const resetFlags = () => {
    setFlags(defaultFeatureFlags);
  };

  const isEnabled = (category: keyof FeatureFlags, feature: string): boolean => {
    return isFeatureEnabled(flags, category, feature);
  };

  return (
    <FeatureFlagContext.Provider value={{ flags, updateFlags, resetFlags, isEnabled }}>
      {children}
    </FeatureFlagContext.Provider>
  );
};
