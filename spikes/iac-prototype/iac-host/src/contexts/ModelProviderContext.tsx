import React, { createContext, useCallback, useContext, useMemo, useState } from 'react';
import type { ModelProviderConfig, ModelProviderState } from '../types/modelProvider';
import {
  getDefaultProviderConfig,
  loadModelProviderState,
  saveModelProviderState,
} from '../services/modelProviderService';

interface ModelProviderContextValue {
  config: ModelProviderConfig | null;
  configs: ModelProviderConfig[];
  defaultConfigId?: string;
  addConfig: (config: ModelProviderConfig) => void;
  updateConfig: (config: ModelProviderConfig) => void;
  removeConfig: (configId: string) => void;
  setDefaultConfig: (configId: string) => void;
  resetConfig: () => void;
}

const ModelProviderContext = createContext<ModelProviderContextValue | null>(null);

export const ModelProviderProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [state, setState] = useState<ModelProviderState | null>(() => loadModelProviderState());

  const addConfig = useCallback((config: ModelProviderConfig) => {
    setState(prev => {
      const nextState: ModelProviderState = {
        configs: [...(prev?.configs || []), config],
        defaultConfigId: prev?.defaultConfigId || config.id,
      };
      saveModelProviderState(nextState);
      return nextState;
    });
  }, []);

  const updateConfig = useCallback((config: ModelProviderConfig) => {
    setState(prev => {
      const configs = prev?.configs ? [...prev.configs] : [];
      const index = configs.findIndex(item => item.id === config.id);
      if (index >= 0) {
        configs[index] = config;
      } else {
        configs.push(config);
      }

      const nextState: ModelProviderState = {
        configs,
        defaultConfigId: prev?.defaultConfigId || config.id,
      };
      saveModelProviderState(nextState);
      return nextState;
    });
  }, []);

  const removeConfig = useCallback((configId: string) => {
    setState(prev => {
      const configs = (prev?.configs || []).filter(config => config.id !== configId);
      const nextState: ModelProviderState | null = configs.length
        ? {
          configs,
          defaultConfigId: prev?.defaultConfigId === configId ? configs[0].id : prev?.defaultConfigId,
        }
        : null;

      saveModelProviderState(nextState);
      return nextState;
    });
  }, []);

  const setDefaultConfig = useCallback((configId: string) => {
    setState(prev => {
      if (!prev?.configs?.length) {
        return prev;
      }
      const nextState: ModelProviderState = {
        configs: prev.configs,
        defaultConfigId: configId,
      };
      saveModelProviderState(nextState);
      return nextState;
    });
  }, []);

  const resetConfig = useCallback(() => {
    setState(null);
    saveModelProviderState(null);
  }, []);

  const defaultConfig = getDefaultProviderConfig(state);

  const value = useMemo(() => ({
    config: defaultConfig,
    configs: state?.configs || [],
    defaultConfigId: state?.defaultConfigId,
    addConfig,
    updateConfig,
    removeConfig,
    setDefaultConfig,
    resetConfig,
  }), [
    addConfig,
    defaultConfig,
    removeConfig,
    resetConfig,
    setDefaultConfig,
    state?.configs,
    state?.defaultConfigId,
    updateConfig,
  ]);

  return (
    <ModelProviderContext.Provider value={value}>
      {children}
    </ModelProviderContext.Provider>
  );
};

export const useModelProvider = (): ModelProviderContextValue => {
  const context = useContext(ModelProviderContext);
  if (!context) {
    throw new Error('useModelProvider must be used within a ModelProviderProvider');
  }
  return context;
};

export default ModelProviderContext;
