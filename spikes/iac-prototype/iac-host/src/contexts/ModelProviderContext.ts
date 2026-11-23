import { createContext, useContext } from 'react';
import type { ModelProviderConfig } from '../types/modelProvider';

export interface ModelProviderContextValue {
  config: ModelProviderConfig | null;
  configs: ModelProviderConfig[];
  defaultConfigId?: string;
  addConfig: (config: ModelProviderConfig) => void;
  updateConfig: (config: ModelProviderConfig) => void;
  removeConfig: (configId: string) => void;
  setDefaultConfig: (configId: string) => void;
  resetConfig: () => void;
}

export const ModelProviderContext = createContext<ModelProviderContextValue | null>(null);

export const useModelProvider = (): ModelProviderContextValue => {
  const context = useContext(ModelProviderContext);
  if (!context) {
    throw new Error('useModelProvider must be used within a ModelProviderProvider');
  }
  return context;
};

export default ModelProviderContext;
