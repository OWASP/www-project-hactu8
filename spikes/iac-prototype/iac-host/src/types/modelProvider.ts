/**
 * Types for model provider configuration.
 */

export type ModelProviderId = 'openai' | 'anthropic' | 'ollama' | 'foundry' | 'custom';

export interface ModelProviderConfig {
  id: string;
  providerId: ModelProviderId;
  model: string;
  apiKey?: string;
  baseUrl?: string;
  updatedAt?: string;
}

export interface ModelProviderState {
  configs: ModelProviderConfig[];
  defaultConfigId?: string;
}

export interface ModelRegistryProvider {
  id: ModelProviderId;
  label: string;
  models: string[];
  requiresBaseUrl?: boolean;
}

export interface ModelRegistryResponse {
  providers: ModelRegistryProvider[];
  updatedAt: string;
}

export interface ModelProviderOption {
  id: ModelProviderId;
  label: string;
}
