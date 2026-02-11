import type {
  ModelProviderConfig,
  ModelProviderId,
  ModelProviderOption,
  ModelProviderState,
  ModelRegistryProvider,
  ModelRegistryResponse,
} from '../types/modelProvider';

const STORAGE_KEY = 'iac-model-provider-config';

export function createConfigId(): string {
  return `mp_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

export const MODEL_PROVIDERS: ModelProviderOption[] = [
  { id: 'openai', label: 'OpenAI' },
  { id: 'anthropic', label: 'Anthropic' },
  { id: 'ollama', label: 'Local - Ollama' },
  { id: 'foundry', label: 'Local - Foundry' },
  { id: 'custom', label: 'Custom (OpenAI-compatible)' },
];

export const MODEL_OPTIONS: Record<ModelProviderId, string[]> = {
  openai: ['gpt-4o-mini', 'gpt-4.1', 'gpt-4o'],
  anthropic: ['claude-3.5-sonnet', 'claude-3.5-haiku', 'claude-3-opus'],
  ollama: ['llama3.1', 'mistral', 'qwen2.5'],
  foundry: ['phi-4', 'phi-3.5-mini'],
  custom: [],
};

export const MODEL_BASE_URLS: Partial<Record<ModelProviderId, string>> = {
  ollama: 'http://localhost:11434',
  foundry: 'http://localhost:8080',
};

export const DEFAULT_MODEL_REGISTRY: ModelRegistryProvider[] = MODEL_PROVIDERS.map(provider => ({
  id: provider.id,
  label: provider.label,
  models: MODEL_OPTIONS[provider.id],
  requiresBaseUrl: ['ollama', 'foundry', 'custom'].includes(provider.id),
}));

export function getProviderLabel(providerId: ModelProviderId): string {
  return MODEL_PROVIDERS.find(provider => provider.id === providerId)?.label || providerId;
}

export function getProviderOptions(registry?: ModelRegistryResponse | null): ModelProviderOption[] {
  if (registry?.providers?.length) {
    return registry.providers.map(provider => ({
      id: provider.id,
      label: provider.label,
    }));
  }

  return MODEL_PROVIDERS;
}

export function getProviderModels(
  providerId: ModelProviderId,
  registry?: ModelRegistryResponse | null
): string[] {
  const entry = registry?.providers?.find(provider => provider.id === providerId);
  if (entry) {
    return entry.models || [];
  }

  return MODEL_OPTIONS[providerId] || [];
}

export function providerRequiresBaseUrl(
  providerId: ModelProviderId,
  registry?: ModelRegistryResponse | null
): boolean {
  const entry = registry?.providers?.find(provider => provider.id === providerId);
  if (typeof entry?.requiresBaseUrl === 'boolean') {
    return entry.requiresBaseUrl;
  }

  return ['ollama', 'foundry', 'custom'].includes(providerId);
}

export function loadModelProviderState(): ModelProviderState | null {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) {
      return null;
    }

    const parsed = JSON.parse(stored) as ModelProviderState | ModelProviderConfig;

    if ('configs' in parsed) {
      const usedIds = new Set<string>();
      let didChange = false;

      const sanitizedConfigs = parsed.configs.map(config => {
        const nextId = config.id && !usedIds.has(config.id) ? config.id : createConfigId();
        if (nextId !== config.id) {
          didChange = true;
        }
        usedIds.add(nextId);
        return {
          ...config,
          id: nextId,
        };
      });

      const defaultConfigId = parsed.defaultConfigId && usedIds.has(parsed.defaultConfigId)
        ? parsed.defaultConfigId
        : sanitizedConfigs[0]?.id;

      if (defaultConfigId !== parsed.defaultConfigId) {
        didChange = true;
      }

      const nextState: ModelProviderState = {
        ...parsed,
        configs: sanitizedConfigs,
        defaultConfigId,
      };

      if (didChange) {
        saveModelProviderState(nextState);
      }

      return nextState;
    }

    if (parsed?.providerId && parsed?.model) {
      const migrated: ModelProviderState = {
        configs: [{
          id: createConfigId(),
          providerId: parsed.providerId,
          model: parsed.model,
          apiKey: parsed.apiKey,
          baseUrl: parsed.baseUrl,
          updatedAt: parsed.updatedAt,
        }],
      };
      migrated.defaultConfigId = migrated.configs[0].id;
      return migrated;
    }

    return null;
  } catch (error) {
    console.error('Error loading model provider config:', error);
    return null;
  }
}

export function saveModelProviderState(state: ModelProviderState | null): void {
  try {
    if (!state) {
      localStorage.removeItem(STORAGE_KEY);
      return;
    }

    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch (error) {
    console.error('Error saving model provider config:', error);
  }
}

export function getDefaultProviderConfig(state?: ModelProviderState | null): ModelProviderConfig | null {
  if (!state?.configs?.length) {
    return null;
  }

  if (state.defaultConfigId) {
    const match = state.configs.find(config => config.id === state.defaultConfigId);
    if (match) {
      return match;
    }
  }

  return state.configs[0] || null;
}

export function getModelProviderHeaders(): Record<string, string> {
  const state = loadModelProviderState();
  const config = getDefaultProviderConfig(state);
  if (!config) {
    return {};
  }

  const headers: Record<string, string> = {
    'X-Model-Provider': config.providerId,
    'X-Model-Id': config.model,
  };

  if (config.apiKey) {
    headers['X-Api-Key'] = config.apiKey;
  }

  if (config.baseUrl) {
    headers['X-Model-Base-Url'] = config.baseUrl;
  }

  return headers;
}
