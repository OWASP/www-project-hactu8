
import { useState, useEffect } from 'react';
import { useFeatureFlags } from '../contexts/FeatureFlagContext';
import type { FeatureFlags } from '../config/featureFlags';
import { presets, presetDescriptions } from '../config/featureFlagPresets';
import type { PresetName } from '../config/featureFlagPresets';
import { checkHealth, getModelRegistry, COPILOT_API_BASE } from '../services/copilotService';
import { useModelProvider } from '../contexts/ModelProviderContext';
import type { ModelProviderConfig, ModelProviderId, ModelRegistryResponse } from '../types/modelProvider';
import {
    MODEL_BASE_URLS,
    createConfigId,
    getProviderLabel,
    getProviderModels,
    getProviderOptions,
    providerRequiresBaseUrl,
} from '../services/modelProviderService';

// Health check status types
type HealthStatus = 'healthy' | 'warning' | 'error' | 'loading';

interface HealthCheckItem {
    name: string;
    status: HealthStatus;
    message: string;
    details?: string;
}

// TODO: Settings, other functions based on user authorization
const sections = [
    // { key: 'profile', label: 'Profile' },
    { key: 'health', label: 'Health' },
    { key: 'modelProvider', label: 'Model Providers' },
    { key: 'security', label: 'Security' },
    { key: 'keys', label: 'API Keys' },
    { key: 'notifications', label: 'Notifications' },
    { key: 'billing', label: 'Billing' },
    { key: 'features', label: 'Feature Flags' },
];

function HealthPanel() {
    const { config } = useModelProvider();
    const [healthChecks, setHealthChecks] = useState<HealthCheckItem[]>([
        { name: 'Copilot API', status: 'loading', message: 'Checking...' },
        { name: 'Model Configuration', status: 'loading', message: 'Checking...' },
        { name: 'Platform', status: 'loading', message: 'Checking...' },
    ]);

    useEffect(() => {
        performHealthChecks();
    }, [config]);

    const performHealthChecks = async () => {
        const checks: HealthCheckItem[] = [];

        // Check Copilot API
        try {
            const health = await checkHealth();
            checks.push({
                name: 'Copilot API',
                status: health.status === 'ok' ? 'healthy' : 'warning',
                message: health.status === 'ok' ? 'Connected' : 'API responding with issues',
                details: `Documents: ${health.documentCount}, Vector store: ${health.vectorStoreCount}`,
            });
        } catch (error) {
            checks.push({
                name: 'Copilot API',
                status: 'error',
                message: 'Connection failed',
                details: error instanceof Error ? error.message : 'Unknown error',
            });
        }

        // Check Model Configuration
        const modelConfig = config?.model || 'Not configured';
        const modelStatus: HealthStatus = config?.model ? 'healthy' : 'warning';
        checks.push({
            name: 'Model Configuration',
            status: modelStatus,
            message: modelConfig,
            details: modelStatus === 'healthy'
                ? `Provider: ${getProviderLabel(config?.providerId || 'openai')}`
                : 'Model not configured in settings',
        });

        // Check Platform
        const platform = config ? getProviderLabel(config.providerId) : 'Not configured';
        const platformStatus: HealthStatus = config ? 'healthy' : 'warning';
        checks.push({
            name: 'Platform',
            status: platformStatus,
            message: platform,
            details: config ? `Using ${platform} for AI inference` : 'No model provider selected',
        });

        setHealthChecks(checks);
    };

    const getStatusColor = (status: HealthStatus): string => {
        switch (status) {
            case 'healthy':
                return '#10b981'; // green
            case 'warning':
                return '#f59e0b'; // yellow/orange
            case 'error':
                return '#ef4444'; // red
            case 'loading':
                return '#6b7280'; // gray
        }
    };

    const getStatusBgColor = (status: HealthStatus): string => {
        switch (status) {
            case 'healthy':
                return '#d1fae5'; // light green
            case 'warning':
                return '#fef3c7'; // light yellow
            case 'error':
                return '#fee2e2'; // light red
            case 'loading':
                return '#f3f4f6'; // light gray
        }
    };

    return (
        <div>
            <div style={{ marginBottom: '1.5rem' }}>
                <h3 style={{ color: '#111827', fontWeight: 700, fontSize: '1.5rem', margin: 0 }}>System Health</h3>
                <p style={{ color: '#4b5563', marginTop: '0.5rem', fontSize: '14px' }}>
                    Monitor the health status of integrated services and configurations.
                </p>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '1rem' }}>
                <button
                    onClick={performHealthChecks}
                    style={{
                        padding: '0.5rem 1rem',
                        background: '#213547',
                        color: 'white',
                        border: 'none',
                        borderRadius: '4px',
                        cursor: 'pointer',
                        fontWeight: 500,
                        fontSize: '14px',
                    }}
                >
                    Refresh Status
                </button>
            </div>

            <div style={{ display: 'grid', gap: '1rem' }}>
                {healthChecks.map((check) => (
                    <div
                        key={check.name}
                        style={{
                            padding: '1.5rem',
                            border: '1px solid #e5e7eb',
                            borderRadius: '8px',
                            background: '#ffffff',
                        }}
                    >
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                            <h4 style={{ color: '#111827', fontWeight: 600, margin: 0, fontSize: '1.125rem' }}>
                                {check.name}
                            </h4>
                            <div
                                style={{
                                    width: '80px',
                                    height: '80px',
                                    borderRadius: '8px',
                                    background: getStatusBgColor(check.status),
                                    border: `3px solid ${getStatusColor(check.status)}`,
                                    display: 'flex',
                                    alignItems: 'center',
                                    justifyContent: 'center',
                                    fontWeight: 700,
                                    fontSize: '0.75rem',
                                    color: getStatusColor(check.status),
                                    textTransform: 'uppercase',
                                    letterSpacing: '0.05em',
                                }}
                            >
                                {check.status === 'loading' ? '...' : check.status}
                            </div>
                        </div>
                        <div style={{ marginBottom: '0.5rem' }}>
                            <span
                                style={{
                                    display: 'inline-block',
                                    padding: '0.25rem 0.75rem',
                                    borderRadius: '4px',
                                    background: getStatusBgColor(check.status),
                                    color: getStatusColor(check.status),
                                    fontSize: '0.875rem',
                                    fontWeight: 600,
                                }}
                            >
                                {check.message}
                            </span>
                        </div>
                        {check.details && (
                            <p style={{ color: '#6b7280', fontSize: '0.875rem', margin: '0.5rem 0 0 0' }}>
                                {check.details}
                            </p>
                        )}
                    </div>
                ))}
            </div>
        </div>
    );
}

function ModelProviderPanel() {
    const {
        config,
        configs,
        defaultConfigId,
        addConfig,
        updateConfig,
        removeConfig,
        setDefaultConfig,
        resetConfig,
    } = useModelProvider();
    const [registry, setRegistry] = useState<ModelRegistryResponse | null>(null);
    const [registryError, setRegistryError] = useState<string | null>(null);
    const [registryLoading, setRegistryLoading] = useState<boolean>(false);
    const [editingId, setEditingId] = useState<string | null>(null);
    const [useCustomModel, setUseCustomModel] = useState(false);
    const [formState, setFormState] = useState<ModelProviderConfig>(() => {
        const providerId = config?.providerId || 'openai';
        const modelDefaults = getProviderModels(providerId, registry);
        return {
            id: config?.id || createConfigId(),
            providerId,
            model: config?.model || modelDefaults[0] || '',
            apiKey: config?.apiKey || '',
            baseUrl: config?.baseUrl || MODEL_BASE_URLS[providerId] || '',
            updatedAt: config?.updatedAt,
        };
    });

    const loadRegistry = async () => {
        setRegistryLoading(true);
        try {
            const response = await getModelRegistry();
            setRegistry(response);
            setRegistryError(null);
        } catch (error) {
            setRegistryError(error instanceof Error ? error.message : 'Failed to load registry');
        } finally {
            setRegistryLoading(false);
        }
    };

    useEffect(() => {
        loadRegistry();
    }, []);

    useEffect(() => {
        const providerId = config?.providerId || 'openai';
        const modelDefaults = getProviderModels(providerId, registry);
        const hasCustomModel = Boolean(config?.model && !modelDefaults.includes(config.model));
        setFormState({
            id: config?.id || createConfigId(),
            providerId,
            model: config?.model || modelDefaults[0] || '',
            apiKey: config?.apiKey || '',
            baseUrl: config?.baseUrl || MODEL_BASE_URLS[providerId] || '',
            updatedAt: config?.updatedAt,
        });
        setUseCustomModel(hasCustomModel);
        setEditingId(null);
    }, [config, registry]);

    const providerOptions = getProviderOptions(registry);
    const modelOptions = getProviderModels(formState.providerId, registry);
    const hasModelOptions = modelOptions.length > 0;
    const showBaseUrl = providerRequiresBaseUrl(formState.providerId, registry);

    const handleProviderChange = (nextProviderId: ModelProviderId) => {
        const nextModelOptions = getProviderModels(nextProviderId, registry);
        const nextModel = nextModelOptions.includes(formState.model)
            ? formState.model
            : (nextModelOptions[0] || '');

        setUseCustomModel(false);
        setFormState(prev => ({
            ...prev,
            providerId: nextProviderId,
            model: nextModel,
            baseUrl: MODEL_BASE_URLS[nextProviderId] || '',
        }));
    };

    const handleSave = () => {
        const trimmedModel = formState.model.trim();
        if (!trimmedModel) {
            return;
        }

        const nextConfig: ModelProviderConfig = {
            id: editingId || formState.id,
            providerId: formState.providerId,
            model: trimmedModel,
            apiKey: formState.apiKey.trim() || undefined,
            baseUrl: formState.baseUrl.trim() || undefined,
            updatedAt: new Date().toISOString(),
        };

        if (editingId) {
            updateConfig(nextConfig);
        } else {
            addConfig(nextConfig);
        }

        setEditingId(null);
    };

    const handleEdit = (target: ModelProviderConfig) => {
        const availableModels = getProviderModels(target.providerId, registry);
        setEditingId(target.id);
        setFormState({
            id: target.id,
            providerId: target.providerId,
            model: target.model,
            apiKey: target.apiKey || '',
            baseUrl: target.baseUrl || MODEL_BASE_URLS[target.providerId] || '',
            updatedAt: target.updatedAt,
        });
        setUseCustomModel(availableModels.length > 0 && !availableModels.includes(target.model));
    };

    const handleAddNew = () => {
        const providerId = 'openai';
        const modelDefaults = getProviderModels(providerId, registry);
        setEditingId(null);
        setUseCustomModel(false);
        setFormState({
            id: createConfigId(),
            providerId,
            model: modelDefaults[0] || '',
            apiKey: '',
            baseUrl: MODEL_BASE_URLS[providerId] || '',
            updatedAt: undefined,
        });
    };

    return (
        <div>
            <div style={{ marginBottom: '1.5rem' }}>
                <h3 style={{ color: '#111827', fontWeight: 700, fontSize: '1.5rem', margin: 0 }}>Model Providers</h3>
                <p style={{ color: '#4b5563', marginTop: '0.5rem', fontSize: '14px' }}>
                    Select the platform and model used by the Copilot panels.
                </p>
            </div>

            <div style={{ display: 'grid', gap: '1rem', maxWidth: 620 }}>
                <div style={{ display: 'grid', gap: '0.75rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <h4 style={{ margin: 0, fontSize: '14px', color: '#111827', fontWeight: 600 }}>Saved Providers</h4>
                        <div style={{ display: 'flex', gap: '0.5rem' }}>
                            <button
                                onClick={loadRegistry}
                                disabled={registryLoading || !COPILOT_API_BASE}
                                style={{
                                    padding: '0.35rem 0.75rem',
                                    background: '#ffffff',
                                    color: '#111827',
                                    border: '1px solid #d1d5db',
                                    borderRadius: '4px',
                                    cursor: registryLoading || !COPILOT_API_BASE ? 'not-allowed' : 'pointer',
                                    fontSize: '12px',
                                    fontWeight: 600,
                                }}
                            >
                                {registryLoading ? 'Refreshing...' : 'Refresh'}
                            </button>
                            <button
                                onClick={handleAddNew}
                                style={{
                                    padding: '0.35rem 0.75rem',
                                    background: '#213547',
                                    color: '#ffffff',
                                    border: 'none',
                                    borderRadius: '4px',
                                    cursor: 'pointer',
                                    fontSize: '12px',
                                    fontWeight: 600,
                                }}
                            >
                                Add Provider
                            </button>
                        </div>
                    </div>
                    {configs.length === 0 ? (
                        <div style={{ padding: '0.75rem', border: '1px dashed #e5e7eb', borderRadius: '6px', fontSize: '12px', color: '#6b7280' }}>
                            No saved providers yet. Add a provider below.
                        </div>
                    ) : (
                        <div style={{ display: 'grid', gap: '0.5rem' }}>
                            {configs.map(saved => (
                                <div
                                    key={saved.id}
                                    style={{
                                        display: 'grid',
                                        gridTemplateColumns: '20px 1fr auto',
                                        alignItems: 'center',
                                        gap: '0.75rem',
                                        padding: '0.75rem',
                                        border: '1px solid #e5e7eb',
                                        borderRadius: '6px',
                                        background: '#ffffff',
                                    }}
                                >
                                    <input
                                        type="radio"
                                        checked={saved.id === defaultConfigId}
                                        onChange={() => setDefaultConfig(saved.id)}
                                    />
                                    <div>
                                        <div style={{ fontSize: '13px', fontWeight: 600, color: '#111827' }}>
                                            {getProviderLabel(saved.providerId)} - {saved.model}
                                        </div>
                                        {saved.baseUrl && (
                                            <div style={{ fontSize: '12px', color: '#6b7280' }}>{saved.baseUrl}</div>
                                        )}
                                    </div>
                                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                                        <button
                                            onClick={() => setDefaultConfig(saved.id)}
                                            style={{
                                                padding: '0.35rem 0.6rem',
                                                borderRadius: '4px',
                                                border: '1px solid #d1d5db',
                                                background: saved.id === defaultConfigId ? '#1f2937' : '#ffffff',
                                                color: saved.id === defaultConfigId ? '#ffffff' : '#111827',
                                                cursor: 'pointer',
                                                fontSize: '12px',
                                                fontWeight: 600,
                                            }}
                                        >
                                            Use in Copilot
                                        </button>
                                        <button
                                            onClick={() => handleEdit(saved)}
                                            style={{
                                                padding: '0.35rem 0.6rem',
                                                borderRadius: '4px',
                                                border: '1px solid #d1d5db',
                                                background: '#ffffff',
                                                color: '#111827',
                                                cursor: 'pointer',
                                                fontSize: '12px',
                                                fontWeight: 600,
                                            }}
                                        >
                                            Edit
                                        </button>
                                        <button
                                            onClick={() => removeConfig(saved.id)}
                                            style={{
                                                padding: '0.35rem 0.6rem',
                                                borderRadius: '4px',
                                                border: 'none',
                                                background: '#ef4444',
                                                color: '#ffffff',
                                                cursor: 'pointer',
                                                fontSize: '12px',
                                            }}
                                        >
                                            Remove
                                        </button>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                <label style={{ display: 'grid', gap: '0.5rem', fontSize: '14px', color: '#374151' }}>
                    Platform
                    <select
                        value={formState.providerId}
                        onChange={e => handleProviderChange(e.target.value as ModelProviderId)}
                        style={{
                            padding: '0.6rem 0.75rem',
                            borderRadius: '6px',
                            border: '1px solid #d1d5db',
                            background: '#ffffff',
                            color: '#111827',
                        }}
                    >
                        {providerOptions.map(provider => (
                            <option key={provider.id} value={provider.id}>
                                {provider.label}
                            </option>
                        ))}
                    </select>
                </label>

                <label style={{ display: 'grid', gap: '0.5rem', fontSize: '14px', color: '#374151' }}>
                    Model
                    {hasModelOptions ? (
                        <>
                            <select
                                value={useCustomModel ? '__custom__' : formState.model}
                                onChange={e => {
                                    const nextValue = e.target.value;
                                    if (nextValue === '__custom__') {
                                        setUseCustomModel(true);
                                        setFormState(prev => ({ ...prev, model: '' }));
                                        return;
                                    }
                                    setUseCustomModel(false);
                                    setFormState(prev => ({ ...prev, model: nextValue }));
                                }}
                                style={{
                                    padding: '0.6rem 0.75rem',
                                    borderRadius: '6px',
                                    border: '1px solid #d1d5db',
                                    background: '#ffffff',
                                    color: '#111827',
                                }}
                            >
                                {modelOptions.map(option => (
                                    <option key={option} value={option}>
                                        {option}
                                    </option>
                                ))}
                                <option value="__custom__">Custom...</option>
                            </select>
                            {useCustomModel && (
                                <input
                                    value={formState.model}
                                    onChange={e => setFormState(prev => ({ ...prev, model: e.target.value }))}
                                    placeholder="Enter custom model"
                                    style={{
                                        padding: '0.6rem 0.75rem',
                                        borderRadius: '6px',
                                        border: '1px solid #d1d5db',
                                        background: '#ffffff',
                                        color: '#111827',
                                    }}
                                />
                            )}
                        </>
                    ) : (
                        <input
                            value={formState.model}
                            onChange={e => setFormState(prev => ({ ...prev, model: e.target.value }))}
                            placeholder="Enter a model"
                            style={{
                                padding: '0.6rem 0.75rem',
                                borderRadius: '6px',
                                border: '1px solid #d1d5db',
                                background: '#ffffff',
                                color: '#111827',
                            }}
                        />
                    )}
                </label>

                <label style={{ display: 'grid', gap: '0.5rem', fontSize: '14px', color: '#374151' }}>
                    API Key
                    <input
                        type="password"
                        value={formState.apiKey}
                        onChange={e => setFormState(prev => ({ ...prev, apiKey: e.target.value }))}
                        placeholder="Enter your API key"
                        style={{
                            padding: '0.6rem 0.75rem',
                            borderRadius: '6px',
                            border: '1px solid #d1d5db',
                            background: '#ffffff',
                            color: '#111827',
                        }}
                    />
                </label>

                {showBaseUrl && (
                    <label style={{ display: 'grid', gap: '0.5rem', fontSize: '14px', color: '#374151' }}>
                        Base URL
                        <input
                            value={formState.baseUrl}
                            onChange={e => setFormState(prev => ({ ...prev, baseUrl: e.target.value }))}
                            placeholder="http://localhost:11434"
                            style={{
                                padding: '0.6rem 0.75rem',
                                borderRadius: '6px',
                                border: '1px solid #d1d5db',
                                background: '#ffffff',
                                color: '#111827',
                            }}
                        />
                    </label>
                )}

                <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.5rem' }}>
                    <button
                        onClick={handleSave}
                        style={{
                            padding: '0.6rem 1.2rem',
                            background: '#213547',
                            color: '#ffffff',
                            border: 'none',
                            borderRadius: '6px',
                            cursor: 'pointer',
                            fontWeight: 600,
                        }}
                    >
                        {editingId ? 'Update Provider' : 'Save Provider'}
                    </button>
                    <button
                        onClick={resetConfig}
                        style={{
                            padding: '0.6rem 1.2rem',
                            background: '#ef4444',
                            color: '#ffffff',
                            border: 'none',
                            borderRadius: '6px',
                            cursor: 'pointer',
                            fontWeight: 600,
                        }}
                    >
                        Clear
                    </button>
                </div>

                <p style={{ color: '#6b7280', fontSize: '12px' }}>
                    Configuration is stored locally in your browser and used for Copilot requests.
                </p>
                {registryError && (
                    <p style={{ color: '#ef4444', fontSize: '12px' }}>
                            Registry error: {registryError}. {COPILOT_API_BASE ? `Base: ${COPILOT_API_BASE}` : ''}
                    </p>
                )}
                {!registryError && registryLoading && (
                    <p style={{ color: '#6b7280', fontSize: '12px' }}>
                        Loading provider registry...
                    </p>
                )}
            </div>
        </div>
    );
}

function FeatureFlagsPanel() {
    const { flags, updateFlags, resetFlags } = useFeatureFlags();

    const handleToggle = (category: keyof FeatureFlags, feature: string) => {
        const categoryFlags = flags[category] as any;
        updateFlags({
            [category]: {
                ...categoryFlags,
                [feature]: !categoryFlags[feature],
            },
        } as Partial<FeatureFlags>);
    };

    const loadPreset = (presetName: PresetName) => {
        const preset = presets[presetName];
        updateFlags(preset);
    };

    const renderCategory = (title: string, category: keyof FeatureFlags) => {
        const categoryFlags = flags[category] as any;
        return (
            <div key={category} style={{ marginBottom: '2rem' }}>
                <h4 style={{ marginBottom: '1rem', color: '#111827', fontWeight: 600 }}>{title}</h4>
                <div style={{ display: 'grid', gap: '0.5rem' }}>
                    {Object.keys(categoryFlags).map((feature) => (
                        <label
                            key={feature}
                            style={{
                                display: 'flex',
                                alignItems: 'center',
                                gap: '0.5rem',
                                padding: '0.5rem',
                                background: '#f9fafb',
                                borderRadius: '4px',
                                cursor: 'pointer',
                            }}
                        >
                            <input
                                type="checkbox"
                                checked={categoryFlags[feature]}
                                onChange={() => handleToggle(category, feature)}
                                style={{ cursor: 'pointer' }}
                            />
                            <span style={{ textTransform: 'capitalize', color: '#1f2937', fontSize: '14px' }}>
                                {feature.replace(/([A-Z])/g, ' $1').trim()}
                            </span>
                        </label>
                    ))}
                </div>
            </div>
        );
    };

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
                <div>
                    <h3 style={{ color: '#111827', fontWeight: 700, fontSize: '1.5rem', margin: 0 }}>Feature Flags</h3>
                    <p style={{ color: '#4b5563', marginTop: '0.5rem', fontSize: '14px' }}>
                        Enable or disable features throughout the application.
                    </p>
                </div>
                <button
                    onClick={resetFlags}
                    style={{
                        padding: '0.5rem 1rem',
                        background: '#dc2626',
                        color: 'white',
                        border: 'none',
                        borderRadius: '4px',
                        cursor: 'pointer',
                        fontWeight: 500,
                    }}
                >
                    Reset to Defaults
                </button>
            </div>

            {/* Presets Section */}
            <div style={{ marginBottom: '2rem', padding: '1rem', background: '#f3f4f6', borderRadius: '6px' }}>
                <h4 style={{ marginBottom: '1rem', color: '#111827', fontWeight: 600 }}>Quick Presets</h4>
                <p style={{ color: '#4b5563', fontSize: '0.875rem', marginBottom: '1rem' }}>
                    Load a predefined configuration to quickly set up feature flags for common use cases.
                </p>
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                    {(Object.keys(presets) as PresetName[]).map((presetName) => (
                        <button
                            key={presetName}
                            onClick={() => loadPreset(presetName)}
                            style={{
                                padding: '0.5rem 1rem',
                                background: '#213547',
                                color: 'white',
                                border: 'none',
                                borderRadius: '4px',
                                cursor: 'pointer',
                                fontWeight: 500,
                                fontSize: '0.875rem',
                            }}
                            title={presetDescriptions[presetName]}
                        >
                            {presetName.charAt(0).toUpperCase() + presetName.slice(1)}
                        </button>
                    ))}
                </div>
            </div>

            {/* Individual Feature Flags */}
            <div style={{ maxHeight: 'calc(100vh - 400px)', overflowY: 'auto', paddingRight: '1rem' }}>
                {renderCategory('Navigation', 'navigation')}
                {renderCategory('Monitoring', 'monitoring')}
                {renderCategory('Library', 'library')}
                {renderCategory('Copilot', 'copilot')}
                {renderCategory('Projects', 'projects')}
                {renderCategory('Testing Tools', 'testing')}
                {renderCategory('Reporting', 'reporting')}
                {renderCategory('Other Features', 'other')}
                {renderCategory('User Menu', 'user')}
                {renderCategory('Navigation Bar', 'navbar')}
            </div>
        </div>
    );
}

function SectionPanel({ section }: { section: string }) {
    switch (section) {
        case 'health':
            return <HealthPanel />;
        case 'modelProvider':
            return <ModelProviderPanel />;
        case 'profile':
            return (
                <div>
                    <h3 style={{ color: '#111827' }}>Profile Settings</h3>
                    <p style={{ color: '#4b5563' }}>Update your personal information, email, and avatar.</p>
                </div>
            );
        case 'security':
            return (
                <div>
                    <h3 style={{ color: '#111827' }}>Security</h3>
                    <p style={{ color: '#4b5563' }}>Change your password, enable 2FA, and review recent activity.</p>
                </div>
            );
        case 'keys':
            return (
                <div>
                    <h3 style={{ color: '#111827' }}>API Keys</h3>
                    <p style={{ color: '#4b5563' }}>Manage your API keys and access tokens.</p>
                </div>
            );
        case 'notifications':
            return (
                <div>
                    <h3 style={{ color: '#111827' }}>Notifications</h3>
                    <p style={{ color: '#4b5563' }}>Configure your notification preferences.</p>
                </div>
            );
        case 'billing':
            return (
                <div>
                    <h3 style={{ color: '#111827' }}>Billing</h3>
                    <p style={{ color: '#4b5563' }}>View invoices and manage payment methods.</p>
                </div>
            );
        case 'features':
            return <FeatureFlagsPanel />;
        default:
            return <div style={{ color: '#4b5563' }}>Select a section</div>;
    }
}

const SETTINGS_SECTION_KEY = 'iac-settings-section';

const Settings = () => {
    const [selected, setSelected] = useState(() => {
        const stored = localStorage.getItem(SETTINGS_SECTION_KEY);
        return stored || 'health';
    });

    useEffect(() => {
        localStorage.setItem(SETTINGS_SECTION_KEY, selected);
    }, [selected]);

    // Minimal, unstyled layout
    return (
        <div style={{ display: 'flex', minHeight: '60vh', height: '100%', overflow: 'hidden' }}>
            <aside style={{ width: 200, padding: '1rem', background: '#f9fafb', borderRight: '1px solid #e5e7eb' }}>
                <h3 style={{ color: '#111827', marginBottom: '1rem' }}>Settings</h3>
                <nav>
                    <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
                        {sections.map((s) => (
                            <li key={s.key}>
                                <button
                                    style={{
                                        width: '100%',
                                        padding: '0.75rem 1rem',
                                        background: selected === s.key ? '#213547' : 'transparent',
                                        color: selected === s.key ? '#ffffff' : '#374151',
                                        border: 'none',
                                        textAlign: 'left',
                                        fontWeight: selected === s.key ? 600 : 400,
                                        cursor: 'pointer',
                                        borderRadius: '4px',
                                        marginBottom: '0.25rem',
                                    }}
                                    onClick={() => setSelected(s.key)}
                                >
                                    {s.label}
                                </button>
                            </li>
                        ))}
                    </ul>
                </nav>
            </aside>
            <main style={{ flex: 1, padding: '2rem', overflowY: 'auto', background: '#ffffff' }}>
                <SectionPanel section={selected} />
            </main>
        </div>
    );
};

export default Settings;
