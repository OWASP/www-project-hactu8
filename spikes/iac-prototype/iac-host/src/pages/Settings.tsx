
import { useState, useEffect } from 'react';
import { useFeatureFlags } from '../contexts/FeatureFlagContext';
import type { FeatureFlags } from '../config/featureFlags';
import { presets, presetDescriptions } from '../config/featureFlagPresets';
import type { PresetName } from '../config/featureFlagPresets';
import { checkHealth } from '../services/copilotService';

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
    { key: 'security', label: 'Security' },
    { key: 'keys', label: 'API Keys' },
    { key: 'notifications', label: 'Notifications' },
    { key: 'billing', label: 'Billing' },
    { key: 'features', label: 'Feature Flags' },
];

function HealthPanel() {
    const [healthChecks, setHealthChecks] = useState<HealthCheckItem[]>([
        { name: 'Copilot API', status: 'loading', message: 'Checking...' },
        { name: 'Model Configuration', status: 'loading', message: 'Checking...' },
        { name: 'Platform', status: 'loading', message: 'Checking...' },
    ]);

    useEffect(() => {
        performHealthChecks();
    }, []);

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
        const modelConfig = import.meta.env.VITE_COPILOT_MODEL || 'Not configured';
        const modelStatus: HealthStatus = modelConfig !== 'Not configured' ? 'healthy' : 'warning';
        checks.push({
            name: 'Model Configuration',
            status: modelStatus,
            message: modelConfig,
            details: modelStatus === 'healthy' ? 'Model is configured' : 'Model not set in environment',
        });

        // Check Platform
        const platform = import.meta.env.VITE_COPILOT_PLATFORM || 'OpenAI';
        const platformStatus: HealthStatus = platform ? 'healthy' : 'warning';
        checks.push({
            name: 'Platform',
            status: platformStatus,
            message: platform,
            details: `Using ${platform} for AI inference`,
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

const Settings = () => {
    const [selected, setSelected] = useState('health');

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
