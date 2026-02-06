import React, { useState, useCallback } from 'react';
import type { InstalledExtension, ExtensionSettingDefinition } from '../../types/extensions';

interface ExtensionSettingsProps {
  extension: InstalledExtension;
  onSave: (extensionId: string, settings: Record<string, string | number | boolean>) => void;
}

/**
 * Schema-driven settings form for a single extension.
 * Renders form controls based on manifest.settings definitions.
 */
const ExtensionSettings: React.FC<ExtensionSettingsProps> = ({ extension, onSave }) => {
  const definitions = extension.manifest.settings ?? [];
  const [values, setValues] = useState<Record<string, string | number | boolean>>(
    () => ({ ...extension.settings })
  );
  const [dirty, setDirty] = useState(false);

  const handleChange = useCallback((key: string, value: string | number | boolean) => {
    setValues((prev) => ({ ...prev, [key]: value }));
    setDirty(true);
  }, []);

  const handleSave = useCallback(() => {
    onSave(extension.manifest.id, values);
    setDirty(false);
  }, [extension.manifest.id, values, onSave]);

  const handleReset = useCallback(() => {
    const defaults: Record<string, string | number | boolean> = {};
    for (const def of definitions) {
      defaults[def.key] = def.default;
    }
    setValues(defaults);
    setDirty(true);
  }, [definitions]);

  if (definitions.length === 0) {
    return (
      <div style={containerStyle}>
        <p style={{ color: '#888' }}>This extension has no configurable settings.</p>
      </div>
    );
  }

  return (
    <div style={containerStyle}>
      <h4 style={{ margin: '0 0 1rem' }}>Settings — {extension.manifest.name}</h4>

      {definitions.map((def) => (
        <SettingField
          key={def.key}
          definition={def}
          value={values[def.key] ?? def.default}
          onChange={handleChange}
        />
      ))}

      <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1.5rem' }}>
        <button onClick={handleSave} disabled={!dirty} style={saveButtonStyle(dirty)}>
          Save
        </button>
        <button onClick={handleReset} style={resetButtonStyle}>
          Reset to Defaults
        </button>
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Individual setting field renderer
// ---------------------------------------------------------------------------

interface SettingFieldProps {
  definition: ExtensionSettingDefinition;
  value: string | number | boolean;
  onChange: (key: string, value: string | number | boolean) => void;
}

const SettingField: React.FC<SettingFieldProps> = ({ definition, value, onChange }) => {
  const { key, label, description, type, options } = definition;

  return (
    <div style={fieldContainerStyle}>
      <label style={labelStyle} htmlFor={`ext-setting-${key}`}>
        {label}
        {definition.required && <span style={{ color: '#ef4444' }}> *</span>}
      </label>
      {description && <p style={descriptionStyle}>{description}</p>}

      {type === 'boolean' && (
        <input
          id={`ext-setting-${key}`}
          type="checkbox"
          checked={Boolean(value)}
          onChange={(e) => onChange(key, e.target.checked)}
          style={{ marginTop: '0.25rem' }}
        />
      )}

      {type === 'string' && (
        <input
          id={`ext-setting-${key}`}
          type="text"
          value={String(value)}
          onChange={(e) => onChange(key, e.target.value)}
          style={inputStyle}
        />
      )}

      {type === 'number' && (
        <input
          id={`ext-setting-${key}`}
          type="number"
          value={Number(value)}
          onChange={(e) => onChange(key, parseFloat(e.target.value) || 0)}
          style={inputStyle}
        />
      )}

      {type === 'select' && options && (
        <select
          id={`ext-setting-${key}`}
          value={String(value)}
          onChange={(e) => onChange(key, e.target.value)}
          style={inputStyle}
        >
          {options.map((opt) => (
            <option key={String(opt.value)} value={String(opt.value)}>
              {opt.label}
            </option>
          ))}
        </select>
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const containerStyle: React.CSSProperties = {
  padding: '1rem',
};

const fieldContainerStyle: React.CSSProperties = {
  marginBottom: '1rem',
};

const labelStyle: React.CSSProperties = {
  display: 'block',
  fontWeight: 600,
  fontSize: '0.9rem',
  marginBottom: '0.15rem',
  color: 'var(--iac-text, #ccc)',
};

const descriptionStyle: React.CSSProperties = {
  margin: '0 0 0.35rem',
  fontSize: '0.8rem',
  color: '#888',
};

const inputStyle: React.CSSProperties = {
  display: 'block',
  width: '100%',
  maxWidth: '400px',
  padding: '0.4rem 0.5rem',
  borderRadius: '4px',
  border: '1px solid var(--iac-border, #333)',
  backgroundColor: 'var(--iac-surface, #1a1a2e)',
  color: 'var(--iac-text, #ccc)',
  fontSize: '0.875rem',
};

const saveButtonStyle = (dirty: boolean): React.CSSProperties => ({
  padding: '0.5rem 1.5rem',
  backgroundColor: dirty ? 'var(--iac-accent, #b1d0dd)' : '#555',
  color: dirty ? 'var(--iac-primary, #213547)' : '#999',
  border: 'none',
  borderRadius: '4px',
  cursor: dirty ? 'pointer' : 'default',
  fontWeight: 600,
});

const resetButtonStyle: React.CSSProperties = {
  padding: '0.5rem 1.5rem',
  backgroundColor: 'transparent',
  color: 'var(--iac-text, #ccc)',
  border: '1px solid var(--iac-border, #333)',
  borderRadius: '4px',
  cursor: 'pointer',
};

export default ExtensionSettings;
