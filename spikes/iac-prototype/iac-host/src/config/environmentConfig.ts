// src/config/environmentConfig.ts

export type Environment = 'development' | 'test' | 'staging' | 'production' | 'local';

export interface EnvironmentConfig {
  name: Environment;
  displayName: string;
  message: string;
  messageType: 'info' | 'warning' | 'error' | 'success';
  navbarColor: string;
  navbarTextColor: string;
  showOnLoad: boolean;
}

// Environment configurations
export const environmentConfigs: Record<Environment, EnvironmentConfig> = {
  development: {
    name: 'development',
    displayName: 'Development',
    message: 'Running in Development Environment',
    messageType: 'success',
    navbarColor: '#d1fae5', // Light green
    navbarTextColor: '#065f46', // Dark green
    showOnLoad: true,
  },
  test: {
    name: 'test',
    displayName: 'Test',
    message: 'Running in Test Environment',
    messageType: 'warning',
    navbarColor: '#fef3c7', // Light yellow
    navbarTextColor: '#92400e', // Dark orange
    showOnLoad: true,
  },
  staging: {
    name: 'staging',
    displayName: 'Staging',
    message: 'Running in Staging Environment - Use with caution',
    messageType: 'warning',
    navbarColor: '#fed7aa', // Light orange
    navbarTextColor: '#7c2d12', // Dark orange
    showOnLoad: true,
  },
  production: {
    name: 'production',
    displayName: 'Production',
    message: 'Production Environment',
    messageType: 'error',
    navbarColor: '#fee2e2', // Light red
    navbarTextColor: '#991b1b', // Dark red
    showOnLoad: true,
  },
  local: {
    name: 'local',
    displayName: 'Local',
    message: 'Running on Local Machine',
    messageType: 'info',
    navbarColor: '#dbeafe', // Light blue
    navbarTextColor: '#1e40af', // Dark blue
    showOnLoad: true,
  },
};

// Detect current environment
export const getCurrentEnvironment = (): Environment => {
  // Check environment variable first
  const envVar = import.meta.env.VITE_APP_ENV as Environment;
  if (envVar && envVar in environmentConfigs) {
    return envVar;
  }

  // Check hostname
  const hostname = window.location.hostname;

  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    return 'local';
  }

  if (hostname.includes('dev.') || hostname.includes('-dev.')) {
    return 'development';
  }

  if (hostname.includes('test.') || hostname.includes('-test.')) {
    return 'test';
  }

  if (hostname.includes('staging.') || hostname.includes('-staging.')) {
    return 'staging';
  }

  if (hostname.includes('prod.') || hostname.includes('-prod.') ||
      import.meta.env.PROD) {
    return 'production';
  }

  // Default to local for development
  return import.meta.env.DEV ? 'local' : 'production';
};

// Get current environment configuration
export const getEnvironmentConfig = (): EnvironmentConfig => {
  const env = getCurrentEnvironment();
  return environmentConfigs[env];
};

// Allow override via localStorage (for testing/demos)
export const setEnvironmentOverride = (env: Environment): void => {
  localStorage.setItem('environmentOverride', env);
  window.location.reload();
};

export const getEnvironmentOverride = (): Environment | null => {
  const override = localStorage.getItem('environmentOverride');
  return override && override in environmentConfigs ? (override as Environment) : null;
};

export const clearEnvironmentOverride = (): void => {
  localStorage.removeItem('environmentOverride');
  window.location.reload();
};

// Get effective environment (override or detected)
export const getEffectiveEnvironment = (): Environment => {
  return getEnvironmentOverride() || getCurrentEnvironment();
};

// Get effective configuration
export const getEffectiveConfig = (): EnvironmentConfig => {
  const env = getEffectiveEnvironment();
  return environmentConfigs[env];
};
