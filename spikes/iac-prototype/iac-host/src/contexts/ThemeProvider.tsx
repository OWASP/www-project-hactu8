import React, { useState } from 'react';
import { ThemeContext } from './ThemeContext';
import type { AppTheme } from './ThemeContext';

const THEME_KEY = 'iac-theme';

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [theme, setThemeState] = useState<AppTheme>(() => {
    return (localStorage.getItem(THEME_KEY) as AppTheme) || 'basic';
  });

  const setTheme = (t: AppTheme) => {
    localStorage.setItem(THEME_KEY, t);
    setThemeState(t);
  };

  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
};
