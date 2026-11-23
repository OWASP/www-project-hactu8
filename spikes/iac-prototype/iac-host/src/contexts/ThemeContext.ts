import { createContext, useContext } from 'react';

export type AppTheme = 'basic' | 'terminal';

export interface ThemeContextValue {
  theme: AppTheme;
  setTheme: (t: AppTheme) => void;
}

export const ThemeContext = createContext<ThemeContextValue>({
  theme: 'basic',
  setTheme: () => {},
});

export const useTheme = () => useContext(ThemeContext);
