import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import federation from '@originjs/vite-plugin-federation';

export default defineConfig({
  plugins: [
    react(),
    federation({
      name: 'iac_mfe_primary',
      filename: 'remoteEntry.js',
      exposes: {
        './StreamlitConsole': './src/components/StreamlitConsole.tsx',
        './StreamlitDashboard': './src/components/StreamlitDashboard.tsx',
        './StreamlitRegistry': './src/components/StreamlitRegistry.tsx',
      },
      shared: ['react', 'react-dom'],
    }),
  ],
  build: {
    target: 'esnext',
    minify: false,
    cssCodeSplit: false,
  },
  server: {
    port: Number(process.env.VITE_PORT) || 5173,
  },
});