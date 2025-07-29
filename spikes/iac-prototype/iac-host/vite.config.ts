import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import federation from '@originjs/vite-plugin-federation';

const timestamp = Date.now();

export default defineConfig({
  plugins: [
    react(),
    federation({
      remotes: {
        iac_mfe_primary: `http://localhost:3001/assets/remoteEntry.js?t=${timestamp}`,
      },
      shared: ['react', 'react-dom'],
    }),
  ],
  server: {
    port: Number(process.env.VITE_PORT) || 5173,
  },
});