import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import federation from '@originjs/vite-plugin-federation';

const timestamp = Date.now();

// The dev server uses the API's certificate (hactu8/tls.py): HACTU8_TLS_CERT / HACTU8_TLS_KEY if set,
// else the self-signed pair in HACTU8_TLS_DIR (default ~/.hactu8/tls). HACTU8_TLS=off serves HTTP.
const tlsOff = ['off', '0', 'false', 'no'].includes((process.env.HACTU8_TLS || 'on').trim().toLowerCase());
if (tlsOff) {
  // The API is plain HTTP too, unless VITE_HACTU8_API_URL says otherwise.
  process.env.VITE_HACTU8_API_URL ||= 'http://127.0.0.1:8000';
}

function devHttps() {
  if (tlsOff) return undefined;
  const dir = process.env.HACTU8_TLS_DIR ? resolve(process.env.HACTU8_TLS_DIR) : join(homedir(), '.hactu8', 'tls');
  const cert = process.env.HACTU8_TLS_CERT || join(dir, 'cert.pem');
  const key = process.env.HACTU8_TLS_KEY || join(dir, 'key.pem');
  if (!existsSync(cert) || !existsSync(key)) {
    throw new Error(`No TLS certificate at ${cert}. Run "python -m hactu8.tls" (or start the API once) ` +
      'to create it, or set HACTU8_TLS=off for plain HTTP.');
  }
  return { cert: readFileSync(cert), key: readFileSync(key) };
}

export default defineConfig(({ command }) => ({
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
    https: command === 'serve' ? devHttps() : undefined,
    proxy: {
      '/api/copilot': {
        target: process.env.VITE_COPILOT_PROXY_TARGET || 'http://localhost:3000',
        changeOrigin: true,
      },
    },
  },
}));
