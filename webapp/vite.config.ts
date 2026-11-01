import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    // Standardized webapp port — matches the standard docker-compose.yml
    // (UNM_WEB_PORT) and docker-compose.dev.yml so "the URL" is always :8080.
    port: 8080,
    proxy: {
      // The API base defaults to the RELATIVE "/v1" (same-origin — see
      // webapp/src/api/client.ts). In dev the browser talks to this vite
      // server on :8080 while the API runs host-side on :3000, so forward /v1
      // there. `ws: true` also upgrades the SSH console WebSocket
      // (ws://localhost:8080/v1/devices/:id/console/ws).
      '/v1': { target: 'http://localhost:3000', ws: true },
    },
  },
});
