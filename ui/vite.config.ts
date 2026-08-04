import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// In Docker Compose the API lives at http://api:8000 on the compose network;
// locally (npm run dev on the host) it's http://localhost:8000.
const apiTarget = process.env.VITE_API_PROXY_TARGET ?? 'http://localhost:8000'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: true,
    proxy: {
      '/api': apiTarget,
      '/health': apiTarget,
    },
  },
})
