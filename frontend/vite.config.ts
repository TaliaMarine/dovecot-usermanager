import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import vuetify from 'vite-plugin-vuetify'

export default defineConfig({
  plugins: [vue(), vuetify({ autoImport: true })],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: {
    // Backend on :8080 in dev (go run ./cmd/usermanager); same origin in production.
    proxy: { '/api': 'http://localhost:8080' },
  },
  build: { outDir: 'dist' },
})
