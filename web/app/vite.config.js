import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath, URL } from 'node:url'

/**
 * Configuración de Vite para la SPA de Ellysia.
 *
 * Plugins:
 * - @vitejs/plugin-vue: compila archivos .vue (SFC).
 *
 * Resolve:
 * - Alias `@` → directorio `src/` para imports limpios.
 *
 * Server (solo desarrollo):
 * - Puerto 5173.
 * - Proxy inverso: cualquier ruta que empiece por /oauth, /sentinel, etc.
 *   se redirige a Flask en :5000. Esto evita CORS en desarrollo y permite
 *   que el frontend de Vue (Vite) y el backend (Flask) convivan en puertos
 *   distintos.
 */
export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    }
  },
  server: {
    port: 5173,
    proxy: {
      '/oauth':     { target: 'http://localhost:5000', changeOrigin: true },
      '/sentinel':  { target: 'http://localhost:5000', changeOrigin: true },
      '/aegis':     { target: 'http://localhost:5000', changeOrigin: true },
      '/users':     { target: 'http://localhost:5000', changeOrigin: true },
      '/system':    { target: 'http://localhost:5000', changeOrigin: true },
      '/acheron':   { target: 'http://localhost:5000', changeOrigin: true },
      '/iris':      { target: 'http://localhost:5000', changeOrigin: true },
    }
  }
})
