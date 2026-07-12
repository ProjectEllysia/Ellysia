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
 * - Proxy inverso: cualquier ruta que empiece por /oauth, /themis, etc.
 *   se redirige a Flask en :5000. Esto evita CORS en desarrollo y permite
 *   que el frontend de Vue (Vite) y el backend (Flask) convivan en puertos
 *   distintos.
 */
export default defineConfig({
  appType: 'spa',
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
      '/themis':    { target: 'http://localhost:5000', changeOrigin: true, bypass: proxyBypass },
      '/aegis':     { target: 'http://localhost:5000', changeOrigin: true, bypass: proxyBypass },
      '/users':     { target: 'http://localhost:5000', changeOrigin: true, bypass: proxyBypass },
      '/system':    { target: 'http://localhost:5000', changeOrigin: true },
      '/acheron':   { target: 'http://localhost:5000', changeOrigin: true, bypass: proxyBypass },
      '/iris':      { target: 'http://localhost:5000', changeOrigin: true, bypass: proxyBypass },
    }
  }
})

// Sub-rutas del frontend (vista "workspace" de cada módulo, servida bajo el
// hub) que comparten prefijo con la API real (p. ej. /themis/stats) pero no
// son endpoints — deben caer en el SPA, no en el proxy hacia Flask.
const FRONTEND_SUBROUTES = new Set([
  '/themis/escaneos',
  '/aegis/generador',
  '/iris/analisis',
  '/acheron/boveda',
])

function proxyBypass(req) {
  const url = req.url.split('?')[0]
  if (req.method !== 'GET') return
  // Solo bypassear navegaciones reales de página (el usuario carga la URL
  // en el navegador). Sin esto, un fetch() en AJAX a una ruta de un solo
  // segmento que también es un endpoint real (p.ej. GET /users, la lista
  // de usuarios) se confundía con una navegación a la página /users y
  // recibía el index.html de la SPA en vez del JSON — "Unexpected token '<'".
  if (req.headers['sec-fetch-dest'] !== 'document') return
  if (/\.\w+$/.test(url)) return
  if (/^\/[^/]+\/?$/.test(url)) return '/'
  if (FRONTEND_SUBROUTES.has(url)) return '/'
}
