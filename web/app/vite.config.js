import { defineConfig, loadEnv } from 'vite'
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
 * - Puerto 80.
 * - Proxy inverso: cualquier ruta que empiece por /oauth, /themis, etc.
 *   se redirige a la API. Esto evita CORS en desarrollo y permite que el
 *   frontend de Vue (Vite) y el backend (Flask) convivan en puertos distintos.
 *
 * Destino del proxy: por defecto Flask en local (`python run.py` → :5000).
 * Con la API en Docker el puerto publicado es el 15000, y además en Windows el
 * 5000 está en el rango reservado por el sistema y no se puede publicar. Para
 * ese caso, en `web/app/.env.local`:
 *
 *     VITE_API_TARGET=http://localhost:15000
 */
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, fileURLToPath(new URL('.', import.meta.url)), '')
  const API_TARGET = env.VITE_API_TARGET || 'http://localhost:5000'

  return {
    appType: 'spa',
    plugins: [vue()],
    resolve: {
      alias: {
        '@': fileURLToPath(new URL('./src', import.meta.url))
      }
    },
    server: {
      port: 80,
      proxy: {
        '/oauth':     { target: API_TARGET, changeOrigin: true },
        '/themis':    { target: API_TARGET, changeOrigin: true, bypass: proxyBypass },
        '/aegis':     { target: API_TARGET, changeOrigin: true, bypass: proxyBypass },
        '/users':     { target: API_TARGET, changeOrigin: true, bypass: proxyBypass },
        '/system':    { target: API_TARGET, changeOrigin: true },
        '/acheron':   { target: API_TARGET, changeOrigin: true, bypass: proxyBypass },
        '/iris':      { target: API_TARGET, changeOrigin: true, bypass: proxyBypass },
        '/hygeia':    { target: API_TARGET, changeOrigin: true, bypass: proxyBypass },
        // Capa comercial. Van con bypass porque comparten prefijo con rutas del
        // SPA: /plans es la API pero /planes es la tabla de precios, y
        // /organizations es la API mientras que /organizacion es la vista. El
        // castellano de las rutas del front evita casi toda colisión, pero el
        // bypass la cierra del todo.
        '/plans':         { target: API_TARGET, changeOrigin: true, bypass: proxyBypass },
        '/organizations': { target: API_TARGET, changeOrigin: true, bypass: proxyBypass },
      },
      allowedHosts: ['dev.local.ellysia.es'],
    }
  }
})

// Sub-rutas del frontend (vista "workspace" de cada módulo, servida bajo el
// hub) que comparten prefijo con la API real (p. ej. /themis/stats) pero no
// son endpoints — deben caer en el SPA, no en el proxy hacia Flask.
const FRONTEND_SUBROUTES = new Set([
  '/themis/escaneos',
  '/aegis/generador',
  '/aegis/campanas',
  '/iris/analisis',
  '/iris/conexiones',
  '/acheron/boveda',
  '/hygeia/activos',
  '/hygeia/etiquetas',
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
