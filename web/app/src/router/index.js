import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/authStore'

/**
 * Configuración de rutas de la SPA.
 *
 * Cada ruta corresponde a una vista (página) que se carga bajo demanda
 * mediante lazy loading (`() => import(...)`). El guard de navegación
 * (`beforeEach`) protege las rutas que requieren autenticación y redirige
 * al dashboard si el usuario ya está logueado e intenta ir al login.
 *
 * @type {import('vue-router').RouteRecordRaw[]}
 */
const routes = [
  {
    path: '/',
    name: 'Landing',
    component: () => import('@/views/LandingView.vue'),
    // Pública: es la portada de ellysia.es. Si hay sesión, muestra los
    // accesos directos a las herramientas; si no, invita a entrar.
  },
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/LoginView.vue'),
    meta: { guest: true },
  },
  // Hubs de módulo: PÚBLICOS. Son la carta de presentación de cada herramienta
  // — quien busca "Acheron" aterriza aquí sin login. La herramienta de trabajo
  // (subruta) sí requiere sesión.
  {
    path: '/themis',
    name: 'ThemisHub',
    component: () => import('@/views/ThemisHubView.vue'),
  },
  {
    path: '/themis/escaneos',
    name: 'Themis',
    component: () => import('@/views/ThemisView.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/aegis',
    name: 'AegisHub',
    component: () => import('@/views/AegisHubView.vue'),
  },
  {
    path: '/aegis/generador',
    name: 'Aegis',
    component: () => import('@/views/AegisView.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/iris',
    name: 'IrisHub',
    component: () => import('@/views/IrisHubView.vue'),
  },
  {
    path: '/iris/analisis',
    name: 'Iris',
    component: () => import('@/views/IrisView.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/acheron',
    name: 'AcheronHub',
    component: () => import('@/views/AcheronHubView.vue'),
  },
  {
    path: '/acheron/boveda',
    name: 'Acheron',
    component: () => import('@/views/AcheronView.vue'),
    meta: { requiresAuth: true },
  },
  // Páginas informativas públicas (enlazadas desde el pie).
  {
    path: '/sobre',
    name: 'Sobre',
    component: () => import('@/views/AboutView.vue'),
  },
  {
    path: '/privacidad',
    name: 'Privacidad',
    component: () => import('@/views/PrivacyView.vue'),
  },
  {
    path: '/terminos',
    name: 'Terminos',
    component: () => import('@/views/TermsView.vue'),
  },
  // Documentación (enlazada desde el desplegable "Documentación" del header
  // de la landing). Misma vista genérica para ambas — el contenido real se
  // irá rellenando; de momento son placeholders.
  {
    path: '/docs/uso',
    name: 'DocsUsage',
    component: () => import('@/views/DocsPlaceholderView.vue'),
    meta: {
      docTitle: 'Documentación de uso',
      docIntro: 'Guías paso a paso para sacar partido a cada herramienta de Ellysia: lanzar un escaneo en Themis, generar una píldora en Aegis, analizar un correo en Iris o guardar una credencial en Acheron.',
    },
  },
  {
    path: '/docs/tecnica',
    name: 'DocsTechnical',
    component: () => import('@/views/DocsPlaceholderView.vue'),
    meta: {
      docTitle: 'Documentación técnica',
      docIntro: 'Referencia técnica de la API, la arquitectura interna y los modelos de datos de Ellysia, pensada para quien integra o extiende la plataforma.',
    },
  },
  {
    path: '/config',
    name: 'Config',
    component: () => import('@/views/ConfigView.vue'),
    // S12: ConfigView llama a GET/PUT /system, root-only desde S7 — el guard
    // del cliente es defensa en profundidad (la API ya rechaza con 403;
    // esto evita cargar la vista para un admin que de todos modos rebotará).
    meta: { requiresAuth: true, requiresRoot: true },
  },
  {
    path: '/profile',
    name: 'Profile',
    component: () => import('@/views/ProfileView.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/users',
    name: 'Users',
    component: () => import('@/views/UsersView.vue'),
    meta: { requiresAuth: true, requiresAdmin: true },
  },
  {
    path: '/queue',
    name: 'Queue',
    component: () => import('@/views/QueueView.vue'),
    meta: { requiresAuth: true },
  },
]

/**
 * Instancia del router con historial HTML5 (sin # en las URLs).
 * Usa createWebHistory para rutas limpias: /, /themis, etc.
 */
const router = createRouter({
  history: createWebHistory(),
  routes,
  /**
   * Sin esto, al ser una SPA, el scroll Y se queda donde estaba: si vienes
   * de un footer o de una estela al fondo de la landing, aterrizas a media
   * página nueva en vez de en su hero. Con atrás/adelante del navegador sí
   * queremos restaurar la posición donde estabas (savedPosition).
   */
  scrollBehavior(to, from, savedPosition) {
    return savedPosition || { top: 0 }
  },
})

/**
 * Guard de navegación global.
 *
 * - Si la ruta requiere auth y no hay sesión → redirige a /login.
 * - Si la ruta es de invitado (login) y ya hay sesión → redirige a la landing.
 * - En cualquier otro caso, deja pasar la navegación.
 */
router.beforeEach((to) => {
  const auth = useAuthStore()
  if (to.meta.requiresAuth && !auth.isAuthenticated) {
    return { path: '/login', query: { redirect: to.fullPath } }
  } else if (to.meta.guest && auth.isAuthenticated) {
    return '/'
  } else if (to.meta.requiresRoot && !auth.isRoot) {
    return '/'
  } else if (to.meta.requiresAdmin && !auth.isAdmin) {
    return '/'
  }
})

export default router
