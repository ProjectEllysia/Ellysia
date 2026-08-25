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
    // Quiz público de una campaña de Aegis: el destino del enlace del correo.
    // PÚBLICA a propósito — el destinatario no tiene cuenta y el token de la
    // query es su única identidad. Cuelga de /quiz y no de /aegis/quiz porque
    // todo lo que empieza por /aegis/ lo captura el proxy hacia Flask
    // (el matcher @api del Caddyfile, vite.config.js) y se serviría el JSON
    // de la API.
    path: '/quiz',
    name: 'Quiz',
    component: () => import('@/views/QuizView.vue'),
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
    path: '/iris/conexiones',
    name: 'IrisConnections',
    component: () => import('@/views/IrisConnectionsView.vue'),
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
  {
    path: '/hygeia',
    name: 'HygeiaHub',
    component: () => import('@/views/HygeiaHubView.vue'),
  },
  {
    path: '/hygeia/activos',
    name: 'Hygeia',
    component: () => import('@/views/HygeiaView.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/hygeia/etiquetas',
    name: 'HygeiaTags',
    component: () => import('@/views/HygeiaTagsView.vue'),
    meta: { requiresAuth: true },
  },
  // Capa comercial: planes, plan propio y organización.
  {
    // Pública: es la tabla de precios, la ve quien todavía no tiene cuenta.
    path: '/planes',
    name: 'Plans',
    component: () => import('@/views/PlansView.vue'),
  },
  {
    path: '/mi-plan',
    name: 'MyPlan',
    component: () => import('@/views/MyPlanView.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/organizacion',
    name: 'Organization',
    component: () => import('@/views/OrganizationView.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/admin/planes',
    name: 'AdminPlans',
    component: () => import('@/views/AdminPlansView.vue'),
    meta: { requiresAuth: true, requiresRoot: true },
  },
  // Aterrizajes de los enlaces de correo. PÚBLICOS a propósito: el token es la
  // única identidad, así que el enlace tiene que funcionar en el móvil donde se
  // abrió el correo, sin sesión abierta.
  {
    path: '/verificar',
    name: 'VerifyEmail',
    component: () => import('@/views/InvitationLandingView.vue'),
    props: { kind: 'verify' },
  },
  {
    path: '/invitacion',
    name: 'AcceptInvitation',
    component: () => import('@/views/InvitationLandingView.vue'),
    props: { kind: 'invitation' },
  },
  {
    // Destino del enlace de recuperación de contraseña. PÚBLICA por el mismo
    // motivo que /verificar y /quiz: el token es la única identidad. Cuelga de
    // un segmento propio y no de /users/... porque todo lo que empieza por
    // /users/ lo captura el proxy hacia Flask (mismo motivo que /quiz y
    // /usuarios).
    path: '/recuperar',
    name: 'Recover',
    component: () => import('@/views/RecoverView.vue'),
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
    path: '/logs',
    name: 'Logs',
    component: () => import('@/views/LogsView.vue'),
    meta: { requiresAuth: true, requiresAdmin: true },
  },
  {
    path: '/profile',
    name: 'Profile',
    component: () => import('@/views/ProfileView.vue'),
    meta: { requiresAuth: true },
  },
  {
    // En español a propósito, como el resto de rutas de la SPA (/planes,
    // /organizacion, /acheron/boveda...). Aquí además es obligatorio: `/users`
    // chocaba de frente con el `/users` del matcher @api de web/Caddyfile,
    // que proxea a Flask porque GET /users es un endpoint real. Una misma URL
    // no puede servir al SPA y a la API a la vez —ningún proxy puede adivinar
    // cuál de las dos—, así que al recargar la página o pegar la URL a mano
    // salía el JSON de la API (o un 401) en vez de la vista. La navegación
    // interna de vue-router no pasa por el proxy, por eso no se veía. Las
    // llamadas apiFetch('/users/...') de los stores NO cambian: esas sí son
    // la API.
    path: '/usuarios',
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

  /**
   * Vista de error genérica, conducida por el código HTTP (`/error/403`,
   * `/error/500`...). PÚBLICA a propósito: la usan los guards del router, el
   * `onError` de navegación y Caddy (el `handle_errors` del Caddyfile
   * redirige aquí los 5xx que genera él mismo), así que no puede exigir
   * sesión. El contenido lo decide `ErrorView.vue` contra
   * `views/errorCatalog.js`.
   */
  {
    path: '/error/:code(\\d{3})',
    name: 'Error',
    component: () => import('@/views/ErrorView.vue'),
  },

  /**
   * Comodín, SIEMPRE el último: vue-router resuelve por orden y una ruta
   * comodín colocada antes se tragaría todo lo que venga detrás.
   *
   * Una dirección desconocida cae aquí y se pinta la vista de error 404.
   * Sin esto, no encajaba con ninguna ruta y la SPA renderizaba un
   * `<router-view>` vacío: pantalla en blanco, sin cabecera ni pie,
   * indistinguible de un fallo de carga.
   */
  {
    path: '/:pathMatch(.*)*',
    name: 'NotFound',
    component: () => import('@/views/ErrorView.vue'),
    meta: { errorCode: 404 },
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
    if (savedPosition) return savedPosition
    if (to.hash) return { el: to.hash, top: 16 }
    return { top: 0 }
  },
})

/**
 * Guard de navegación global.
 *
 * - Si la ruta requiere auth y no hay sesión → redirige a /login.
 * - Si la ruta es de invitado (login) y ya hay sesión → redirige a la landing.
 * - Si la ruta exige un rol y la cuenta no lo tiene → /error/403 (antes caía
 *   a la portada en silencio, sin explicar nada).
 * - En cualquier otro caso, deja pasar la navegación.
 */
router.beforeEach((to) => {
  const auth = useAuthStore()
  if (to.meta.requiresAuth && !auth.isAuthenticated) {
    return { path: '/login', query: { redirect: to.fullPath } }
  } else if (to.meta.guest && auth.isAuthenticated) {
    return '/'
  } else if (to.meta.requiresRoot && !auth.isRoot) {
    return { path: '/error/403' }
  } else if (to.meta.requiresAdmin && !auth.isAdmin) {
    return { path: '/error/403' }
  }
})

/**
 * Errores de navegación (p. ej. una carga perezosa de chunk que falla tras un
 * despliegue) → vista de error 500 en vez de dejar la pantalla en blanco o la
 * vista anterior medio rota. La guarda evita el bucle si el fallo está en la
 * propia vista de error.
 */
router.onError((error) => {
  console.error('[Ellysia] Error de navegación:', error)
  const name = router.currentRoute.value.name
  if (name !== 'Error' && name !== 'NotFound') {
    router.replace({ name: 'Error', params: { code: '500' } })
  }
})

export default router
