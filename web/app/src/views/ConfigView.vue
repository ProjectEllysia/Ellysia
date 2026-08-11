<template>
  <div class="config-page">
    <StarBackground />
    <Topbar title="Configuración" />

    <main class="main">
      <div v-if="store.loading" class="loading-block">
        <div class="skeleton skeleton--lg"></div>
      </div>

      <div v-else class="config-layout">
        <div class="config-nav-column">
          <aside class="config-nav">
            <nav>
              <template v-for="g in navGroups" :key="g.label">
                <span class="nav-group-label">{{ g.label }}</span>
                <a v-for="s in g.items" :key="s.id"
                  :class="['nav-link', { active: activeSection === s.id }]"
                  href="#" @click.prevent="scrollTo(s.id)">
                  <span class="nav-icon" v-html="s.icon"></span>
                  <span class="nav-label">{{ s.label }}</span>
                </a>
              </template>
            </nav>
          </aside>
        </div>

        <form class="config-form" @submit.prevent="handleSave">
          <section id="section-general" class="section">
            <div class="section-head section-head--row">
              <div><h2>General</h2><p class="section-desc">Directorios del sistema y alta de cuentas</p></div>
              <span class="version-chip" title="Versión de la aplicación">v{{ store.configFlat['appVersion'] }}</span>
            </div>
            <div class="section-body">
              <div class="cfg-grid">
                <div class="form-group"><label>Temp</label><input v-model="store.configFlat['general.directories.tempdir']" type="text" class="inp" /></div>
                <div class="form-group"><label>Logs</label><input v-model="store.configFlat['general.directories.logdir']" type="text" class="inp" /></div>
              </div>
              <p class="field-hint">Con el registro abierto, cualquiera puede crearse una cuenta desde la pantalla de acceso y estrenará el plan gratuito. En un despliegue interno lo normal es cerrarlo y dar de alta a la gente desde Usuarios.</p>
              <div class="cfg-grid">
                <div class="form-group">
                  <label>Registro público</label>
                  <select v-model="store.configFlat['general.registration.enabled']" class="inp">
                    <option :value="true">Abierto</option>
                    <option :value="false">Cerrado</option>
                  </select>
                </div>
                <div class="form-group">
                  <label>Vigencia del enlace de verificación (horas)</label>
                  <input v-model.number="store.configFlat['general.registration.verificationTtlHours']" type="number" min="1" max="720" class="inp" />
                </div>
                <div class="form-group">
                  <label>Vigencia de la invitación a una organización (horas)</label>
                  <input v-model.number="store.configFlat['general.registration.invitationTtlHours']" type="number" min="1" max="2160" class="inp" />
                </div>
              </div>
            </div>
          </section>

          <section id="section-security" class="section">
            <div class="section-head"><h2>Seguridad</h2><p class="section-desc">Hashing de contraseñas (Argon2id)</p></div>
            <div class="section-body">
              <p class="field-hint">Parámetros de coste de Argon2id. Subirlos endurece los hashes pero ralentiza el inicio de sesión. Solo afectan a contraseñas creadas o cambiadas tras guardar.</p>
              <div class="cfg-grid">
                <div class="form-group"><label>Iteraciones (time cost)</label><input v-model.number="store.configFlat['general.security.argon2.time_cost']" type="number" min="1" max="20" class="inp" /></div>
                <div class="form-group"><label>Memoria (KiB)</label><input v-model.number="store.configFlat['general.security.argon2.memory_cost']" type="number" min="8192" step="1024" class="inp" /><span class="field-hint">65536 KiB = 64 MiB por hash</span></div>
                <div class="form-group"><label>Paralelismo (hilos)</label><input v-model.number="store.configFlat['general.security.argon2.parallelism']" type="number" min="1" max="16" class="inp" /></div>
              </div>
            </div>
          </section>

          <section id="section-database" class="section">
            <div class="section-head"><h2>Base de datos</h2><p class="section-desc">Conexión PostgreSQL y pool de conexiones</p></div>
            <div class="section-body">
              <p class="field-hint">Las credenciales viven en el archivo <code>.env</code>. Estos ajustes requieren reiniciar la API para aplicarse.</p>
              <div class="cfg-grid">
                <div class="form-group"><label>Nivel de aislamiento</label>
                  <select v-model="store.configFlat['infrastructure.database.isolation_level']" class="inp sel">
                    <option v-for="lvl in isolationLevels" :key="lvl" :value="lvl">{{ lvl }}</option>
                  </select>
                </div>
                <div class="form-group"><label>Tamaño del pool</label><input v-model.number="store.configFlat['infrastructure.database.pool_size']" type="number" min="1" max="100" class="inp" /></div>
                <div class="form-group"><label>Conexiones extra (overflow)</label><input v-model.number="store.configFlat['infrastructure.database.max_overflow']" type="number" min="0" max="100" class="inp" /></div>
                <div class="form-group"><label>Timeout del pool (s)</label><input v-model.number="store.configFlat['infrastructure.database.pool_timeout']" type="number" min="1" max="300" class="inp" /></div>
              </div>
            </div>
          </section>

          <section id="section-redis" class="section">
            <div class="section-head"><h2>Redis</h2><p class="section-desc">Backend de la cola de tareas</p></div>
            <div class="section-body">
              <p class="field-hint">La contraseña se toma de <code>REDIS_PASSWORD</code> en <code>.env</code>. En contenedores, las variables <code>REDIS_HOST</code> / <code>REDIS_PORT</code> / <code>REDIS_DB</code> tienen prioridad sobre estos valores.</p>
              <div class="cfg-grid">
                <div class="form-group"><label>Host</label><input v-model="store.configFlat['infrastructure.redis.host']" type="text" class="inp mono" /></div>
                <div class="form-group"><label>Puerto</label><input v-model.number="store.configFlat['infrastructure.redis.port']" type="number" min="1" max="65535" class="inp" /></div>
                <div class="form-group"><label>Base de datos (db)</label><input v-model.number="store.configFlat['infrastructure.redis.db']" type="number" min="0" max="15" class="inp" /></div>
                <div class="form-group"><label>Timeout de conexión (s)</label><input v-model.number="store.configFlat['infrastructure.redis.socket_connect_timeout']" type="number" min="1" max="60" class="inp" /></div>
              </div>
            </div>
          </section>

          <section id="section-taskqueue" class="section">
            <div class="section-head"><h2>TaskQueue</h2><p class="section-desc">Cola de tareas en segundo plano</p></div>
            <div class="section-body">
              <div class="cfg-grid">
                <div class="form-group"><label>Max Workers</label><input v-model.number="store.configFlat['infrastructure.taskqueue.max_workers']" type="number" min="1" max="32" class="inp" /></div>
                <div class="form-group"><label>Historial TTL (s)</label><input v-model.number="store.configFlat['infrastructure.taskqueue.history_ttl_seconds']" type="number" min="60" max="86400" class="inp" /></div>
                <div class="form-group"><label>Max items en historial</label><input v-model.number="store.configFlat['infrastructure.taskqueue.history_max_items']" type="number" min="10" max="1000" class="inp" /></div>
              </div>
            </div>
          </section>

          <section id="section-ai" class="section">
            <div class="section-head"><h2>IA</h2><p class="section-desc">Estrategia de los modelos de lenguaje por módulo</p></div>
            <div class="section-body">
              <p class="field-hint">Elige qué proveedor genera el contenido de cada módulo. Las credenciales y los modelos se configuran en <code>.env</code> (<code>OLLAMA_*</code>, <code>OPENAI_*</code>).</p>
              <div class="cfg-grid">
                <div class="form-group"><label>Estrategia por defecto</label>
                  <select v-model="store.configFlat['tools.scribe.defaultStrategy']" class="inp sel">
                    <option v-for="s in aiStrategies" :key="s.value" :value="s.value">{{ s.label }}</option>
                  </select>
                </div>
                <div class="form-group"><label>Themis</label>
                  <select v-model="store.configFlat['tools.scribe.modules.themis']" class="inp sel">
                    <option v-for="s in aiStrategies" :key="s.value" :value="s.value">{{ s.label }}</option>
                  </select>
                </div>
                <div class="form-group"><label>Aegis</label>
                  <select v-model="store.configFlat['tools.scribe.modules.aegis']" class="inp sel">
                    <option v-for="s in aiStrategies" :key="s.value" :value="s.value">{{ s.label }}</option>
                  </select>
                </div>
              </div>
            </div>
          </section>

          <section id="section-iris" class="section">
            <div class="section-head"><h2>Iris</h2><p class="section-desc">Umbrales de análisis de cabeceras de correo</p></div>
            <div class="section-body">
              <p class="field-hint">Puntuación de autenticidad de un correo. Por encima del umbral legítimo se considera fiable; por debajo del sospechoso, una amenaza. El umbral sospechoso puede ser negativo.</p>
              <div class="cfg-grid">
                <div class="form-group"><label>Umbral legítimo</label><input v-model.number="store.configFlat['features.iris.legitimateThreshold']" type="number" class="inp" /></div>
                <div class="form-group"><label>Umbral sospechoso</label><input v-model.number="store.configFlat['features.iris.suspiciousThreshold']" type="number" class="inp" /></div>
                <div class="form-group"><label>Cabeceras mínimas</label><input v-model.number="store.configFlat['features.iris.minHeaders']" type="number" min="0" max="50" class="inp" /></div>
                <div class="form-group"><label>Tamaño máx. del mensaje (bytes)</label><input v-model.number="store.configFlat['features.iris.maxMessageBytes']" type="number" min="1024" step="1024" class="inp" /><span class="field-hint">10485760 = 10 MiB</span></div>
              </div>
            </div>
          </section>

          <section id="section-themis" class="section">
            <div class="section-head"><h2>Themis</h2><p class="section-desc">Escáner de red, análisis web y vulnerabilidades</p></div>
            <div class="section-body">
              <div class="cfg-row"><label class="toggle-row"><input v-model="store.configFlat['features.themis.enabled']" type="checkbox" class="toggle" /><span>Habilitado</span></label></div>
              <div class="cfg-grid">
                <div class="form-group"><label>Directorio de salida (PDFs)</label><input v-model="store.configFlat['features.themis.directories.output']" type="text" class="inp" /></div>
                <div class="form-group"><label>Directorio CSV</label><input v-model="store.configFlat['features.themis.directories.csv']" type="text" class="inp" /></div>
                <div class="form-group"><label>Directorio de recursos</label><input v-model="store.configFlat['features.themis.directories.resources']" type="text" class="inp" /></div>
              </div>
              <div class="cfg-row"><label class="toggle-row"><input v-model="store.configFlat['features.themis.areLocalIpsAllowed']" type="checkbox" class="toggle" /><span>Permitir IPs locales</span></label></div>
              <div class="cfg-grid">
                <div class="form-group"><label>Carpeta por defecto</label><input v-model="store.configFlat['features.themis.folders.defaultFolderName']" type="text" class="inp" /><span class="field-hint">Nombre de la carpeta virtual para escaneos sin agrupar</span></div>
                <div class="form-group"><label>Escaneos en estadísticas</label><input v-model.number="store.configFlat['features.themis.history.maxScans']" type="number" min="1" max="100" class="inp" /><span class="field-hint">Escaneos recientes que se promedian en el histórico</span></div>
              </div>
              <h3 class="subsection-title">Verificación de accesibilidad del host</h3>
              <div class="cfg-grid">
                <div class="form-group"><label class="toggle-row"><input v-model="store.configFlat['features.themis.hostReachabilityCheck.enabled']" type="checkbox" class="toggle" /><span>Habilitado</span></label></div>
                <div class="form-group"><label>Timeout (s)</label><input v-model.number="store.configFlat['features.themis.hostReachabilityCheck.timeout']" type="number" step="0.5" min="0.5" class="inp" /></div>
                <div class="form-group"><label>Puerto</label><input v-model.number="store.configFlat['features.themis.hostReachabilityCheck.port']" type="number" min="1" max="65535" class="inp" /></div>
              </div>
              <h3 class="subsection-title">Traceroute</h3>
              <div class="cfg-grid">
                <div class="form-group"><label>Validez de caché (h)</label><input v-model.number="store.configFlat['features.themis.traceroute.cacheHours']" type="number" min="1" max="720" class="inp" /></div>
                <div class="form-group"><label>Saltos máximos</label><input v-model.number="store.configFlat['features.themis.traceroute.maxHops']" type="number" min="1" max="64" class="inp" /></div>
                <div class="form-group"><label>Timeout (s)</label><input v-model.number="store.configFlat['features.themis.traceroute.timeout']" type="number" min="1" max="600" class="inp" /></div>
                <div class="form-group"><label>Reintento si falla (min)</label><input v-model.number="store.configFlat['features.themis.traceroute.retryFailedMinutes']" type="number" min="1" max="1440" class="inp" /></div>
              </div>
            </div>
            <div class="scanner-grid">
              <ScannerCard name="Nmap" icon="scan" :flat="store.configFlat" prefix="features.themis.scanners.nmap" />
              <ScannerCard name="Nikto" icon="web" :flat="store.configFlat" prefix="features.themis.scanners.nikto" />
            </div>
          </section>

          <section id="section-aegis" class="section">
            <div class="section-head"><h2>Aegis</h2><p class="section-desc">Generación de píldoras de concienciación con IA</p></div>
            <div class="section-body">
              <div class="cfg-row"><label class="toggle-row"><input v-model="store.configFlat['features.aegis.enabled']" type="checkbox" class="toggle" /><span>Habilitado</span></label></div>
              <div class="cfg-grid">
                <div class="form-group"><label>Consejos por píldora</label><input v-model.number="store.configFlat['features.aegis.tipsAmount']" type="number" min="1" max="20" class="inp" /></div>
                <div class="form-group"><label>Antigüedad máx. de alertas (años)</label><input v-model.number="store.configFlat['features.aegis.vulnerabilitiesAntiquity']" type="number" min="1" max="30" class="inp" /></div>
              </div>
              <div class="grid">
                <div class="form-group"><label>Directorio de salida</label><input v-model="store.configFlat['features.aegis.directories.output']" type="text" class="inp" /></div>
                <div class="form-group"><label>Stack de documentos</label><input v-model="store.configFlat['features.aegis.directories.stack']" type="text" class="inp" /></div>
              </div>
              <h3 class="subsection-title">Prompt del sistema</h3>
              <textarea v-model="store.configFlat['features.aegis.prompts.system']" rows="10" class="txta"></textarea>
              <h3 class="subsection-title">Plantilla de usuario</h3>
              <textarea v-model="store.configFlat['features.aegis.prompts.userTemplate']" rows="8" class="txta"></textarea>
            </div>
          </section>

          <div class="form-actions">
            <button type="button" class="btn btn--secondary" @click="store.resetForm()">Restablecer</button>
            <button type="submit" class="btn btn--primary" :disabled="store.saving">{{ store.saving ? 'Guardando…' : 'Guardar Configuración' }}</button>
          </div>
        </form>
      </div>
    </main>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import { useConfigStore } from '@/stores/configStore'
import ScannerCard from '@/components/config/ScannerCard.vue'

const store = useConfigStore()

const ICON = {
  general:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
  security:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
  database:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>',
  redis:     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>',
  taskqueue: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><line x1="8" y1="9" x2="16" y2="9"/><line x1="8" y1="13" x2="14" y2="13"/></svg>',
  ai:        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="6" height="6" rx="1"/><rect x="4" y="4" width="16" height="16" rx="2"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 15h3M1 9h3M1 15h3"/></svg>',
  iris:      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-10 5L2 7"/></svg>',
  themis:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
  aegis:     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>',
}

const navGroups = [
  { label: 'Plataforma', items: [
    { id: 'general',   label: 'General',       icon: ICON.general },
    { id: 'security',  label: 'Seguridad',     icon: ICON.security },
    { id: 'database',  label: 'Base de datos', icon: ICON.database },
    { id: 'redis',     label: 'Redis',         icon: ICON.redis },
    { id: 'taskqueue', label: 'TaskQueue',     icon: ICON.taskqueue },
  ]},
  { label: 'Módulos', items: [
    { id: 'ai',       label: 'IA',       icon: ICON.ai },
    { id: 'iris',     label: 'Iris',     icon: ICON.iris },
    { id: 'themis', label: 'Themis', icon: ICON.themis },
    { id: 'aegis',    label: 'Aegis',    icon: ICON.aegis },
  ]},
]
const navSections = navGroups.flatMap((g) => g.items)

const isolationLevels = ['READ UNCOMMITTED', 'READ COMMITTED', 'REPEATABLE READ', 'SERIALIZABLE']
const aiStrategies = [
  { value: 'ollama', label: 'Ollama (local)' },
  { value: 'openai', label: 'OpenAI' },
]

const activeSection = ref('general')
let observer = null
function scrollTo(sectionId) { const el = document.getElementById(`section-${sectionId}`); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' }) }

onMounted(() => {
  store.loadConfig()
  observer = new IntersectionObserver((entries) => { for (const e of entries) { if (e.isIntersecting) activeSection.value = e.target.id.replace('section-', '') } }, { rootMargin: '-80px 0px -60% 0px' })
  requestAnimationFrame(() => { for (const s of navSections) { const el = document.getElementById(`section-${s.id}`); if (el) observer.observe(el) } })
})
onUnmounted(() => { if (observer) observer.disconnect() })

// El catálogo fijo de marcas se retiró: los productos vigilados se eligen por
// usuario contra el índice CPE del espejo local de NVD (GET /aegis/products),
// no desde la configuración global.
function handleSave() { store.saveConfig() }
</script>

<style scoped>
.config-page { min-height: 100vh; background: var(--bg); padding-top: var(--topbar-h); position: relative; }
.main { max-width: 1600px; margin: 0 auto; padding: 1.75rem 1.1rem 4rem; position: relative; z-index: 1; }
.config-layout { display: flex; gap: 1.25rem; align-items: flex-start; }
.config-nav-column { width: 160px; flex-shrink: 0; align-self: stretch; }
.config-nav { position: sticky; top: calc(var(--topbar-h) + 1.75rem); }
.config-nav nav { display: flex; flex-direction: column; gap: 0.2rem; }
.nav-link { display: flex; align-items: center; gap: 0.45rem; padding: 0.45rem 0.6rem; border-radius: 7px; color: var(--text-muted); font-size: var(--fs-lg); font-weight: 500; text-decoration: none; transition: all var(--transition); }
.nav-link:hover { background: var(--surface-2); color: var(--text-dim); }
.nav-link.active { background: var(--accent-dim); color: var(--accent-bright); font-weight: 600; }
.nav-icon { width: 16px; height: 16px; flex-shrink: 0; display: flex; align-items: center; }
.nav-icon svg { width: 100%; height: 100%; }
.nav-label { white-space: nowrap; }
.nav-group-label { font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-size: var(--fs-body); font-weight: 600; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-muted); padding: 0 0.6rem; margin: 0.7rem 0 0.25rem; }
.nav-group-label:first-child { margin-top: 0; }
.config-form { flex: 1; min-width: 0; }
.section { margin-bottom: 2rem; }
.section-head { margin-bottom: 0.85rem; padding-bottom: 0.55rem; border-bottom: 1px solid var(--border); }
.section-head--row { display: flex; align-items: flex-start; justify-content: space-between; gap: 0.85rem; }
.section-head h2 { font-size: var(--fs-2xl); font-weight: 700; color: var(--text); margin: 0; font-family: var(--font-display); font-size-adjust: var(--fsa-display); }
.section-desc { font-size: var(--fs-lg); color: var(--text-muted); margin: 0.15rem 0 0; }
.version-chip { flex-shrink: 0; font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-size: var(--fs-md); font-weight: 600; color: var(--accent-bright); background: var(--accent-dim); border: 1px solid var(--border-solid); border-radius: 999px; padding: 0.2rem 0.6rem; }
.section-body { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.1rem 1.25rem; display: flex; flex-direction: column; gap: 0.85rem; }
.subsection-title { font-size: var(--fs-lg); font-weight: 600; color: var(--text-dim); margin: 0.2rem 0 0.3rem; }
.cfg-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 0.85rem; }
.cfg-row { display: flex; align-items: center; }
.scanner-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 0.85rem; margin-top: 0.85rem; }
.form-group { display: flex; flex-direction: column; gap: 0.25rem; }
.form-group label { font-size: var(--fs-md); font-weight: 600; color: var(--text-dim); }
.inp { background: var(--bg); border: 1px solid var(--border-solid); border-radius: 6px; padding: 0.45rem 0.6rem; color: var(--text); font-size: var(--fs-input); outline: none; transition: border-color 0.2s; }
.inp:focus { border-color: var(--accent); }
.sel { cursor: pointer; appearance: none; -webkit-appearance: none; padding-right: 1.8rem; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2382829a' stroke-width='2.5'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 0.55rem center; background-size: 0.85rem; }
.sel option { background: var(--surface-2); color: var(--text); }
.txta { background: var(--bg); border: 1px solid var(--border-solid); border-radius: 6px; padding: 0.5rem 0.6rem; color: var(--text); font-size: var(--fs-input); outline: none; resize: vertical; width: 100%; min-height: 70px; box-sizing: border-box; transition: border-color 0.2s; }
.txta:focus { border-color: var(--accent); }
.mono { font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); }
.toggle-row { display: flex; align-items: center; gap: 0.4rem; cursor: pointer; font-size: var(--fs-lg); font-weight: 500; color: var(--text); }
.toggle { width: 16px; height: 16px; accent-color: var(--accent); cursor: pointer; }
.field-hint { font-size: var(--fs-md); color: var(--text-muted); line-height: 1.5; }
.field-hint code { font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-size: var(--fs-md); background: var(--surface-2); padding: 1px 4px; border-radius: 3px; color: var(--text-dim); }
.form-actions { display: flex; gap: 0.6rem; justify-content: flex-end; position: sticky; bottom: 0.85rem; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 0.85rem 1.1rem; z-index: 10; }
.loading-block { padding: 5rem 0; display: flex; justify-content: center; width: 100%; }
.skeleton { background: var(--surface); border-radius: 8px; animation: pulse 1.4s ease-in-out infinite; }
.skeleton--lg { width: 100%; height: 380px; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .4; } }
@media (max-width: 800px) { .config-layout { flex-direction: column; } .config-nav-column { width: 100%; } .config-nav { position: static; } .config-nav nav { flex-direction: row; flex-wrap: wrap; } .nav-link { flex: 1; justify-content: center; min-width: 80px; } }
</style>
