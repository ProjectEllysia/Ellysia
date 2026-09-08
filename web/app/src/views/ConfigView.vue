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
                  <label>Vigencia del enlace de recuperación (minutos)</label>
                  <input v-model.number="store.configFlat['general.registration.passwordResetTtlMinutes']" type="number" min="5" max="1440" class="inp" />
                </div>
                <div class="form-group">
                  <label>Vigencia de la invitación a una organización (horas)</label>
                  <input v-model.number="store.configFlat['general.registration.invitationTtlHours']" type="number" min="1" max="2160" class="inp" />
                </div>
              </div>
            </div>
          </section>

          <section id="section-security" class="section">
            <div class="section-head"><h2>Seguridad</h2><p class="section-desc">Contraseñas, sesión y segundo factor</p></div>
            <div class="section-body">
              <p class="field-hint">Parámetros de coste de Argon2id. Subirlos endurece los hashes pero ralentiza el inicio de sesión. Solo afectan a contraseñas creadas o cambiadas tras guardar.</p>
              <div class="cfg-grid">
                <div class="form-group"><label>Iteraciones (time cost)</label><input v-model.number="store.configFlat['general.security.argon2.time_cost']" type="number" min="1" max="20" class="inp" /></div>
                <div class="form-group"><label>Memoria (KiB)</label><input v-model.number="store.configFlat['general.security.argon2.memory_cost']" type="number" min="8192" step="1024" class="inp" /><span class="field-hint">65536 KiB = 64 MiB por hash</span></div>
                <div class="form-group"><label>Paralelismo (hilos)</label><input v-model.number="store.configFlat['general.security.argon2.parallelism']" type="number" min="1" max="16" class="inp" /></div>
              </div>

              <h3 class="subsection-title">Sesión (JWT)</h3>
              <p class="field-hint">Cuánto vive una sesión. El token de acceso es el que acompaña a cada petición; el de refresco es el que permite renovarlo sin volver a pedir la contraseña, así que su vigencia es la duración real de la sesión. El secreto de firma vive en <code>JWT_SECRET_KEY</code> y no está aquí. En contenedores, <code>JWT_ALGORITHM</code>, <code>ACCESS_TOKEN_EXPIRY_MINUTES</code> y <code>REFRESH_TOKEN_EXPIRY_DAYS</code> tienen prioridad sobre estos valores.</p>
              <div class="cfg-grid">
                <div class="form-group"><label>Algoritmo de firma</label>
                  <select v-model="store.configFlat['general.security.jwt.algorithm']" class="inp sel">
                    <option v-for="alg in jwtAlgorithms" :key="alg" :value="alg">{{ alg }}</option>
                  </select>
                  <span class="field-hint">Solo la familia HS*: la firma usa un secreto simétrico</span>
                </div>
                <div class="form-group"><label>Vigencia del token de acceso (min)</label><input v-model.number="store.configFlat['general.security.jwt.access_token_expiry_minutes']" type="number" min="1" max="1440" class="inp" /></div>
                <div class="form-group"><label>Vigencia del token de refresco (días)</label><input v-model.number="store.configFlat['general.security.jwt.refresh_token_expiry_days']" type="number" min="1" max="365" class="inp" /></div>
              </div>

              <h3 class="subsection-title">Segundo factor (TOTP)</h3>
              <p class="field-hint">El emisor es el nombre que la aplicación autenticadora enseña junto al código. Los códigos de recuperación se generan una sola vez al activar el segundo factor: cambiar aquí su número no afecta a quien ya lo tenga activado.</p>
              <div class="cfg-grid">
                <div class="form-group"><label>Emisor</label><input v-model="store.configFlat['general.security.mfa.issuer']" type="text" class="inp" /></div>
                <div class="form-group"><label>Vigencia del reto (min)</label><input v-model.number="store.configFlat['general.security.mfa.challenge_expiry_minutes']" type="number" min="1" max="60" class="inp" /></div>
                <div class="form-group"><label>Intentos por reto</label><input v-model.number="store.configFlat['general.security.mfa.max_challenge_attempts']" type="number" min="1" max="20" class="inp" /></div>
                <div class="form-group"><label>Códigos de recuperación</label><input v-model.number="store.configFlat['general.security.mfa.recovery_codes_count']" type="number" min="1" max="50" class="inp" /></div>
                <div class="form-group"><label>Recordatorio de activación (días)</label><input v-model.number="store.configFlat['general.security.mfa.notice_interval_days']" type="number" min="1" max="365" class="inp" /><span class="field-hint">Cada cuánto se le recuerda a quien no lo tiene activado</span></div>
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
              <p class="field-hint">Elige qué proveedor genera el contenido de cada módulo. Las credenciales siguen en <code>.env</code>; el modelo se elige aquí y se aplica al siguiente trabajo en segundo plano, sin reiniciar nada.</p>
              <div class="cfg-grid">
                <div class="form-group"><label>Estrategia por defecto</label>
                  <select v-model="store.configFlat['tools.scribe.defaultStrategy']" class="inp sel">
                    <option v-for="s in aiStrategies" :key="s.value" :value="s.value">{{ s.label }}</option>
                  </select>
                </div>
                <div v-for="m in aiModules" :key="m.key" class="form-group"><label>{{ m.label }}</label>
                  <select v-model="store.configFlat[`tools.scribe.modules.${m.key}`]" class="inp sel">
                    <option v-for="s in aiStrategies" :key="s.value" :value="s.value">{{ s.label }}</option>
                  </select>
                </div>
              </div>

              <h3 class="subsection-title">Modelo de cada proveedor</h3>
              <p class="field-hint">La lista sale de preguntarle al proveedor qué sirve ahora mismo. Dejar el campo vacío significa usar la variable de entorno, que es como funcionaba antes de que el modelo se pudiera elegir desde aquí.</p>
              <div class="cfg-grid">
                <ModelPicker
                  v-for="s in aiStrategies" :key="s.value"
                  v-model="store.configFlat[`tools.scribe.strategies.${s.value}.model`]"
                  :label="s.label" :env-hint="s.envVar"
                  :catalog="store.aiModels[s.value]" :loading="store.aiModelsLoading" />
              </div>

              <h3 class="subsection-title">Límites y reintentos</h3>
              <p class="field-hint">El tope de tokens rechaza un prompt desproporcionado antes de gastar la llamada. El corte automático deja de llamar al proveedor tras los fallos seguidos indicados, para no encadenar esperas contra un backend que ya se sabe caído.</p>
              <div class="cfg-grid">
                <div class="form-group"><label>Tokens máximos del prompt</label><input v-model.number="store.configFlat['tools.scribe.maxInputTokens']" type="number" min="1000" max="200000" step="1000" class="inp" /></div>
                <div class="form-group"><label>Intentos por generación</label><input v-model.number="store.configFlat['tools.scribe.resilience.maxRetries']" type="number" min="1" max="10" class="inp" /></div>
                <div class="form-group"><label>Base de la espera entre intentos (s)</label><input v-model.number="store.configFlat['tools.scribe.resilience.retryBaseSeconds']" type="number" min="1" max="10" step="0.1" class="inp" /></div>
                <div class="form-group"><label>Fallos que abren el corte</label><input v-model.number="store.configFlat['tools.scribe.resilience.breakerThreshold']" type="number" min="1" max="20" class="inp" /></div>
                <div class="form-group"><label>Duración del corte (s)</label><input v-model.number="store.configFlat['tools.scribe.resilience.breakerTimeoutSeconds']" type="number" min="5" max="3600" class="inp" /></div>
              </div>

              <h3 class="subsection-title">Timeout de cada proveedor (s)</h3>
              <p class="field-hint">Un modelo local tarda mucho más que una API en la nube, así que cada proveedor lleva el suyo.</p>
              <div class="cfg-grid">
                <div v-for="s in aiStrategies" :key="s.value" class="form-group">
                  <label>{{ s.label }}</label>
                  <input v-model.number="store.configFlat[`tools.scribe.strategies.${s.value}.timeout`]" type="number" min="10" max="1800" class="inp" />
                </div>
              </div>
            </div>
          </section>

          <section id="section-herald" class="section">
            <div class="section-head"><h2>Correo</h2><p class="section-desc">Relay de salida y marca de los mensajes</p></div>
            <div class="section-body">
              <p class="field-hint">Por aquí salen las campañas de Aegis, los avisos de Hygeia e Iris y los correos de cuenta (verificación, invitaciones, recuperación). El usuario y la contraseña del relay viven en <code>SMTP_USERNAME</code> y <code>SMTP_PASSWORD</code> del <code>.env</code>; lo de aquí no es secreto.</p>
              <div class="cfg-grid">
                <div class="form-group"><label>Estrategia por defecto</label>
                  <select v-model="store.configFlat['tools.herald.defaultStrategy']" class="inp sel">
                    <option v-for="s in mailStrategies" :key="s.value" :value="s.value">{{ s.label }}</option>
                  </select>
                </div>
                <div v-for="m in mailModules" :key="m.key" class="form-group"><label>{{ m.label }}</label>
                  <select v-model="store.configFlat[`tools.herald.modules.${m.key}`]" class="inp sel">
                    <option v-for="s in mailStrategies" :key="s.value" :value="s.value">{{ s.label }}</option>
                  </select>
                </div>
              </div>

              <h3 class="subsection-title">Relay SMTP</h3>
              <div class="cfg-grid">
                <div class="form-group"><label>Host</label><input v-model="store.configFlat['tools.herald.strategies.smtp.host']" type="text" class="inp mono" /></div>
                <div class="form-group"><label>Puerto</label><input v-model.number="store.configFlat['tools.herald.strategies.smtp.port']" type="number" min="1" max="65535" class="inp" /></div>
                <div class="form-group"><label>Dirección del remitente</label><input v-model="store.configFlat['tools.herald.strategies.smtp.fromAddress']" type="text" class="inp mono" /></div>
                <div class="form-group"><label>Nombre del remitente</label><input v-model="store.configFlat['tools.herald.strategies.smtp.fromName']" type="text" class="inp" /></div>
              </div>
              <div class="cfg-row"><label class="toggle-row"><input v-model="store.configFlat['tools.herald.strategies.smtp.useTls']" type="checkbox" class="toggle" /><span>Cifrar con STARTTLS</span></label></div>

              <h3 class="subsection-title">Marca de los correos</h3>
              <p class="field-hint">Lo que pintan las plantillas. Es la marca base del producto: el white-label por organización se configura en cada organización y se aplica encima de esta.</p>
              <div class="cfg-grid">
                <div class="form-group"><label>Nombre del producto</label><input v-model="store.configFlat['tools.herald.branding.productName']" type="text" class="inp" /></div>
                <div class="form-group"><label>Color de acento</label><input v-model="store.configFlat['tools.herald.branding.accentColor']" type="color" class="inp color-inp" /></div>
                <div class="form-group"><label>URL del logotipo</label><input v-model="store.configFlat['tools.herald.branding.logoUrl']" type="text" class="inp mono" /><span class="field-hint">Vacío = sin logotipo</span></div>
                <div class="form-group"><label>Correo de soporte</label><input v-model="store.configFlat['tools.herald.branding.supportEmail']" type="text" class="inp mono" /></div>
              </div>
              <div class="form-group"><label>Nota del pie</label><input v-model="store.configFlat['tools.herald.branding.footerNote']" type="text" class="inp" /></div>
              <div class="form-group"><label>Directorio de plantillas</label><input v-model="store.configFlat['tools.herald.templatesDir']" type="text" class="inp mono" /><span class="field-hint">Vacío = las plantillas que trae la aplicación</span></div>
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
              <h3 class="subsection-title">Buzones vigilados</h3>
              <div class="cfg-grid">
                <div class="form-group"><label>Conexiones por usuario</label><input v-model.number="store.configFlat['features.iris.maxConnectionsPerUser']" type="number" min="1" max="50" class="inp" /></div>
                <div class="form-group"><label>Correos ingeridos al día</label><input v-model.number="store.configFlat['features.iris.maxIngestedPerDay']" type="number" min="1" max="10000" class="inp" /></div>
                <div class="form-group"><label>Intervalo de sondeo (min)</label><input v-model.number="store.configFlat['features.iris.pollIntervalMinutes']" type="number" min="1" max="1440" class="inp" /></div>
                <div class="form-group"><label>Directorio de salida</label><input v-model="store.configFlat['features.iris.directories.output']" type="text" class="inp" /></div>
              </div>
              <h3 class="subsection-title">Resumen con IA</h3>
              <PromptField v-model="store.configFlat['features.iris.prompts.summary.system']" label="Prompt del sistema" title="Iris — prompt del sistema" />
              <PromptField v-model="store.configFlat['features.iris.prompts.summary.userTemplate']" label="Plantilla de usuario" title="Iris — plantilla de usuario" />
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
                <div class="form-group"><label>Vigencia del riesgo aceptado (días)</label><input v-model.number="store.configFlat['features.themis.acceptedRiskDays']" type="number" min="1" max="3650" class="inp" /><span class="field-hint">Pasado ese plazo, un hallazgo aceptado vuelve a contar</span></div>
                <div class="form-group"><label>Plazo por defecto de un trabajo (s)</label><input v-model.number="store.configFlat['features.themis.taskDefaults.timeout']" type="number" min="60" max="604800" class="inp" /><span class="field-hint">Lo que espera la cola antes de dar por muerto un escaneo</span></div>
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
              <h3 class="subsection-title">Base de conocimiento</h3>
              <p class="field-hint">El espejo local de NVD, KEV, EPSS y OVAL con el que Lybra decide si un servicio detectado es vulnerable. «Antigüedad máxima» es lo que se tolera desde la última sincronización de cada fuente antes de avisar de que está rancia; no borra nada.</p>
              <div class="cfg-row"><label class="toggle-row"><input v-model="store.configFlat['features.themis.kb.enabled']" type="checkbox" class="toggle" /><span>Sincronización activa</span></label></div>
              <div class="cfg-grid">
                <div class="form-group"><label>Cron de sincronización</label><input v-model="store.configFlat['features.themis.kb.syncCron']" type="text" class="inp mono" /><span class="field-hint">Formato cron de cinco campos</span></div>
                <div class="form-group"><label>Ventana pedida a NVD (días)</label><input v-model.number="store.configFlat['features.themis.kb.nvdWindowDays']" type="number" min="1" max="120" class="inp" /><span class="field-hint">Cuánto histórico se pide en cada pasada</span></div>
                <div v-for="feed in kbFeeds" :key="feed.key" class="form-group">
                  <label>Antigüedad máxima — {{ feed.label }} (días)</label>
                  <input v-model.number="store.configFlat[`features.themis.kb.maxAgeDays.${feed.key}`]" type="number" min="1" max="365" class="inp" />
                </div>
              </div>
              <div class="cfg-grid">
                <div v-for="source in kbSourcePaths" :key="source.path" class="form-group">
                  <label>Origen — {{ source.label }}</label>
                  <input v-model="store.configFlat[source.path]" type="text" class="inp mono" />
                </div>
              </div>
            </div>
            <div class="scanner-grid">
              <ScannerCard name="Nmap" icon="scan" :flat="store.configFlat" prefix="features.themis.scanners.nmap" />
              <ScannerCard name="Nikto" icon="web" :flat="store.configFlat" prefix="features.themis.scanners.nikto" />
              <ScannerCard name="Nuclei" icon="vuln" :flat="store.configFlat" prefix="features.themis.scanners.nuclei">
                <div class="cfg-grid cfg-grid--tight">
                  <div class="form-group"><label>Binario</label><input v-model="store.configFlat['features.themis.scanners.nuclei.binaryPath']" type="text" class="inp mono" /></div>
                  <div class="form-group"><label>Directorio de plantillas</label><input v-model="store.configFlat['features.themis.scanners.nuclei.templatesDir']" type="text" class="inp mono" /><span class="field-hint">Vacío = las que trae el binario</span></div>
                  <div class="form-group"><label>Versión de plantillas</label><input v-model="store.configFlat['features.themis.scanners.nuclei.templatesVersion']" type="text" class="inp mono" /></div>
                  <div class="form-group"><label>Peticiones por segundo</label><input v-model.number="store.configFlat['features.themis.scanners.nuclei.rateLimit']" type="number" min="1" max="1000" class="inp" /></div>
                  <div class="form-group"><label>Timeout por petición (s)</label><input v-model.number="store.configFlat['features.themis.scanners.nuclei.requestTimeout']" type="number" min="1" max="120" class="inp" /></div>
                  <div class="form-group"><label>Timeout del escaneo (s)</label><input v-model.number="store.configFlat['features.themis.scanners.nuclei.timeout']" type="number" min="60" max="14400" class="inp" /></div>
                </div>
                <div class="form-group">
                  <label>Severidades por defecto</label>
                  <div class="chip-row">
                    <label v-for="sev in nucleiSeverities" :key="sev" class="chip">
                      <input v-model="store.configFlat['features.themis.scanners.nuclei.defaultSeverities']" type="checkbox" :value="sev" />
                      <span>{{ sev }}</span>
                    </label>
                  </div>
                  <span class="field-hint">Lo que se escanea si el usuario no elige otra cosa</span>
                </div>
              </ScannerCard>
              <ScannerCard name="Lybra" icon="scan" :flat="store.configFlat" prefix="features.themis.scanners.lybra">
                <div class="cfg-row"><label class="toggle-row"><input v-model="store.configFlat['features.themis.scanners.lybra.activeChecks']" type="checkbox" class="toggle" /><span>Comprobaciones activas</span></label></div>
                <div class="cfg-row"><label class="toggle-row"><input v-model="store.configFlat['features.themis.scanners.lybra.fingerprintingEnabled']" type="checkbox" class="toggle" /><span>Fingerprinting</span></label></div>
                <div class="cfg-row"><label class="toggle-row"><input v-model="store.configFlat['features.themis.scanners.lybra.ingest.enabled']" type="checkbox" class="toggle" /><span>Ingesta de hallazgos</span></label></div>
                <div class="cfg-grid cfg-grid--tight">
                  <div class="form-group"><label>Severidad mínima</label>
                    <select v-model="store.configFlat['features.themis.scanners.lybra.ingest.minSeverity']" class="inp sel">
                      <option v-for="sev in severities" :key="sev" :value="sev">{{ sev }}</option>
                    </select>
                  </div>
                  <div class="form-group"><label>Máx. comprobaciones</label><input v-model.number="store.configFlat['features.themis.scanners.lybra.ingest.maxChecks']" type="number" min="1" max="5000" class="inp" /></div>
                </div>

                <CollapsibleSection default-open>
                  <template #header><h4 class="card-subtitle">Motor</h4></template>
                  <p class="field-hint">Cuánto empuja el motor contra el objetivo. Subir la concurrencia o bajar el intervalo acelera el escaneo y aumenta el riesgo de que el objetivo lo trate como un ataque.</p>
                  <div class="cfg-grid cfg-grid--tight">
                    <div v-for="dial in lybraEngineDials" :key="dial.key" class="form-group">
                      <label>{{ dial.label }}</label>
                      <input
                        v-model.number="store.configFlat[`features.themis.scanners.lybra.engine.${dial.key}`]"
                        type="number" :min="dial.min" :max="dial.max" :step="dial.step || 1" class="inp" />
                    </div>
                    <div class="form-group"><label>User-Agent</label><input v-model="store.configFlat['features.themis.scanners.lybra.engine.httpUserAgent']" type="text" class="inp mono" /></div>
                  </div>
                </CollapsibleSection>

                <CollapsibleSection default-open>
                  <template #header><h4 class="card-subtitle">Evidencia</h4></template>
                  <p class="field-hint">El trozo de respuesta cruda que se guarda junto a cada hallazgo para poder revisarlo después.</p>
                  <div class="cfg-row"><label class="toggle-row"><input v-model="store.configFlat['features.themis.scanners.lybra.evidence.enabled']" type="checkbox" class="toggle" /><span>Guardar evidencia</span></label></div>
                  <div class="cfg-grid cfg-grid--tight">
                    <div class="form-group"><label>Tamaño máx. (bytes)</label><input v-model.number="store.configFlat['features.themis.scanners.lybra.evidence.maxBodyBytes']" type="number" min="256" step="256" class="inp" /></div>
                    <div class="form-group"><label>Retención (días)</label><input v-model.number="store.configFlat['features.themis.scanners.lybra.evidence.retentionDays']" type="number" min="1" max="3650" class="inp" /></div>
                  </div>
                </CollapsibleSection>

                <CollapsibleSection default-open>
                  <template #header><h4 class="card-subtitle">Credenciales por defecto</h4></template>
                  <p class="field-hint">Es la única fase que escribe en el objetivo: cada intento es un inicio de sesión real. El tope es por cuenta, no por servicio, y evita que la comprobación se convierta en fuerza bruta.</p>
                  <div class="cfg-grid cfg-grid--tight">
                    <div class="form-group"><label>Intentos por cuenta</label><input v-model.number="store.configFlat['features.themis.scanners.lybra.credentials.maxAttempts']" type="number" min="1" max="20" class="inp" /></div>
                  </div>
                </CollapsibleSection>
              </ScannerCard>
            </div>
          </section>

          <section id="section-aegis" class="section">
            <div class="section-head"><h2>Aegis</h2><p class="section-desc">Generación de píldoras de concienciación con IA</p></div>
            <div class="section-body">
              <div class="cfg-row"><label class="toggle-row"><input v-model="store.configFlat['features.aegis.enabled']" type="checkbox" class="toggle" /><span>Habilitado</span></label></div>
              <div class="cfg-grid">
                <div class="form-group"><label>Consejos por píldora</label><input v-model.number="store.configFlat['features.aegis.tipsAmount']" type="number" min="1" max="20" class="inp" /></div>
                <div class="form-group"><label>Preguntas del test</label><input v-model.number="store.configFlat['features.aegis.questionsAmount']" type="number" min="1" max="20" class="inp" /></div>
                <div class="form-group"><label>Opciones por pregunta</label><input v-model.number="store.configFlat['features.aegis.optionsAmount']" type="number" min="2" max="8" class="inp" /></div>
                <div class="form-group"><label>Antigüedad máx. de alertas (años)</label><input v-model.number="store.configFlat['features.aegis.vulnerabilitiesAntiquity']" type="number" min="1" max="30" class="inp" /></div>
              </div>
              <div class="cfg-grid">
                <div class="form-group"><label>Directorio de salida</label><input v-model="store.configFlat['features.aegis.directories.output']" type="text" class="inp" /></div>
                <div class="form-group"><label>Stack de documentos</label><input v-model="store.configFlat['features.aegis.directories.stack']" type="text" class="inp" /></div>
              </div>
              <PromptField v-model="store.configFlat['features.aegis.prompts.system']" label="Prompt del sistema" title="Aegis — prompt del sistema" />
              <PromptField v-model="store.configFlat['features.aegis.prompts.userTemplate']" label="Plantilla de usuario" title="Aegis — plantilla de usuario" />
            </div>
          </section>

          <section id="section-hygeia" class="section">
            <div class="section-head"><h2>Hygeia</h2><p class="section-desc">Monitorización de activos vía agente</p></div>
            <div class="section-body">
              <p class="field-hint">Un activo pasa a «desconectado» cuando falla el número de latidos seguidos indicado. Bajar el intervalo multiplica el volumen de datos: la retención es la que decide cuánto histórico se conserva.</p>
              <div class="cfg-grid">
                <div class="form-group"><label>Intervalo de latido (s)</label><input v-model.number="store.configFlat['features.hygeia.heartbeatIntervalSec']" type="number" min="5" max="3600" class="inp" /></div>
                <div class="form-group"><label>Latidos perdidos para desconectar</label><input v-model.number="store.configFlat['features.hygeia.offlineAfterMissed']" type="number" min="1" max="100" class="inp" /></div>
                <div class="form-group"><label>Retención (días)</label><input v-model.number="store.configFlat['features.hygeia.retentionDays']" type="number" min="1" max="3650" class="inp" /></div>
                <div class="form-group"><label>Cron de purga</label><input v-model="store.configFlat['features.hygeia.retentionCron']" type="text" class="inp mono" /><span class="field-hint">Formato cron de cinco campos</span></div>
                <div class="form-group"><label>Precio de la electricidad (por kWh)</label><input v-model.number="store.configFlat['features.hygeia.energyPricePerKwh']" type="number" min="0" step="0.01" class="inp" /></div>
                <div class="form-group"><label>Moneda</label><input v-model="store.configFlat['features.hygeia.energyPriceCurrency']" type="text" maxlength="3" class="inp mono" /><span class="field-hint">Código ISO 4217 (EUR, USD...)</span></div>
                <div class="form-group"><label>Versión mínima de agente</label><input v-model="store.configFlat['features.hygeia.minAgentVersion']" type="text" class="inp mono" placeholder="0.0.0" /><span class="field-hint">Formato X.Y.Z. Un activo con una versión anterior se marca como desactualizado en la lista; "0.0.0" no marca ninguno.</span></div>
              </div>
              <h3 class="subsection-title">Umbrales</h3>
              <p class="field-hint">«Latidos sostenidos» evita las alertas por un pico puntual: la métrica tiene que seguir alta ese número de latidos seguidos. Disco y swap avisan al primero.</p>
              <div class="cfg-grid">
                <template v-for="metric in hygeiaMetrics" :key="metric.key">
                  <div class="form-group"><label>{{ metric.label }} — aviso</label><input v-model.number="store.configFlat[`features.hygeia.thresholds.${metric.key}.warning`]" type="number" min="1" max="100" class="inp" /></div>
                  <div class="form-group"><label>{{ metric.label }} — crítico</label><input v-model.number="store.configFlat[`features.hygeia.thresholds.${metric.key}.critical`]" type="number" min="1" max="100" class="inp" /></div>
                  <div v-if="metric.sustained" class="form-group"><label>{{ metric.label }} — latidos sostenidos</label><input v-model.number="store.configFlat[`features.hygeia.thresholds.${metric.key}.sustainedHeartbeats`]" type="number" min="1" max="60" class="inp" /></div>
                </template>
              </div>
              <h3 class="subsection-title">Colores del informe</h3>
              <p class="field-hint">La paleta con la que se genera el PDF de Hygeia, igual que la de cada escáner de Themis.</p>
              <div class="color-grid">
                <div v-for="color in reportColors" :key="color.key" class="color-pick">
                  <input v-model="store.configFlat[`features.hygeia.colorPalette.${color.key}`]" type="color" class="color-input" />
                  <span class="color-label">{{ color.label }}</span>
                  <span class="color-hex">{{ store.configFlat[`features.hygeia.colorPalette.${color.key}`] }}</span>
                </div>
              </div>

              <h3 class="subsection-title">Límites</h3>
              <p class="field-hint">Topes de lo que el agente puede enviar y de lo que la API acepta. Recortarlos protege a la API de un agente comprometido o mal configurado.</p>
              <div class="cfg-grid">
                <div v-for="limit in hygeiaLimits" :key="limit.key" class="form-group">
                  <label>{{ limit.label }}</label>
                  <input v-model.number="store.configFlat[`features.hygeia.limits.${limit.key}`]" type="number" min="1" class="inp" />
                  <span v-if="limit.hint" class="field-hint">{{ limit.hint }}</span>
                </div>
              </div>
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
import { ref, computed, onMounted, onUnmounted, nextTick } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import { useConfigStore } from '@/stores/configStore'
import ScannerCard from '@/components/config/ScannerCard.vue'
import CollapsibleSection from '@/components/config/CollapsibleSection.vue'
import ModelPicker from '@/components/config/ModelPicker.vue'
import PromptField from '@/components/shared/PromptField.vue'

const store = useConfigStore()

const ICON = {
  general:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
  security:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
  database:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>',
  redis:     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>',
  taskqueue: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><line x1="8" y1="9" x2="16" y2="9"/><line x1="8" y1="13" x2="14" y2="13"/></svg>',
  ai:        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="6" height="6" rx="1"/><rect x="4" y="4" width="16" height="16" rx="2"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 15h3M1 9h3M1 15h3"/></svg>',
  herald:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16v16H4z"/><path d="m4 7 8 6 8-6"/><path d="M2 20h6"/></svg>',
  iris:      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-10 5L2 7"/></svg>',
  themis:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
  aegis:     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>',
  hygeia:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>',
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
    { id: 'herald',   label: 'Correo',   icon: ICON.herald },
    { id: 'iris',     label: 'Iris',     icon: ICON.iris },
    { id: 'themis', label: 'Themis', icon: ICON.themis },
    { id: 'aegis',    label: 'Aegis',    icon: ICON.aegis },
    { id: 'hygeia',   label: 'Hygeia',   icon: ICON.hygeia },
  ]},
]
const navSections = navGroups.flatMap((g) => g.items)

const isolationLevels = ['READ UNCOMMITTED', 'READ COMMITTED', 'REPEATABLE READ', 'SERIALIZABLE']
// Solo la familia HS*: la firma usa un secreto simétrico, y el backend
// rechaza cualquier otra cosa (S8).
const jwtAlgorithms = ['HS256', 'HS384', 'HS512']
// `envVar` es la variable que se usa cuando el campo de modelo queda vacío, y
// se enseña como pista dentro del propio control: sin ella, un campo vacío se
// lee como «sin modelo» en vez de como «el que diga el entorno».
const aiStrategies = [
  { value: 'ollama', label: 'Ollama (local)', envVar: 'OLLAMA_MODEL' },
  { value: 'openai', label: 'OpenAI',        envVar: 'OPENAI_MODEL' },
  { value: 'google', label: 'Google Gemini', envVar: 'GOOGLE_MODEL' },
]
// Los módulos que generan contenido con IA. Iris faltaba: llama a
// `build_generator("iris")` desde su redactor de resúmenes, pero su estrategia
// no estaba declarada, así que caía en la de por defecto sin que se viera.
const aiModules = [
  { key: 'themis', label: 'Themis' },
  { key: 'aegis',  label: 'Aegis' },
  { key: 'iris',   label: 'Iris' },
]

// Herald solo tiene una estrategia registrada hoy (relay SMTP). El selector se
// mantiene porque la capa es enchufable por diseño y la alternativa —esconder
// el control— haría invisible qué está eligiendo el sistema.
const mailStrategies = [
  { value: 'smtp', label: 'Relay SMTP' },
]
const mailModules = [
  { key: 'aegis',    label: 'Aegis (campañas)' },
  { key: 'iris',     label: 'Iris (avisos)' },
  { key: 'hygeia',   label: 'Hygeia (avisos)' },
  { key: 'accounts', label: 'Cuentas (verificación, invitaciones)' },
]
const severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
// Nuclei etiqueta sus plantillas en minúsculas; el valor que se guarda tiene
// que coincidir exactamente con lo que espera el binario.
const nucleiSeverities = ['critical', 'high', 'medium', 'low', 'info']

const kbFeeds = [
  { key: 'nvd',  label: 'NVD' },
  { key: 'kev',  label: 'KEV' },
  { key: 'epss', label: 'EPSS' },
  { key: 'oval', label: 'OVAL' },
]

// Los diales del motor de Lybra son quince campos numéricos con la misma
// forma: se describen aquí y se pintan con v-for, como ya se hace con los
// umbrales y los límites de Hygeia.
const lybraEngineDials = [
  { key: 'tcpConcurrency',       label: 'Concurrencia TCP',        min: 1,   max: 2000 },
  { key: 'tcpTimeout',           label: 'Timeout TCP (s)',         min: 0.1, max: 60, step: 0.1 },
  { key: 'udpTimeout',           label: 'Timeout UDP (s)',         min: 0.1, max: 60, step: 0.1 },
  { key: 'udpRetries',           label: 'Reintentos UDP',          min: 0,   max: 10 },
  { key: 'udpBudgetSeconds',     label: 'Presupuesto UDP (s)',     min: 1,   max: 600, step: 0.5 },
  { key: 'rateLimitInterval',    label: 'Intervalo entre envíos (s)', min: 0, max: 10, step: 0.05 },
  { key: 'hostPoolSize',         label: 'Hosts en paralelo',       min: 1,   max: 64 },
  { key: 'httpTimeout',          label: 'Timeout HTTP (s)',        min: 1,   max: 120 },
  { key: 'httpMaxBodyBytes',     label: 'Cuerpo HTTP máx. (bytes)', min: 1024, max: 8388608, step: 1024 },
  { key: 'networkTimeout',       label: 'Timeout de red (s)',      min: 0.5, max: 120, step: 0.5 },
  { key: 'bannerTimeout',        label: 'Timeout de banner (s)',   min: 0.5, max: 60, step: 0.5 },
  { key: 'maxBlindProbes',       label: 'Sondeos a ciegas máx.',   min: 0,   max: 20 },
  { key: 'maxPayloadExpansions', label: 'Expansiones de payload máx.', min: 1, max: 500 },
]

// Los umbrales y los límites de Hygeia son 22 campos con la misma forma: se
// describen aquí y se pintan con v-for en vez de a mano uno por uno.
const hygeiaMetrics = [
  { key: 'cpuPct',  label: 'CPU (%)',    sustained: true },
  { key: 'memPct',  label: 'Memoria (%)', sustained: true },
  { key: 'diskPct', label: 'Disco (%)',  sustained: false },
  { key: 'swapPct', label: 'Swap (%)',   sustained: false },
]
// Las seis tintas de una paleta de informe. Mismo juego que usa ScannerCard
// para los escáneres de Themis; aquí se repite la lista porque Hygeia no pasa
// por ese componente (no es un escáner, no tiene prompts ni tarjeta propia).
const reportColors = [
  { key: 'black',     label: 'Negro' },
  { key: 'dark',      label: 'Oscuro' },
  { key: 'main',      label: 'Principal' },
  { key: 'secondary', label: 'Secundario' },
  { key: 'light',     label: 'Claro' },
  { key: 'white',     label: 'Blanco' },
]

const hygeiaLimits = [
  { key: 'maxBodyBytes',         label: 'Tamaño máx. del cuerpo (bytes)', hint: '1048576 = 1 MiB' },
  { key: 'maxDecompressedBytes', label: 'Tamaño máx. descomprimido (bytes)', hint: '4194304 = 4 MiB' },
  { key: 'maxProcesses',         label: 'Procesos por latido' },
  { key: 'maxDiskMounts',        label: 'Puntos de montaje' },
  { key: 'maxNetInterfaces',     label: 'Interfaces de red' },
  { key: 'maxSeriesPoints',      label: 'Puntos por serie temporal' },
  { key: 'minIntervalSec',       label: 'Intervalo mínimo entre latidos (s)' },
  { key: 'clockSkewSec',         label: 'Desfase de reloj tolerado (s)', hint: 'Cuánto se acepta que el reloj del agente vaya adelantado' },
  { key: 'maxBackfillSec',       label: 'Antigüedad máx. de un latido (s)', hint: '86400 = un día; más viejo que eso se rechaza' },
  { key: 'maxAssetsPerUser',     label: 'Activos por usuario' },
  { key: 'maxInventoryItems',    label: 'Elementos de inventario' },
]

const kbSourcePaths = computed(() => {
  const prefix = 'features.themis.kb.sources.'
  return Object.keys(store.configFlat)
    .filter((key) => key.startsWith(prefix))
    .sort()
    .map((path) => ({ path, label: path.slice(prefix.length).replace('oval.', 'OVAL ').toUpperCase() }))
})

const activeSection = ref('general')
let observer = null
function scrollTo(sectionId) { const el = document.getElementById(`section-${sectionId}`); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' }) }

onMounted(async () => {
  // Hay que esperar a la carga: mientras `store.loading` es true el formulario
  // no está en el DOM (v-else), así que registrar el observer antes dejaba el
  // resaltado del nav sin observar nada — no fallaba, simplemente no hacía nada.
  await store.loadConfig()
  // Sin `await`: son llamadas a proveedores externos que pueden tardar, y el
  // formulario no debe esperarlas para pintarse.
  store.loadAiModels()
  await nextTick()
  observer = new IntersectionObserver((entries) => {
    // Con este rootMargin varias secciones intersecan a la vez; la activa es la
    // más alta de las visibles, no la última que reporte el observer.
    const visible = entries.filter((entry) => entry.isIntersecting)
    if (!visible.length) return
    visible.sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)
    activeSection.value = visible[0].target.id.replace('section-', '')
  }, { rootMargin: '-80px 0px -60% 0px' })
  for (const section of navSections) {
    const el = document.getElementById(`section-${section.id}`)
    if (el) observer.observe(el)
  }
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
/* El overflow propio no rompe el sticky (solo lo rompería en un ancestro): es la
   válvula para que el nav siga siendo usable en pantallas bajas. */
.config-nav { position: sticky; top: calc(var(--topbar-h) + 1.75rem); max-height: calc(100vh - var(--topbar-h) - 3.5rem); overflow-y: auto; }
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
.cfg-grid--tight { grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 0.5rem; }
.cfg-row { display: flex; align-items: center; }
.color-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(90px, 1fr)); gap: 0.35rem; max-width: 560px; }
.color-pick { display: flex; flex-direction: column; align-items: center; gap: 0.1rem; padding: 0.4rem 0.2rem; background: var(--bg); border-radius: 5px; border: 1px solid var(--border); }
.color-input { width: 30px; height: 22px; border: none; border-radius: 3px; cursor: pointer; background: transparent; padding: 0; }
.color-label { font-size: var(--fs-body); font-weight: 600; color: var(--text-dim); }
.color-hex { font-size: var(--fs-body); color: var(--text-muted); font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); }
.chip-row { display: flex; flex-wrap: wrap; gap: 0.35rem; }
.chip { display: flex; align-items: center; gap: 0.3rem; padding: 0.25rem 0.5rem; background: var(--bg); border: 1px solid var(--border-solid); border-radius: 999px; font-size: var(--fs-md); color: var(--text-dim); cursor: pointer; }
.chip input { accent-color: var(--accent); cursor: pointer; }
.card-subtitle { font-size: var(--fs-md); font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em; margin: 0; }
/* Separación entre los tres bloques colapsables de Lybra (Motor, Evidencia,
   Credenciales): antes la daba el margin-top de `.card-subtitle`, que ahora
   vive dentro del botón de cada CollapsibleSection y no puede seguir
   cumpliendo ese papel. El nodo raíz de un componente hijo lleva también el
   atributo scoped del padre, así que este selector sin :deep() sí alcanza a
   las tres instancias declaradas aquí, dentro del slot de Lybra. */
.collapsible + .collapsible { margin-top: 0.5rem; }
/* `align-items: start` evita que Grid estire cada tarjeta a la altura de la más
   alta de su fila (Lybra, con varias subsecciones, frente a Nmap/Nikto casi
   sin opciones propias) — ese estirado era el hueco vacío que denunciaba el
   issue #451, no un exceso de contenido de Lybra. */
.scanner-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 0.85rem; margin-top: 0.85rem; align-items: start; }
.form-group { display: flex; flex-direction: column; gap: 0.25rem; }
.form-group label { font-size: var(--fs-md); font-weight: 600; color: var(--text-dim); }
.inp { background: var(--bg); border: 1px solid var(--border-solid); border-radius: 6px; padding: 0.45rem 0.6rem; color: var(--text); font-size: var(--fs-input); outline: none; transition: border-color 0.2s; }
.inp:focus { border-color: var(--accent); }
.sel { cursor: pointer; appearance: none; -webkit-appearance: none; padding-right: 1.8rem; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2382829a' stroke-width='2.5'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 0.55rem center; background-size: 0.85rem; }
.sel option { background: var(--surface-2); color: var(--text); }
.mono { font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); }
/* Un `input[type=color]` con el relleno de `.inp` deja la muestra reducida a
   una línea: aquí el control ES la muestra, así que se le quita el relleno. */
.color-inp { padding: 0.15rem; height: 2.1rem; cursor: pointer; }
.toggle-row { display: flex; align-items: center; gap: 0.4rem; cursor: pointer; font-size: var(--fs-lg); font-weight: 500; color: var(--text); }
.toggle { width: 16px; height: 16px; accent-color: var(--accent); cursor: pointer; }
.field-hint { font-size: var(--fs-md); color: var(--text-muted); line-height: 1.5; }
.field-hint code { font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-size: var(--fs-md); background: var(--surface-2); padding: 1px 4px; border-radius: 3px; color: var(--text-dim); }
/* Barra flotante, no una tarjeta más: con `--surface` y `--border` era idéntica
   a los `.section-body` por encima de los que pasa, y al solaparse parecía una
   sección rota. `--surface-2` es un tono distinto del de las tarjetas en los dos
   temas (`--topbar-bg` no valía: en dawn es el mismo color de tarjeta al 85%), y
   la sombra la despega del contenido que va pasando por debajo. */
.form-actions { display: flex; gap: 0.6rem; justify-content: flex-end; position: sticky; bottom: 0.85rem; background: var(--surface-2); border: 1px solid var(--border-med); border-radius: 10px; padding: 0.85rem 1.1rem; box-shadow: 0 4px 20px rgba(0,0,0,0.28); z-index: 10; }
.loading-block { padding: 5rem 0; display: flex; justify-content: center; width: 100%; }
.skeleton { background: var(--surface); border-radius: 8px; animation: pulse 1.4s ease-in-out infinite; }
.skeleton--lg { width: 100%; height: 380px; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .4; } }
@media (max-width: 800px) { .config-layout { flex-direction: column; } .config-nav-column { width: 100%; } .config-nav { position: static; } .config-nav nav { flex-direction: row; flex-wrap: wrap; } .nav-link { flex: 1; justify-content: center; min-width: 80px; } }
</style>
