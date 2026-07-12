# Ellysia — Plan de viabilidad SaaS (multiusuario, sin multitenancy empresarial)

_Consolidado el 2026-07-11 a partir de dos análisis previos + verificación directa contra el código actual._

## 0. Premisa confirmada

Modelo: **una sola instancia, una sola base de datos, aislamiento por `user_id`** (no una stack Docker por cliente). Verificado en código:

| Afirmación | Estado | Evidencia |
|---|---|---|
| Iris filtra por `user_id` | ✅ confirmado | `iris/repositories.py:27,36,98` |
| Themis/Aegis/Acheron/Users filtran por `user_id` | ✅ ya sabido | repos con `filters={"user_id": ...}` |
| Rate limiter sobrevive multi-worker/reinicio | ❌ **no** — `storage_uri="memory://"` | `shared/_endpoints.py:123` |
| Token de quiz de Aegis no filtra otros recipients | ✅ seguro — 1 token → 1 recipient, sin listado | `aegis/managers.py:840-875`, rate-limit 10/h en `endpoints.py:736` |
| Flujo "olvidé mi contraseña" | ❌ no existe | sin resultados en `users/` |
| Integración de pagos (Stripe/Paddle/LemonSqueezy) | ❌ no existe | sin resultados en `API/` |
| Página de pricing en frontend | ❌ no existe | sin resultados en `web/app/src` |
| Cuotas por usuario (scans/día, píldoras/día, tamaño vault) | ❌ no existe | sin resultados en `scan.py` |
| Aegis: campañas + quiz público + `herald` | ✅ **implementado**, no solo diseñado | modelos `Campaign`/`CampaignRecipient`/`DistributionList`/`CampaignAnswer`, endpoints `/aegis/quiz`, módulo `herald` completo |
| Scribe usa OpenAI por defecto (aegis/themis) | ✅ ya configurado | `SecOpsConfig.json`: `defaultStrategy: "openai"` |
| MFA (TOTP + recovery codes) | ✅ **implementado** end-to-end, no solo diseñado | modelos `MFATotpCredential`/`MFARecoveryCode`/`MFAChallenge`, login con paso de 2º factor en `LoginView.vue`, `MfaSetupModal.vue` |
| Aviso al usuario si no tiene MFA activado (login o email) | ❌ no existe | sin resultados de nudge/recordatorio |
| Scheduler periódico reutilizable (cron/interval) | ✅ ya existe y en uso | `APScheduler` (dependencia declarada), `themis/services/scheduling.py:Scheduler` lo usa para escaneos recurrentes |
| Landing/hub intermedio por módulo (antes de entrar a la herramienta) | ❌ no existe | el nav lleva directo a la vista de trabajo de cada módulo |

Esta tabla es la fuente de verdad para las fases siguientes — no reabrir preguntas ya verificadas (p. ej. no volver a auditar el leak de tokens de quiz salvo que cambie el código).

## 1. Diagnóstico por módulo

- **Iris**: el scoring de 37 reglas sobre cabeceras es un MVP correcto pero no es producto diario sin ingesta automática (IMAP polling). Sin esto, sigue siendo demo. Falta también reputación de URLs (URLhaus/PhishTank/OpenPhish), feedback loop de falsos positivos, y una puerta de entrada propia (hub) que explique qué hace antes de pedirle al usuario que pegue cabeceras a mano.
- **Acheron**: no compite como password manager aislado (Bitwarden/1Password ya ganan esa categoría). Su valor real es alimentar escaneo autenticado en Lybra (Fase 4 del roadmap). No venderlo como producto independiente — su hub debe explicar precisamente esto, no vender "otro gestor de contraseñas".
- **Themis**: débil como "envoltorio de Nmap/Nikto/OpenVAS". Solo diferencia si Lybra se completa — Finding unificado, ciclo de vida, scoring contextual (CVSS+EPSS+KEV+exposición), reporte en lenguaje natural. Esto ya está en tu roadmap propio.
- **Aegis**: el wedge product correcto — más inmediato de entender para un no-técnico, menor fricción técnica (no escanea nada del cliente), y **ya implementado**. Prioridad de lanzamiento, primer módulo en recibir hub propio.

Los cuatro módulos comparten el mismo problema de superficie: hoy el usuario entra a la app y cae directo en la herramienta de trabajo, sin una parada intermedia que explique qué está usando, qué estado tiene, y a dónde más puede ir (documentación, otros módulos). Ver sección 3.

## 2. Fases de ejecución

### Fase 0 — Fundaciones SaaS (bloqueante antes de aceptar el primer pago real)

Todo esto es trabajo confirmado como faltante, no especulación:

1. **Rate limiter → Redis** (`storage_uri="redis://..."` en `shared/_endpoints.py`). Sin esto un solo usuario abusivo degrada a todos y los límites no sobreviven un restart/multi-worker.
2. **Cuotas por usuario**: scans concurrentes/día, píldoras Aegis/día, tamaño de vault, recipients por campaña. No existe ninguna hoy — es tu única defensa contra "mal vecino" sin segmentación por organización.
3. **Flujo de recuperación de contraseña** (users module + email transaccional vía `herald`).
4. **Integración de pago**: Stripe (Checkout hosted, soporta EUR/tarjetas internacionales, no manejas PCI) o Lemon Squeezy/Paddle si prefieres que ellos actúen como merchant of record y gestionen IVA cross-border por ti — recomendado para un solo founder vendiendo a España + LatAm. Webhook que active atributos ABAC al confirmar pago.
5. **Registro público + pricing en el frontend** — hoy no existe ninguna de las dos páginas.
6. **Backups Postgres automatizados** (`pg_dump` nocturno → Cloudflare R2 o Hetzner Storage Box). Verificar primero si ya existe algo parcial antes de construir desde cero.
7. **Monitoring básico** del VPS único (UptimeKuma, gratis, self-hosted).

Estimación: 2–4 semanas de trabajo técnico, en paralelo con la Fase 1 (no son secuenciales, Fase 0 es infraestructura, Fase 1 es producto/UX).

### Fase 1 — Lanzamiento Aegis-first

Como el backend de campañas ya existe, esta fase es de pulido y go-to-market, no de construcción desde cero:

1. UX de campaña end-to-end en `web/app`: crear lista de distribución → lanzar campaña → ver tasa de completitud/resultados del quiz.
2. ~~Hub de Aegis~~ **Hubs de los 4 módulos — HECHO (2026-07-11), rediseñados como landings públicas**: componente compartido `components/shared/ModuleHub.vue` + `AegisHubView`/`ThemisHubView`/`IrisHubView`/`AcheronHubView`, cada uno en `/<módulo>`. **Son PÚBLICOS** (sin `requiresAuth`): la carta de presentación de cada herramienta, para que quien busque "Acheron" aterrice en su hub sin login — `LandingView` (`/`) es el meta-hub que las reúne. Diseño "carta de presentación" estilo NordSecurity con la identidad Elysium: hero benefit-led, placa dual (actividad real si hay sesión / dato de producto `highlight` si es visita anónima), capacidades editoriales, cross-sell "el resto del panteón", banda CTA final. La herramienta de trabajo vive en `/<módulo>/<subruta>` (p. ej. `/aegis/generador`) y **sí** requiere sesión. Cabecera/pie públicos compartidos: `components/shared/SiteHeader.vue` + `SiteFooter.vue` (este último también en `LandingView`). El fetch de métricas se salta cuando no hay sesión (evita el rebote a login). Páginas informativas públicas nuevas: `/sobre`, `/privacidad`, `/terminos` (`AboutView`/`PrivacyView`/`TermsView` vía `InfoPage.vue`) — legal marcado como preliminar, pendiente de completar antes del lanzamiento comercial.
3. **Nudge de MFA + recordatorio programado** (ver sección 4) — barato, y una plataforma de ciberseguridad que cobra dinero sin empujar su propio 2FA es una contradicción que un cliente exigente notará.
4. Landing + pricing enfocados **solo en Aegis**: "cumple con la concienciación obligatoria de ENS/GDPR sin contratar a nadie."
5. Tier único de lanzamiento (hipótesis: ~29€/mes, píldoras + campañas sin límite agresivo, sin Themis/Iris todavía). Validar que alguien paga antes de tocar precio.
6. Canal inicial: 5–10 conversaciones directas con consultoras IT locales (revenue share) antes de gastar en ads o esperar SEO.
7. Sin free tier — trial de 14 días, cobro desde el día uno.

### Fase 2 — Expansión (tras validar Fase 1)

1. Iris e Themis como add-ons sobre el mismo pricing.
2. ~~Hubs de Themis, Iris y Acheron~~ — adelantado a Fase 1, ver arriba.
3. Iris: IMAP polling (`imaplib` + `email` stdlib) — la apuesta funcional de mayor valor pendiente, convierte Iris de demo a hábito diario.
4. Themis: seguir el roadmap Lybra ya escrito — prioriza Fase G (cierre de bucle detección→remediación con comando exacto, ej. `apt-get install -y openssh-server=...`) y el dashboard de superficie de ataque en el tiempo (`first_seen_at`/`last_seen_at`). Este dashboard es también el primer candidato natural para un segundo tipo de recordatorio programado (sección 4): "esta semana se abrió un puerto nuevo en tu servidor".
5. Extender los recordatorios programados de la sección 4 a otros eventos de confianza/retención (aviso de fin de trial, fallo de cobro) según se vayan necesitando.

### Fase 3 — Hardening con tracción (>50–100 usuarios de pago)

1. Postgres Row-Level Security como defensa en profundidad (no antes — el filtro centralizado por `user_id` en repos ya cubre el riesgo inmediato).
2. Colas RQ con prioridad por categoría (que un OpenVAS de un usuario no bloquee al resto).
3. Export de datos GDPR + cancelación de cuenta autoservicio.
4. Hygeia solo si hay demanda explícita validada — no antes.

## 3. Landing intermedia por módulo

Hoy la navegación salta directo del menú principal a la vista de trabajo de cada módulo (nuevo escaneo, nuevo análisis, etc.). Falta una parada intermedia por módulo: una página que explique qué es la herramienta, muestre su estado, ofrezca atajos, y enlace tanto a la propia app como a documentación y recursos externos.

**Referencias reales que informan el diseño** (no es un patrón inventado — es lo que ya usan productos maduros):
- **Consola de AWS por servicio** (ej. GuardDuty): hero con la propuesta de valor de una línea, capacidades del servicio en resumen, y un CTA de "activar/empezar" — friction-free onboarding antes de exponer el panel de trabajo real.
- **Pestaña "Security" de un repo de GitHub**: no es una herramienta única, es una colección de tarjetas (Code scanning, Dependabot, Secret scanning), cada una con su propio resumen, botón de activar/ver, y enlace a documentación — exactamente el patrón de "hub por capacidad" que necesitan Themis/Iris/Aegis/Acheron.
- **Tendencias de dashboard SaaS 2026** (Datadog, Linear, Stripe y similares): *progressive disclosure* — mostrar solo la cifra que más importa (la "north star metric") arriba a la izquierda, no un muro de datos; grids tipo *bento* (tarjetas de tamaño variable) para las capacidades secundarias; capturas reales del propio producto en vez de ilustraciones genéricas.
- **KnowBe4 / Auth0 (galería de extensiones) / 1Password Watchtower**: cada producto o característica tiene su propia página de aterrizaje con explicación + CTA + enlace a documentación, en vez de asumir que el usuario ya sabe para qué sirve.

**Plantilla genérica por módulo** (construirla una vez para Aegis en Fase 1, reusarla para los demás en Fase 2):

1. **Hero** — nombre del módulo + propuesta de valor de una línea + CTA primario que lleva a la herramienta real.
2. **Métrica norte / estado** (esquina superior izquierda, la única cifra que importa) — dos variantes:
   - *Primera vez* (sin datos aún): variante tipo AWS GuardDuty, un CTA de "empezar" con lo mínimo para el primer uso.
   - *Usuario recurrente*: snapshot real (ver cifras por módulo abajo).
3. **Atajos rápidos** (grid tipo GitHub Security tab) — 3–4 tarjetas a las subtareas más comunes, cada una con su propio botón directo.
4. **Capacidades del módulo** (grid bento secundario) — qué hace, con captura real del producto, no ilustración genérica.
5. **Recursos** — documentación propia del módulo **y** enlaces externos de autoridad relevantes (regulatorios, glosarios, fuentes técnicas). Es el punto que hoy falta por completo: la landing debe poder sacar al usuario tanto hacia la herramienta como hacia contenido de referencia.
6. **Cross-sell discreto** a los módulos que el usuario aún no usa — conecta directamente con la estrategia comercial de Fase 1→2 (Aegis primero, luego Iris/Themis como add-on).

**Contenido específico por módulo:**

| Módulo | Métrica norte | Atajos rápidos | Recursos (internos + externos) |
|---|---|---|---|
| **Aegis** | Tasa de finalización de la última campaña | Nueva píldora · Nueva campaña · Alertas CVE por marca | Guía de concienciación ENS/GDPR, Kit Digital, glosario de tipos de phishing |
| **Themis** | Hallazgos críticos abiertos / fecha del último escaneo | Nuevo escaneo · Historial · Escaneos programados | Roadmap Lybra (para el usuario curioso), docs de Nmap/Nikto, guía de CVSS/EPSS/KEV |
| **Iris** | Correos analizados este mes / % marcados como phishing | Analizar correo · Historial · (Fase 2) Conectar buzón IMAP | Glosario de indicadores de phishing, guía de SPF/DKIM/DMARC |
| **Acheron** | Secretos guardados / antigüedad de la última rotación | Añadir secreto · Ver vault · Exportar | Explicación de cómo Acheron alimenta el escaneo autenticado de Lybra (para no venderlo como password manager aislado), enlace a la app móvil |

## 4. Notificaciones y recordatorios programados (nudge de MFA + base reutilizable)

MFA ya está implementado end-to-end (TOTP + códigos de recuperación, paso de segundo factor en el login). Lo que falta es empujar al usuario que no lo ha activado — sin esto, una plataforma de ciberseguridad se contradice a sí misma.

**Nudge en login (barato, solo frontend)**: tras un login exitoso, si el usuario no tiene MFA confirmado, mostrar un aviso no bloqueante reutilizando el sistema de toasts ya existente (`toastStore.js`), con enlace directo a la sección de MFA del perfil. Mostrarlo como máximo una vez por sesión (flag en `sessionStorage`) para no ser intrusivo en cada login.

**Recordatorio por email — reusar lo que ya existe, no construir un mailer nuevo**: `themis/services/scheduling.py` ya usa `APScheduler` (`BackgroundScheduler`, dependencia ya declarada en `requirements.txt`) para lanzar escaneos recurrentes. Ese es el mecanismo de scheduling a reutilizar; no hace falta inventar uno nuevo.

Dado que el plan comercial ya anticipa más de un tipo de recordatorio (aviso de fin de trial, fallo de cobro, y en Fase 2 el digest semanal de superficie de ataque de Themis — "esta semana se abrió un puerto nuevo"), sí se justifica un registro genérico ligero en vez de acoplar el job solo a MFA:

- Un módulo pequeño de "recordatorios programados" con una función por tipo (`mfa_nudge`, y más adelante `trial_ending`, `weekly_asset_digest`, etc.), cada una devolviendo los usuarios elegibles.
- Un único job de `APScheduler` (trigger de intervalo, ej. diario) que recorre los recordatorios registrados y usa `herald.build_mailer(...)` para enviar cada uno — `herald` no cambia, solo se le pide que envíe como ya sabe hacer.
- Idempotencia: cada tipo de recordatorio guarda su propio "último enviado" (timestamp en el usuario o una tabla ligera de log) para no repetir antes de N días, configurable en `SecOpsConfig.json` como el resto de parámetros no-secretos.
- Elegibilidad para el nudge de MFA en concreto: sin `MFATotpCredential` confirmada, cuenta con más de N días de antigüedad (no molestar el día 1), sin recordatorio enviado en los últimos X días.

No es una nueva clase "extensión del mailer" — la pieza que faltaba nunca fue el envío (`herald` ya lo hace bien), sino el scheduler + la selección de destinatarios, y ese patrón ya existe en el código (Themis). El único código nuevo es la lista de reglas de elegibilidad y el job que las recorre.

## 5. Infraestructura (ajustada al modelo multiusuario, no single-tenant)

- **1 VPS** (Hetzner CX41/CCX13, ~10–35€/mes) — nada de wildcard DNS ni provisioning por cliente.
- Docker compose: API + worker RQ + Postgres + Redis. Ollama es opcional/no crítico — `scribe` ya usa OpenAI por defecto.
- **Caddy** como reverse proxy con TLS automático (Let's Encrypt) — decisión de infra de menor mantenimiento para un founder solo.
- **Brevo** SMTP (ya soportado por `herald`) + SPF/DKIM/DMARC en el dominio de envío — sin esto las campañas de Aegis (y los recordatorios de la sección 4) van a spam y el producto parece roto.
- **OpenVAS** fuera del tier de lanzamiento — Aegis no lo necesita, y cuando Themis/Lybra lo requiera, decidir bajo demanda vs. siempre-arriba compartido.
- Coste total de infra estimado: **<50€/mes**. El punto de equilibrio con un solo cliente de pago a 29–100€/mes ya es positivo.

## 6. Comercial (de acuerdo con el análisis original, sin cambios)

- No SEO genérico contra Tenable/Qualys/Rapid7, no ads pagados amplios, no cold email a "CISO de PYME" (la mayoría no tiene uno).
- Sí: canal regulatorio (ENS, Kit Digital si sigue activo), alianzas con consultoras IT locales (mejor ROI de tiempo que negociar con PYMEs una a una), contenido técnico en español, LinkedIn con el responsable de IT individual, comunidad INCIBE/ISMS Forum.
- Mensaje: no "plataforma modular SecOps" — sí "el ciberseguridad que tu PYME necesita, sin contratar un equipo."
- LatAm: liderar con miedo a ransomware, no con compliance (normativas más laxas ahí); precios sensibles a PPP si se persigue escala regional.

## 7. Qué NO construir todavía

- Hygeia (agente Go de monitorización) — segundo producto, canal de ventas distinto.
- Correlación cross-host, re-escaneo inteligente, export SARIF/STIX — features de empresa mediana, no de PYME de un servidor.
- Seat-based pricing — un precio por cuenta es más honesto con la arquitectura actual.
- Free tier — trial sí, gratis indefinido no.
- Un framework de recordatorios grande — solo la mínima lista de reglas + un job, hasta que haya 3+ tipos reales que lo justifiquen.
- Los cuatro módulos a la vez — Aegis primero, validar, luego expandir.

## 8. Checklist accionable — próximos 30/60/90 días

**Días 0–30 (Fase 0 + arranque Fase 1):**
- [ ] Rate limiter a Redis
- [ ] Cuotas básicas por usuario (al menos: scans concurrentes, píldoras/día)
- [ ] Flujo de reset de contraseña
- [ ] Elegir proveedor de pago (Stripe vs Lemon Squeezy/Paddle) e integrar Checkout + webhook
- [ ] Página de registro público + pricing en `web/app`
- [ ] Backups Postgres automatizados + UptimeKuma
- [ ] SPF/DKIM/DMARC en dominio de envío Brevo

**Días 30–60 (lanzamiento Aegis):**
- [ ] UX de campaña completa en frontend
- [x] Hubs de los 4 módulos (plantilla reusable) — hecho 2026-07-11; falta landing/pricing enfocados en Aegis
- [ ] Nudge de MFA en login + job de recordatorio programado (reusando `APScheduler`)
- [ ] 5–8 conversaciones selectivas con consultoras IT (no cold — LinkedIn, recomendación, INCIBE)

**Días 60–90 (validación de mercado — punto de decisión crítico):**

**Umbral de éxito en septiembre:** al menos **1 consultora que diga "me interesa, cuéntame más"** (no necesariamente pagando aún). Si esto ocurre, el plan tiene justificación para octubre–noviembre; si no, el mensaje/canal/producto están rotos.

Checklist:
- [ ] ≥1 consultora en conversación seria (no vaga, con detalles específicos sobre su caso)
- [ ] Feedback claro sobre precio, diferenciadores, qué falta
- [ ] Landing + hub puntuales, pricing testada en conversación real
- [ ] LinkedIn/contenido técnico establécido como rutina (1 post/semana mínimo)

**Octubre (transición post-validación):**

| Resultado septiembre | Decisión octubre |
|---|---|
| **≥1 consultora interesada** | Renegocia trabajo (30h/semana) o parte-time. Ellysia es prioridad 1 Oct–Nov. Máster sigue pero segundo plano. |
| **3–5 "maybes" en trial pero sin decisión clara** | Sigue side-project 10–15h/semana. Máster es prioritario. Enero (fin máster) es siguiente punto de decisión. |
| **Ningún interés real** | Acepta feedback negativo. Side-project a 5–10h/semana. Diagnostica en enero: ¿pivotear o cerrar? |

**Nota importante:** no es "fallo" terminar en octubre con Ellysia en side-project. Es reconocer que el runway de septiembre fue para *validar*, no para *convertir*. Si validaste que el mercado existe, has ganado.
