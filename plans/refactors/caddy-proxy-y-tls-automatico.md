# Sustituir Nginx + Certbot por Caddy: TLS automático y despliegue de un paso

## Contexto

El despliegue del 14 de agosto de 2026 puso a prueba el flujo de TLS descrito en
`README.md` §"SSL certificates (production)". Funcionó, pero costó una sesión
entera y siete fallos encadenados. Ninguno era del certificado en sí:

| # | Fallo | Causa real |
|---|---|---|
| 1 | `certonly` salía con código 0 sin emitir nada | `entrypoint: ["/bin/true"]` pisaba el `ENTRYPOINT ["certbot"]` de la imagen |
| 2 | Reto ACME → 404 | Certbot y Nginx en proyectos de Compose distintos (`ellysiaserver` vs `ellysia`), cada uno con su volumen |
| 3 | Reto ACME → 404 (otra vez) | El contenedor `web` en marcha era anterior al bloque `/.well-known/` (va horneado en la imagen, no montado) |
| 4 | `no valid A records` | Apex sin registro; un apex no admite CNAME y la IP es dinámica |
| 5 | El linaje habría acabado en `live/www.ellysia.es/` | Certbot nombra el linaje según el primer `-d` |
| 6 | `cp: Permission denied` | Certbot escribe `live/` como root con `0700` |
| 7 | Nginx seguía sirviendo el autofirmado | El `cp` falló y el `&&` cortó el `restart`, sin error visible |

El patrón es claro: **el certificado no es el problema, lo es la cantidad de
pasos manuales y de conocimiento tribal necesario para encadenarlos.** Seis de
los siete fueron fallos mudos — exit 0, sin salida, o un 404 que no apuntaba a
su causa. Y todos volverán a estar disponibles dentro de dos o tres años, en el
próximo despliegue, cuando nadie recuerde nada de esto.

La premisa del roadmap (§1: *"el objetivo declarado de Ellysia es construirlo, no
venderlo"*, 10–15 h/semana) hace que esto pese más de lo normal: el tiempo que se
va en pelear con infraestructura no vuelve, y un despliegue que exige recordar
siete trampas es un despliegue que se pospone.

---

## 1. El debate: cuatro opciones

### A) Statu quo — Nginx + Certbot manual + cron

Lo que hay. Funciona hoy.

**A favor:** cero trabajo nuevo; Nginx es lo que ya está documentado y auditado;
techo de rendimiento máximo de las cuatro opciones.

**En contra:** las siete trampas de arriba siguen ahí. El proceso conserva tres
fases manuales obligatorias (bootstrap del autofirmado → `up` → emisión + copia +
reload) y un cron en el host que puede fallar en silencio. `web/ssl/renew.sh`
hace el mismo `cp` sin `sudo` que falló en el paso 6, así que **la renovación
automática está rota hoy mismo** y no se sabrá hasta que el certificado caduque.

### B) Nginx + Certbot + script de bootstrap

Automatizar la fase 1 en un `web/ssl/bootstrap.sh` que genere el autofirmado solo
si falta.

**A favor:** diff pequeño, no toca el enrutado, mantiene todo el conocimiento
existente sobre Nginx.

**En contra:** ataca la trampa menos grave. Las de proyecto de Compose, permisos
de root, `fullchain` vs `cert`, y el `cp` silencioso siguen intactas. Es
envolver mejor un proceso frágil, no arreglarlo.

### C) Caddy

Servidor web con emisión y renovación de certificados integradas en el propio
servidor, sin ACME externo.

**A favor:** elimina de raíz **cinco de las siete trampas** (1, 2, 3, 5, 6, 7 —
todas menos la del DNS del apex, que es de la zona y ninguna herramienta puede
arreglar). No hay certbot, ni cron, ni copiar ficheros, ni permisos de root, ni
un bootstrap autofirmado: Caddy arranca sin certificado y lo consigue él mismo.
El fichero de configuración pasa de ~100 líneas de Nginx + 30 de tabla de rutas a
unas 40 en total.

**En contra:** hay que reescribir `nginx.conf`, `proxy-common.conf` y
`api-locations.conf` como un `Caddyfile`, y volver a verificar el enrutado
completo — incluida la tabla que acabamos de arreglar. Rendimiento ligeramente
por debajo de Nginx en benchmarks sintéticos (irrelevante aquí: con 45.000–80.000
req/s en las tres, el cuello de botella son los escaneos y Postgres, nunca el
proxy).

### D) Traefik

**A favor:** también resuelve el TLS automático, y descubre servicios por
etiquetas de Docker.

**En contra:** su ventaja real —descubrimiento dinámico— no aplica: aquí hay
tres hostnames fijos y dos servicios que no cambian. A cambio, la configuración
se dispersa en etiquetas dentro de `docker-compose.yml`, lo que va **en contra**
de la cultura del repositorio: `api-locations.conf` es un fichero revisable, con
comentarios que explican el porqué de cada línea, y un test que lo verifica.
Convertirlo en etiquetas YAML pierde eso. Además es la de curva de aprendizaje
más pronunciada de las tres.

### Veredicto: **C, Caddy**

Traefik resuelve un problema que Ellysia no tiene (orquestación dinámica) al
precio de empeorar uno que sí tiene (configuración legible y verificable). Nginx
tiene el mejor techo de rendimiento, pero el proxy no es ni de lejos el cuello de
botella de esta aplicación, y ese techo se paga con toda la fragilidad
operacional documentada arriba. Caddy es la única opción que convierte el TLS de
**proceso** en **propiedad del sistema**.

El criterio decisivo no es "cuál es mejor servidor", es **cuántos pasos hay que
recordar dentro de tres años**. Con Caddy son cero.

---

## 2. Cómo funciona Caddy (y por qué desaparecen las trampas)

### 2.1 HTTPS automático

Caddy no necesita que se le hable de ACME. En cuanto sabe un nombre de dominio
—porque aparece como dirección de un sitio en el `Caddyfile`— activa
[HTTPS automático](https://caddyserver.com/docs/automatic-https): pide el
certificado, lo instala, y lo renueva en segundo plano el resto de su vida.

El arranque en frío que obliga al autofirmado en Nginx **no existe**: Caddy
arranca sin certificado y lo obtiene sobre la marcha. Esa es la diferencia
estructural — Nginx evalúa `ssl_certificate` al cargar la configuración y muere
si el fichero falta; Caddy trata el certificado como estado a conseguir, no como
requisito previo.

### 2.2 Los tres retos, y por qué importa tener más de uno

| Reto | Puerto | Cuándo sirve |
|---|---|---|
| **HTTP-01** | 80 | El que usa certbot hoy |
| **TLS-ALPN-01** | 443 | **Activado por defecto.** No necesita el puerto 80 abierto |
| **DNS-01** | ninguno | Requiere credenciales de API del proveedor DNS |

Caddy prueba los disponibles y **aprende cuál funciona mejor** en ese entorno.
Esto es directamente relevante para el despliegue actual: hoy dependes de que el
router de casa tenga el 80 abierto hacia dentro. Si el ISP lo bloquea alguna vez
—cosa habitual en conexiones residenciales—, certbot se queda sin salida y
Caddy sigue emitiendo por TLS-ALPN-01 sin que nadie toque nada.

Ante un fallo, Caddy reintenta, cambia de tipo de reto, cambia de emisor
(Let's Encrypt → ZeroSSL) y aplica retroceso exponencial, **usando el entorno de
staging de Let's Encrypt durante los reintentos** para no quemar la cuota. Las
cuatro emisiones fallidas de esta sesión, que casi agotan el límite de 5/hora, no
habrían consumido cuota real.

### 2.3 Renovación

Automática, en segundo plano, sin cron y sin copiar nada: Caddy sirve el
certificado desde su propio almacén, así que no hay un segundo sitio donde
dejarlo. Las trampas 6 y 7 (permisos de root y `cp` silencioso) **no tienen
dónde ocurrir**, porque el paso de copia desaparece del proceso.

### 2.4 La única trampa nueva: el volumen `/data`

Caddy guarda certificados y claves en `/data`. **Si ese volumen no persiste,
Caddy vuelve a emitir en cada reinicio y agota el límite de Let's Encrypt.** Es
el fallo más reportado de Caddy en producción, y la contrapartida honesta de todo
lo anterior.

Se resuelve con dos volúmenes con nombre en el compose, y —dado el historial de
esta sesión— con `name:` explícito, como ya tienen `postgres_data` y compañía,
para que un nombre de proyecto distinto nunca pueda dejarlos huérfanos:

```yaml
volumes:
  caddy_data:
    name: ellysia_caddy_data   # certificados y claves ACME — NO borrar
  caddy_config:
    name: ellysia_caddy_config
```

Merece un comentario en el compose tan explícito como el que ya lleva
`certbot-webroot`.

---

## 3. La configuración: `Caddyfile`

Traducción directa de la estructura actual. Sirve como referencia de
implementación, no como fichero final.

```caddyfile
{
	# Contacto para avisos de caducidad. Sin esto Caddy emite igual, pero
	# nadie recibe aviso si la renovación se atasca.
	email gmiganescu@gmail.com
}

# ── Fragmentos reutilizables ────────────────────────────────────
# Equivalente a proxy-common.conf. Caddy ya envía X-Forwarded-For,
# X-Forwarded-Proto y X-Forwarded-Host, y preserva el Host original,
# por defecto: solo hay que añadir X-Real-IP.
(api_backend) {
	reverse_proxy Ellysia-API:5000 {
		header_up X-Real-IP {remote_host}
	}
}

(spa) {
	root * /srv
	@assets path /assets/*
	header @assets Cache-Control "public, max-age=31536000, immutable"
	try_files {path} /index.html
	file_server
}

# ── SPA (Vue) ───────────────────────────────────────────────────
ellysia.es, www.ellysia.es {
	encode gzip
	request_body { max_size 20MB }
	header Strict-Transport-Security "max-age=31536000; includeSubDomains"

	# Rutas del SPA que cuelgan de un prefijo de la API. Van PRIMERO:
	# los `handle` son mutuamente excluyentes y se evalúan en el orden
	# escrito, sin las reglas de precedencia de `location =` de Nginx.
	@spa_bajo_prefijo_api path /themis/ /themis/escaneos \
		/aegis/ /aegis/generador \
		/iris/ /iris/analisis /iris/conexiones \
		/acheron/ /acheron/boveda \
		/hygeia/ /hygeia/activos /hygeia/etiquetas
	handle @spa_bajo_prefijo_api {
		import spa
	}

	# El resto de esos prefijos es la API.
	@api path /oauth/* /users /users/* /system /system/* \
		/plans /plans/* /organizations /organizations/* \
		/themis/* /aegis/* /iris/* /acheron/* /hygeia/*
	handle @api {
		import api_backend
	}

	handle {
		import spa
	}
}

# ── API ─────────────────────────────────────────────────────────
api.ellysia.es {
	encode gzip
	request_body { max_size 20MB }
	header Strict-Transport-Security "max-age=31536000; includeSubDomains"
	import api_backend
}

# ── Acceso por IP / localhost (desarrollo) ──────────────────────
# Sustituye al bloque `localhost` de nginx.conf, que lleva un
# "BORRAR CUANDO..." desde hace meses. En un VPS público este bloque
# es lo que responde a quien escanee la IP a pelo: decidir si debe
# existir es parte de esta migración, no un resto que se arrastra.
:80 {
	import spa
}
```

### 3.1 Qué mejora y qué no

**Mejora:** desaparece la precedencia implícita de Nginx. En `api-locations.conf`
un `location = /users` gana siempre sobre `location /users/`, **sin importar el
orden en el fichero** — precisamente lo que hizo invisible el choque de `/users`.
En Caddy los `handle` se evalúan en el orden escrito: lo que se lee es lo que
pasa.

**No mejora:** la tabla de rutas sigue existiendo, y sigue habiendo que
mantenerla sincronizada con `run.py` y con el router del SPA. **El test
`API/tests/unit/test_nginx_api_locations.py` sigue siendo necesario** — habrá que
adaptar su parser al `Caddyfile` y renombrarlo. Su valor no cambia: es lo único
que convierte esa divergencia en un fallo de CI.

Y el choque de `/users` **no lo resuelve ningún proxy**: si una misma URL es a la
vez endpoint real y ruta del SPA, ninguna herramienta puede adivinar cuál sirve.
El renombrado a `/usuarios` (commit `85c57b52`) sigue siendo la solución correcta.

---

## 4. Dos niveles opcionales que sí eliminan la tabla

No forman parte de esta migración, pero conviene saber que existen porque cambian
el techo de lo que se puede simplificar.

### Nivel 2 — el SPA llama a `api.ellysia.es`

Hoy `useApi.js` hace `apiFetch('/users/mfa')`, mismo origen. Si en su lugar
apuntara a `https://api.ellysia.es`, el host del SPA **no necesitaría proxear
ninguna ruta de API** y toda la tabla desaparecería: dos bloques de tres líneas.

**Coste:** CORS. La API tendría que emitir `Access-Control-Allow-Origin` para el
origen del SPA y responder a los preflight `OPTIONS`, y las cookies o cabeceras
de auth pasan a ser cross-origin. Es trabajo real y no trivial de verificar.

### Nivel 3 — prefijar toda la API con `/api`

La solución estructural: `@api path /api/*`, un solo matcher, colisión
imposible por construcción, para siempre.

**Coste:** rompe a todos los `hygeia-agent` ya desplegados, que hacen `POST` a
`/hygeia/ingest`. Exigiría un periodo de transición sirviendo ambos prefijos.
Solo tiene sentido antes de que haya agentes en producción — es decir, ya no, o
coordinado con una versión mayor del agente.

---

## 5. La pregunta del código firmado: **no, y por cuatro razones independientes**

Pregunta planteada: *¿los certificados que emite Caddy/Let's Encrypt podrían
reutilizarse para firmar el software de Hygeia Agent?*

La respuesta es no, y no es una limitación de Caddy: es de Let's Encrypt y del
propio modelo de confianza del código firmado. Cada una de estas razones basta
por sí sola.

**1. El EKU lo prohíbe explícitamente.** Un certificado X.509 lleva codificado su
propósito en el campo *Extended Key Usage*. Los de Let's Encrypt llevan
`id-kp-serverAuth` y `id-kp-clientAuth`, y nada más. Firmar código exige el EKU
`codeSigning` (OID 1.3.6.1.5.5.7.3.3). Los verificadores comprueban ese campo:
un certificado TLS presentado para firmar se rechaza sin llegar a mirar la firma.

**2. La cadena de confianza es otra.** Windows Authenticode confía en las CA del
Microsoft Trusted Root Program *para el propósito de firma de código*, y Let's
Encrypt no está en ese programa para eso. macOS exige un Developer ID de Apple.
Aunque el EKU fuera correcto, la cadena no validaría en ninguna de las dos.

**3. La custodia de la clave es incompatible.** Desde el 1 de junio de 2023, la
clave privada de cualquier certificado de firma de código públicamente confiable
—OV o EV— debe residir en hardware certificado (FIPS 140-2 nivel 2 o Common
Criteria EAL 4+). El modelo de Let's Encrypt es exactamente el contrario: claves
en software, generadas y rotadas automáticamente cada 60–90 días.

**4. La vida útil es incompatible.** Un certificado de Let's Encrypt dura 90
días; un binario firmado debe seguir validando años después. El código firmado
resuelve eso con *timestamping* (RFC 3161), una contrafirma de una autoridad de
sellado de tiempo que congela la validez en el momento de firmar. Sin ella, cada
binario quedaría "caducado" a los tres meses.

### 5.1 Lo que Hygeia Agent sí necesita, por plataforma

El plan del agente (`plans/feature/hygeia/hygeia-backend.md` §15) prevé una
matriz de cinco binarios *"firmados una sola vez en el pipeline"*. Firmar es una
cosa distinta en cada plataforma:

| Plataforma | Mecanismo real | Coste |
|---|---|---|
| **Linux (.deb)** | **GPG, no X.509.** Debian/Ubuntu no verifican el `.deb` suelto: verifican los metadatos del repositorio (`Release`/`InRelease`) firmados con GPG | **Gratis** |
| **Windows (.exe)** | Certificado OV de firma de código, clave en token o HSM en la nube | De pago, renovación anual |
| **macOS** | Apple Developer ID + notarización | 99 $/año |

El detalle de Linux es el más útil a corto plazo, porque contradice la intuición.
La firma de `.deb` individuales (`debsigs`) **existe pero está desactivada por
defecto** — `/etc/dpkg/dpkg.cfg` trae `no-debsig`. La cadena de integridad real
va por el repositorio: se firma el fichero `Release` con GPG y el cliente lo
referencia con `signed-by=/ruta/al/llavero` en la fuente de apt. (`apt-key` está
obsoleto y eliminado en Debian 13; no usarlo.)

Y eso conecta con el problema real de hoy:

```bash
sudo apt install ./hygeia-agent_1.0.5_linux_arm64.deb
```

Instalar desde un fichero local **se salta toda verificación de firma**, y además
fue lo que permitió el error de arquitectura del principio de la sesión. El
siguiente paso natural para la distribución del agente no es firmar `.deb`
sueltos: es **publicar un repositorio apt firmado con GPG**, que arregla las dos
cosas de golpe — verificación criptográfica real y `apt` eligiendo la
arquitectura correcta automáticamente. Coste: cero euros.

Sobre Windows, dos datos de 2026 por si se plantea: desde el 23 de febrero de
2026 el CA/B Forum limita los certificados de firma de código a 459 días, así que
la renovación pasa a ser anual; y **EV ya no compensa sobre OV**, porque la
ventaja histórica —reputación inmediata en SmartScreen— la eliminó Microsoft en
2024.

Dado el objetivo declarado del proyecto (construirlo, no venderlo), la
recomendación es **repositorio apt firmado con GPG para Linux, y nada para
Windows/macOS hasta que exista alguien que instale el agente ahí**.

---

## 6. Plan de migración

### Fase 1 — Preparar (sin tocar producción)
1. Escribir `web/Caddyfile` traduciendo los cuatro bloques `server` actuales.
2. Reescribir `web/Dockerfile`: `FROM caddy:2-alpine` en la etapa final, `COPY --from=builder /app/dist /srv`, `COPY Caddyfile /etc/caddy/Caddyfile`. La etapa de build de la SPA no cambia.
3. `docker-compose.yml`: añadir `caddy_data` y `caddy_config` con `name:` explícito; eliminar el servicio `certbot`, el volumen `certbot-webroot` y el bind mount `./web/ssl`.
4. Adaptar `API/tests/unit/test_nginx_api_locations.py` para parsear el `Caddyfile`, y renombrarlo a `test_caddy_api_routes.py`. **Debe seguir pasando antes de continuar.**

### Fase 2 — Verificar en local
5. `docker compose --profile container up -d --build web` en local. Caddy emitirá un certificado autofirmado propio para `localhost`, sin ACME.
6. Recorrer a mano las rutas que la tabla protege: `/hygeia/etiquetas`, `/usuarios`, `/themis/escaneos`, `/acheron/boveda`, y una llamada de API real desde el SPA.

### Fase 3 — Desplegar
7. Levantar Caddy. Obtendrá el certificado él solo en el primer arranque.
8. Verificar desde fuera con `openssl s_client` y con `hygeia-agent doctor`.
9. **Solo entonces**, retirar: `crontab -e` (quitar `renew.sh`), `web/ssl/renew.sh`, `web/ssl/generate.ps1`, `web/nginx.conf`, `web/api-locations.conf`, `web/proxy-common.conf`, y los volúmenes `ellysia_certbot-webroot` y los cuatro `ellysiaserver_*` huérfanos.

### Fase 4 — Documentar
10. Reescribir `README.md` §"SSL certificates": las dos secciones actuales (dev autofirmado + producción con sus tres fases y dos "gotchas") se sustituyen por la explicación de que Caddy lo hace solo, más **la única advertencia que queda: no borrar el volumen `ellysia_caddy_data`**.
11. Actualizar `AGENTS.md` y `web/app/CLAUDE.md` donde mencionen Nginx.

### Vuelta atrás
Hasta la fase 3 no se toca producción. Después, revertir es `git revert` del
merge y `up -d --build web`: los certificados de Let's Encrypt emitidos por
certbot siguen en `web/ssl/letsencrypt/` mientras no se borren a mano, así que
el Nginx anterior vuelve a arrancar con el certificado válido.

---

## 7. Qué NO resuelve esta migración

Por honestidad, y para que nadie espere de Caddy lo que no da:

- **El apex `ellysia.es`.** Es una restricción de DNS (un apex no admite CNAME) y con IP dinámica no hay registro A posible. Se arregla el día del VPS, no con un proxy.
- **La tabla de rutas.** Sigue existiendo y sigue necesitando su test, salvo que se adopte el Nivel 2 o el Nivel 3 (§4).
- **La firma del agente.** No tiene relación con el TLS del servidor (§5).
- **Los dos checkouts del servidor** (`~/Ellysia` y `~/EllysiaServer`). Es higiene operativa pendiente, independiente de esto.
