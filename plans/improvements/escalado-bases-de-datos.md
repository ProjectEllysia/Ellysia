# Escalado de base de datos — Postgres

> Documento de diseño, no código existente. Nace de una discusión sobre si el crecimiento
> de tráfico (en particular el previsto por [Hygeia](../feature/hygeia/hygeia-backend.md),
> con ingesta de telemetría de alto volumen) obliga a acoplar una segunda base de datos de
> otro paradigma (p. ej. MongoDB) o a shardear. Conclusión: **no, todavía no** — Postgres
> aguanta varios escalones más sin salir del paradigma relacional. Este documento cubre solo
> los pasos que son aplicables **cuando llegue el momento**, no un rediseño especulativo.

---

## 1. Por qué no un segundo paradigma (MongoDB u otro)

Toda la arquitectura actual (`infrastructure/UnitOfWork`, `teardown_request`/`job_context`,
los repositorios de cada módulo) asume **una sola frontera transaccional Postgres**. Los
datos semi-estructurados que llevarían a plantear un documento NoSQL ya se resuelven con
columnas `JSONB` (patrón usado en todo el repo: `metrics` de `AssetSnapshot`, `details` de
`Anomaly`, `labels`, etc.).

Acoplar Mongo (o cualquier otra BD de otro paradigma) para una sola tabla de alto volumen
introduciría una segunda transacción no atómica con la primera — justo el tipo de
acoplamiento que módulos como Hygeia necesitan evitar (persistir snapshot + evaluar +
abrir/cerrar anomalía en una única transacción, ver `hygeia-backend.md` §6) — a cambio de
poco: Postgres+JSONB ya cubre el caso de uso. **No se recomienda.**

---

## 2. Alta disponibilidad (redundancia) — aplicable sin tocar código

Réplicas de streaming (`primary` + N `replicas`) es una capacidad nativa de Postgres,
ortogonal al código de aplicación: el engine/session singleton de `infrastructure` sigue
apuntando a un único DSN, resuelto por un proxy delante de la BD.

| Pieza | Qué hace | Dónde vive |
|---|---|---|
| Streaming replication | Replica el WAL del primary a N réplicas (async o sync) | Config de Postgres / contenedor |
| Failover | Promociona una réplica a primary si el primary cae | Patroni (o el failover gestionado si se migra a un Postgres cloud tipo RDS/Cloud SQL) |
| Proxy | Los clientes siempre hablan con "un" endpoint; el proxy enruta al primary vigente | pgbouncer / HAProxy delante del Postgres actual |

**Esfuerzo:** 🔧 medio, pero es trabajo de infraestructura/ops (compose, contenedores,
proxy), no de `src/`. Cero cambios en `UnitOfWork`, repositorios o modelos.

**No aplicar todavía:** no hay hoy una necesidad operativa (SLA de uptime, tráfico) que lo
justifique; queda documentado como el paso natural cuando la disponibilidad del Postgres
único empiece a doler.

---

## 3. Reparto de lecturas (read replicas) — aplicable, esfuerzo acotado

Una vez existan réplicas (§2), tiene sentido enviarles las lecturas pesadas y dejar el
primary solo para escritura + lecturas que necesiten consistencia fuerte.

**Candidatos claros a leer de réplica** (solo lectura, toleran una réplica con unos
segundos de retraso):
- `GET /hygeia/assets/{id}/metrics` (serie temporal, Fase 5 de Hygeia) — el caso de uso
  que motivó esta discusión.
- Listados (`GET /hygeia/assets`, `GET /hygeia/alerts`, `GET /themis/scans`, etc.).

**Qué tocaría en código:** un segundo engine/session "read-only" en `infrastructure`, y que
cada repositorio decida explícitamente qué queries van a cuál. Cambio acotado (unas pocas
líneas en `infrastructure`, no un rediseño) — pero **solo tiene sentido después de §2**, no
antes: sin réplicas no hay a dónde enrutar.

**Esfuerzo:** ⚡ rápido una vez exista la infraestructura de §2.

---

## 4. Lo que se descarta explícitamente (por ahora)

Documentado para no volver a discutirlo desde cero cuando se replantee el techo:

- **Sharding de escritura (Citus u otro)** — solo se justificaría si una sola tabla
  (candidato: `AssetSnapshot` de Hygeia, shardeada por `asset_id`) superara lo que
  TimescaleDB ya resuelve (ver `hygeia-backend.md` §3, "techo" documentado). Es más
  invasivo que §2/§3 y no hay hoy volumen que lo requiera.
- **Segunda BD de otro paradigma (MongoDB, etc.)** — descartado en §1; no se ha
  identificado ningún caso de uso del repo que Postgres+JSONB no cubra ya.

---

## 5. Orden recomendado si/cuando haga falta

1. §2 (HA con réplicas + failover) — solo cuando la disponibilidad del Postgres único sea
   un problema real, no antes.
2. §3 (routing de lecturas a réplica) — inmediatamente después de §2, aprovechando la
   infraestructura ya montada.
3. Reevaluar sharding/Timescale **solo** si `AssetSnapshot` (o tabla equivalente) de Hygeia
   alcanza el volumen que su propio plan ya señala como techo — no antes, y no como parte
   de este documento.

*Documento vivo. Si en el futuro aparece un caso de uso concreto que Postgres+JSONB no
cubra, documentarlo aquí antes de decidir una segunda BD — no como discusión especulativa.*
