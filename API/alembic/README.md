# Alembic — Migraciones de Base de Datos para Ellysia

## ¿Qué es Alembic?

Alembic es la herramienta oficial de migraciones de esquema para SQLAlchemy. Permite
versionar los cambios de la base de datos (crear/alterar/eliminar tablas, columnas,
índices, constraints) de forma **incremental, reproducible y reversible**.

Cada cambio de esquema se escribe en un script Python dentro de `versions/` y se
registra en la tabla `alembic_version` en PostgreSQL. Esto permite que cualquier
desarrollador o entorno (dev, staging, producción) evolucione su base de datos sin
perder datos.

## ¿Qué mejora respecto al sistema anterior?

| Antes (`create_all`) | Ahora (Alembic) |
|---|---|
| `Base.metadata.create_all(engine)` solo creaba tablas nuevas; **no alteraba existentes**. | Los scripts de migración pueden `ALTER TABLE ADD COLUMN`, modificar tipos, renombrar, etc. |
| Cambiar una columna requería `DROP` manual o usar `_init_db()` destructivo que borraba **todos** los datos. | Cada migración preserva los datos; solo cambia la estructura. |
| No había historial versionado del esquema en git. | Cada migración es un fichero `.py` en `versions/` que se commitea y revisa. |
| El estado del esquema dependía de qué `model.py` se había ejecutado sobre la DB. | La tabla `alembic_version` registra exactamente qué revisiones se han aplicado. |

## Estructura de ficheros

```
API/alembic/
├── alembic.ini              # Configuración (URL dinámica desde env.py)
├── env.py                   # Lee credenciales de SecOpsConfig (.env), importa todos los modelos
├── script.py.mako           # Plantilla para nuevas revisiones
└── versions/                # Migraciones (una por cambio de esquema)
    └── 819ead62a00a_baseline_v3_2.py   # Baseline: esquema completo inicial (37 tablas)
```

## Cómo se usa en el día a día

### Requisito previo

El directorio de trabajo debe ser `API/` y las variables de entorno de base de datos
(`POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `POSTGRES_HOST`, `POSTGRES_PORT`)
deben estar definidas (vía `.env`).

### 1. Generar una nueva migración (tras cambiar un modelo)

```bash
cd API
alembic revision --autogenerate -m "añadir columna priority a Scan"
```

Esto genera un fichero nuevo en `versions/` con dos funciones: `upgrade()` (aplicar) y
`downgrade()` (revertir).

**Importante:** Revisar siempre el script generado. El autogenerate de Alembic es bueno
pero no perfecto: no detecta renombrados de columna, ni cambios de server default, ni
algunos casos de herencia `joined-table` (como `Scan` → `NmapScan`). Ajusta manualmente
lo necesario.

### 2. Aplicar migraciones pendientes

```bash
alembic upgrade head
```

Ellysia ejecuta esto automáticamente al arrancar (`run.py → _run_migrations()`), así que en
producción/Docker no hace falta correrlo manualmente. En desarrollo, tras generar una
nueva migración, aplicarla antes de arrancar la app.

### 3. Revertir la última migración

```bash
alembic downgrade -1
```

### 4. Ver estado actual

```bash
alembic current          # ¿En qué revisión está la DB?
alembic history          # Historial de revisiones sin aplicar
```

### 5. Marcar DB existente sin ejecutar DDL

Si la DB ya tiene las tablas creadas (p.ej. por un deploy anterior con `create_all`)
pero no tiene la tabla `alembic_version`:

```bash
alembic stamp head       # Registra la versión actual sin ejecutar SQL
```

## Flujo en Docker

El Dockerfile ya copia `alembic.ini` y `alembic/` al contenedor. Al arrancar:

| Perfil | Contenedor | ¿Ejecuta migraciones? |
|---|---|---|
| `container` | `Ellysia-API` | Sí — `run.py` llama a `_run_migrations()` antes de arrancar el servidor. |
| `container` | `Ellysia-Worker` | No — el worker no toca el esquema; la API ya lo ha aplicado. |
| `dev` | `python run.py` local | Sí — `run.py` llama a `_run_migrations()` en cada arranque (salvo `fresh_db_init=True`). |

## Fresh DB Init (`CREATE_DATABASE=true`)

Cuando se configura `CREATE_DATABASE=true` en `API/.env`, la app ejecuta `_init_db()`:

1. `DROP DATABASE IF EXISTS` + `CREATE DATABASE`
2. `_run_migrations()` → `alembic upgrade head` (crea todas las tablas)
3. Seed: usuario `root`, atributos, y temas de concienciación (`Topic`)

Esta ruta **no debería usarse en producción** — es destructiva. Para entornos reales,
las migraciones de Alembic gestionan la evolución del esquema sin pérdida de datos.

## Notas específicas de Ellysia

### Modelos con herencia joined-table

Las siguientes jerarquías usan herencia de tabla unida (polymorphic), que puede
confundir al autogenerate:

- `Document` → `AegisDocument`, `SentinelDocument`, `IrisDocument`
- `Scan` → `NmapScan`, `NiktoScan`, `OpenVASScan`
- `Storable` → `Account`, `CreditCard`, `SecureNote`, `Identity`, `BankAccount`, `WifiNetwork`, `SoftwareLicense`

**Regla:** tras generar una migración que toca estas tablas, revisa que las FK
polimórficas sean correctas y que no haya instrucciones duplicadas.

### Añadir nuevos modelos

Si creas un nuevo `model.py` en un módulo:

1. Añade un `import` en `env.py` para que el nuevo modelo se registre en `Base.metadata`.
2. Genera la migración con `alembic revision --autogenerate -m "añadir modelo Foo"`.
3. Revisa el script, aplica con `upgrade head`.

### Tests

Los tests (`tests/conftest.py`) **no usan Alembic** — crean las tablas directamente con
`Base.metadata.create_all()`. Esto es intencionado: los tests son efímeros, no tienen
datos que preservar, y `create_all` es más rápido que ejecutar una pila completa de
migraciones. Las migraciones de Alembic se relegan a los entornos con datos (dev real,
stage, producción).

### Convenciones

- Las migraciones se commitean junto con los cambios en `model.py`.
- Nunca edites una migración que ya se ha aplicado a un entorno — crea una nueva.
- Los `downgrade()` deben mantenerse funcionales (entornos de stage hacen rollback).
- El revision ID se genera automáticamente (hash); el slug lo pones tú en el `-m`.
