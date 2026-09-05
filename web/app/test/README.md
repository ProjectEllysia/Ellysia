# Suites del cliente de Acheron

Se ejecutan con `node` a secas, sin framework. Salen con código distinto de cero si algo falla,
para poder usarse en CI:

```bash
npm run test:acheron    # interop + CRUD + sync
```

## `acheron-vectors.json` — vectores de interoperabilidad

La criptografía de la bóveda está implementada **dos veces y sin compartir código**: en Java
dentro de [`AcheronCore`](https://github.com/ProjectEllysia/AcheronCore) (la usa la app Android) y
en JavaScript dentro de `web/app/src/acheron/` (la usa esta SPA). Cada una implementa por su
cuenta el mismo formato de cable, así que pueden divergir en silencio.

Lo único que lo impide son estos vectores. `AcheronCore` cifra unas bóvedas de prueba con
contraseñas y salts fijos y vuelca el resultado junto con los valores en claro esperados;
`acheron.interop.test.mjs` las abre y comprueba que descifra exactamente eso. Si una de las dos
implementaciones cambia el formato y la otra no, el test falla.

**No se editan a mano.** Los genera `VectorGenerator` en `AcheronCore`:

```bash
./gradlew test --tests '*VectorGenerator'     # salida en build/acheron-vectors.json
```

| | |
|---|---|
| **Generados desde** | `AcheronCore` @ [`516bb7a`](https://github.com/ProjectEllysia/AcheronCore/commit/516bb7a0f6a02df22fb8ae8f6041e66cdf143d49) |
| **Cobertura** | Argon2id y PBKDF2, con `account`, `creditcard` y `securenote` |

Al actualizarlos hay que anotar aquí la versión de `AcheronCore` de la que salieron: sin eso, un
fallo de interoperabilidad no se puede atribuir a un cambio concreto del motor Java.

## `acheron-schema.json` — el catálogo compartido

El catálogo de tipos de la bóveda (qué es una «cuenta», qué campos tiene una «tarjeta») está
escrito en cuatro sitios: aquí, en la API (`storable_specs.py`), en la app Android
(`StorableTypes.kt`) y en `AcheronCore`. Los cuatro tienen que coincidir en los nombres exactos de
los campos, porque son las claves del JSON de la bóveda.

[`AcheronSchema`](https://github.com/ProjectEllysia/AcheronSchema) es la fuente de verdad común, y
esto es una copia versionada suya. `acheron.schema.test.mjs` comprueba que
`src/acheron/storableSchema.js` no se ha ido por su cuenta.

Se compara contra la copia y no contra el repositorio remoto a propósito: la suite no toca la red,
y una comprobación que necesite internet no es una comprobación, es una fuente de fallos
intermitentes.

**No se edita a mano.** Se actualiza copiando el fichero de `AcheronSchema` a un tag concreto, y
anotando aquí cuál:

| | |
|---|---|
| **Copiado de** | `AcheronSchema` @ [`v1.0.0`](https://github.com/ProjectEllysia/AcheronSchema/releases/tag/v1.0.0) (`05f5be7`) |

Al añadir un tipo o un campo, el orden es: primero `AcheronSchema`, después esta copia y el
esquema de la SPA. Al revés, la suite falla — que es justo lo que debe hacer.

> Estos vectores cubren la dirección **Java → JS**: comprueban que este cliente sabe leer lo que
> escribe el Java. La dirección contraria —que el Java sepa leer lo que escribe este cliente— no
> la cubre nadie todavía; es el asunto de
> [#486](https://github.com/ProjectEllysia/EllysiaServer/issues/486).
