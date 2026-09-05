# Diseño: el ciclo de vida de la sesión desbloqueada en la extensión

Documento de decisión para [#483](https://github.com/ProjectEllysia/EllysiaServer/issues/483).
Fechado el **2026-09-05**. Decide **dónde vive la bóveda desbloqueada** en la extensión de
navegador de Acheron, cuánto dura y qué la cierra.

Es una decisión de **seguridad**, no de comodidad, y por eso se toma antes de escribir la
extensión: tomada por defecto mientras se persigue un bug de autocompletado, saldrá mal.

## Contexto

Acheron es la bóveda de credenciales de Ellysia. El servidor es *zero-knowledge*: guarda un blob
cifrado que no sabe leer, y la contraseña maestra nunca sale del cliente.

Abrir una bóveda cuesta tres pasos: derivar una clave desde la contraseña maestra con Argon2id,
validar el *checker* con ella, y usarla para desenvolver la `vaultKey` que cifra cada campo. Lo que
queda en memoria tras eso —la `vaultKey` desenvuelta— **es** la bóveda abierta: quien la tenga
puede leer todas las credenciales del usuario sin conocer su contraseña maestra.

El problema propio de la extensión es que **Manifest V3 recicla el service worker** tras unos
segundos de inactividad. Al morir se lleva la memoria, y con ella la `vaultKey`. Sin una decisión
explícita, la bóveda se cerraría sola constantemente y la extensión sería inusable.

## Estado actual verificado (2026-09-05)

- **La `vaultKey` se importa como NO extraíble.** `OpenVault` en `AcheronCoreWeb` la declara
  `readonly vaultKey: CryptoKey`, importada con `extractable = false`. Ni el propio código puede
  volver a sacar sus bytes.
- **Desbloquear cuesta ~137 ms.** Medido en Chrome real durante el espolón de
  [#482](https://github.com/ProjectEllysia/EllysiaServer/issues/482), con los parámetros de
  producción: Argon2id, 64 MiB, 3 pasadas.
- **Las extensiones de Chrome no corren en Android**, así que esos 137 ms no son una estimación de
  escritorio para un caso móvil: son el número.
- **La API expone una sonda barata**, `GET /acheron/vault/revision`, que devuelve sólo el contador
  de revisión sin ciphertext. Relevante porque permite mantener el estado fresco sin descargar la
  bóveda entera.

Ese coste de desbloqueo es el dato que más condiciona el diseño, y en la dirección buena. En un
gestor cuyo KDF costara varios segundos, la presión por cachear agresivamente sería enorme. Aquí
**re-desbloquear es barato**, así que la decisión puede tomarse con criterio de seguridad sin pagar
un precio de usabilidad desproporcionado.

## Las cuatro preguntas

### 1. ¿Dónde vive la sesión cuando el service worker muere?

**Decisión: en `chrome.storage.session`, nunca en disco.**

Las opciones consideradas:

| Opción | Por qué no / por qué sí |
|---|---|
| No persistir nada | Seguro y **inusable**: el worker muere cada 30 s y pediría la maestra continuamente |
| `chrome.storage.local` o IndexedDB | **Descartado.** Escriben a disco. Cualquiera con acceso al perfil abre la bóveda sin la contraseña maestra, y eso tira la propiedad *zero-knowledge* del lado del cliente |
| *Offscreen document* que sostenga el `CryptoKey` | Conserva la no-extraibilidad, pero `chrome.offscreen` exige declarar un **motivo** de una lista cerrada, y ninguno describe «sostener estado criptográfico». Usar `WORKERS` o `LOCAL_STORAGE` como pretexto es la clase de cosa que un revisor de la Chrome Web Store rechaza, con razón |
| **`chrome.storage.session`** | Vive **sólo en memoria**, se vacía al cerrar el navegador y admite `setAccessLevel('TRUSTED_CONTEXTS')`, que la deja fuera del alcance de los content scripts |

### 2. Si se persiste algo, ¿qué exactamente?

**Decisión: la `vaultKey` desenvuelta en bytes, y nunca la contraseña maestra.**

Guardar la contraseña maestra sería peor por una razón que no es técnica: **los usuarios la
reutilizan**. Una contraseña maestra filtrada abre además su correo. La `vaultKey` sólo abre esta
bóveda, y rotarla es un `changePassword`.

Esto obliga a un compromiso que conviene mirar de frente: `chrome.storage.session` sólo admite
valores serializables, así que la clave deja de ser un `CryptoKey` no extraíble y pasa a ser bytes.
**Se pierde la no-extraibilidad.**

El compromiso es aceptable porque esa propiedad protege menos de lo que parece en este escenario
concreto. La no-extraibilidad separa *usar* la clave de *exfiltrarla*, y sirve contra un atacante
que puede llamar a la API de cifrado pero no leer memoria. Aquí, cualquier atacante capaz de leer
`chrome.storage.session` ya ejecuta código **dentro de la extensión**, y desde ahí puede
sencillamente pedirle que descifre la bóveda entera y exfiltrar el texto en claro. Frente a ese
atacante, la clave no extraíble no cambia el desenlace.

Lo que sí cambia el desenlace es que **nada de eso toque el disco**, y ésa es la línea que este
diseño no cruza.

### 3. ¿Cuánto dura, y qué la cierra?

**Decisión: 15 minutos de inactividad, re-armados en cada uso.** Y se cierra, además, ante:

- **Cierre del navegador** — gratis, `chrome.storage.session` se vacía sola.
- **Bloqueo de la sesión del sistema operativo** — `chrome.idle.onStateChanged` entrega el estado
  `locked`. Si el usuario bloquea su equipo, la bóveda se bloquea con él.
- **Un bloqueo explícito** en la interfaz, siempre visible y a un clic.
- **Un cambio de contraseña maestra** desde cualquier otro cliente, detectable porque `revision`
  avanza y la `vaultKey` guardada deja de desenvolver.

Quince minutos es un valor conservador que se puede sostener **precisamente porque re-desbloquear
cuesta 137 ms**. La justificación habitual para timeouts largos es que desbloquear duele; aquí no.

Debe ser configurable, con un máximo acotado. Un «no bloquear nunca» no debería existir: convierte
un robo de equipo desatendido en un robo de todas las credenciales.

### 4. ¿Qué ve un atacante con ejecución de código en una página?

Ésta es la pregunta que distingue una extensión de autocompletado de la SPA, y la que más
superficie añade.

Un content script vive en páginas que la extensión no controla. Las reglas que se derivan:

- **La `vaultKey` nunca sale del contexto privilegiado.** Los content scripts no la reciben ni
  pueden leerla: `setAccessLevel('TRUSTED_CONTEXTS')` los deja fuera de `chrome.storage.session`, y
  el descifrado ocurre en el service worker.
- **Rellenar exige un gesto del usuario.** Nada de autocompletar al cargar la página. Una página
  hostil no puede provocar un rellenado que el usuario no pidió.
- **Se rellena una credencial, no se entrega la bóveda.** El mensaje que cruza al content script
  lleva los valores de *un* storable, el que el usuario eligió, y nada más. No existe un mensaje
  que devuelva la lista completa.
- **El origen decide, y lo decide el proceso privilegiado.** La correspondencia entre página y
  credencial se resuelve en el service worker usando `matchKey` y la regla de
  [#484](https://github.com/ProjectEllysia/EllysiaServer/issues/484) —host exacto, sin subdominios,
  sólo `https`—, contra el origen real de la pestaña y no contra lo que el content script diga que
  es. Un content script que mienta sobre su origen no consigue nada.
- **Sin iframes de terceros.** No se rellena dentro de un iframe cuyo origen no coincida con el de
  la página principal; es la vía clásica de robo de credenciales por *clickjacking*.

## Consecuencias para la implementación

Lo que [#485](https://github.com/ProjectEllysia/EllysiaServer/issues/485) debe respetar:

1. La sesión desbloqueada vive en `chrome.storage.session` con `TRUSTED_CONTEXTS`. Ni
   `storage.local`, ni IndexedDB, ni `localStorage`.
2. Se guarda la `vaultKey` desenvuelta y un instante de último uso. Nunca la contraseña maestra.
3. Todo el descifrado ocurre en el service worker. El content script recibe valores, nunca claves.
4. Rellenar exige gesto del usuario, coincidencia de origen resuelta en el proceso privilegiado, y
   nada de iframes de origen distinto.
5. Bloqueo por inactividad a los 15 minutos, más `chrome.idle` en estado `locked`, más bloqueo
   manual. Configurable con techo.

## Lo que este documento no ha verificado

Con la misma disciplina que el espolón de [#482](https://github.com/ProjectEllysia/EllysiaServer/issues/482):
lo de arriba es diseño apoyado en el comportamiento **documentado** de las APIs, no medido. Antes
de construir sobre ello, [#485](https://github.com/ProjectEllysia/EllysiaServer/issues/485) debería
confirmar con una sonda pequeña, y en Chrome real, dos cosas:

- Que `chrome.storage.session` **no deja rastro en disco** —inspeccionando el directorio del perfil
  tras guardar un valor reconocible— y que se vacía al cerrar el navegador.
- Que `setAccessLevel('TRUSTED_CONTEXTS')` **bloquea de verdad** la lectura desde un content
  script, comprobando que el intento falla.

Si alguna de las dos no se cumple, la opción del *offscreen document* vuelve a la mesa pese a su
problema con los motivos declarables, y esta decisión hay que revisarla entera.
