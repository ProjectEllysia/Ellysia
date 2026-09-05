/**
 * Esquema de los tipos de storable de Acheron: el CONTRATO DE DATOS, sin nada
 * que se vea en pantalla.
 *
 * Qué categorías existen, qué claves tiene cada una y cuáles son sensibles.
 * Estas claves son las del JSON del vault y las que espera la API, así que
 * tienen que coincidir con `storable_specs.py` (API), `StorableTypes.kt`
 * (móvil) y las clases de `vault/storables/` (AcheronCore). Cambiar un nombre
 * aquí sin cambiarlo allí hace que un cliente no sepa leer lo que escribió otro.
 *
 * Este fichero es el que se moverá a un paquete propio para que lo compartan
 * la SPA y la extensión de navegador; por eso no contiene ni una cadena de
 * texto visible para el usuario. Las etiquetas viven en `storableLabels.js`, y
 * `storableTypes.js` compone ambos para la interfaz.
 *
 * `secret` marca los campos sensibles. Es propiedad del dato, no de la
 * pantalla: la interfaz los enmascara, y la futura extensión necesitará saber
 * cuál es el campo de contraseña para autocompletarlo sin mostrarlo en claro.
 */
export const STORABLE_SCHEMA = [
  {
    kind: 'account', category: 'accounts',
    fields: [
      { key: 'username' },
      { key: 'domain' },
      { key: 'password', secret: true },
    ],
  },
  {
    kind: 'creditcard', category: 'creditcards',
    fields: [
      { key: 'cardHolderName' },
      { key: 'cardNumber', secret: true },
      { key: 'expirationDate' },
      { key: 'cvv', secret: true },
      { key: 'postalCode' },
    ],
  },
  {
    kind: 'securenote', category: 'securenotes',
    fields: [
      { key: 'content' },
    ],
  },
  {
    kind: 'identity', category: 'identities',
    fields: [
      { key: 'fullName' },
      { key: 'email' },
      { key: 'phone' },
      { key: 'address' },
      { key: 'city' },
      { key: 'country' },
      { key: 'documentId', secret: true },
    ],
  },
  {
    kind: 'bankaccount', category: 'bankaccounts',
    fields: [
      { key: 'bankName' },
      { key: 'holder' },
      { key: 'iban', secret: true },
      { key: 'swiftBic', secret: true },
      { key: 'accountNumber', secret: true },
    ],
  },
  {
    kind: 'wifi', category: 'wifinetworks',
    fields: [
      { key: 'ssid' },
      { key: 'password', secret: true },
      { key: 'securityType' },
    ],
  },
  {
    kind: 'license', category: 'licenses',
    fields: [
      { key: 'product' },
      { key: 'licenseKey', secret: true },
      { key: 'licensedTo' },
      { key: 'version' },
    ],
  },
]

/** Entrada del esquema por categoría (clave plural del vault JSON). */
export const SCHEMA_BY_CATEGORY = Object.fromEntries(
  STORABLE_SCHEMA.map((t) => [t.category, t]),
)

/** Entrada del esquema por kind (singular de la API). */
export const SCHEMA_BY_KIND = Object.fromEntries(
  STORABLE_SCHEMA.map((t) => [t.kind, t]),
)
