/**
 * Presentación de los tipos de storable: lo que se ve en pantalla y cómo se
 * comporta el formulario. Es la otra mitad de `storableSchema.js`, y la que
 * NO viaja al paquete compartido — la extensión de navegador no pinta este
 * formulario y no necesita estas cadenas.
 *
 * Indexado por `kind`, y dentro por la clave del campo, para que la
 * correspondencia con el esquema sea comprobable. `storableTypes.js` compone
 * ambos ficheros y `acheron.schema.test.mjs` verifica que no se desincronizan:
 * un campo sin etiqueta pinta un `undefined`, y una etiqueta sin campo es
 * código muerto que nadie ve.
 *
 * Por campo, más de `label`:
 *   - prefill:   en EDICIÓN se pre-rellena con el valor actual. Los secretos
 *                más sensibles (contraseña, PAN, CVV) van a false: se dejan en
 *                blanco y solo se reescriben si el usuario teclea algo.
 *                Ojo, NO equivale a `!secret` del esquema: `documentId`,
 *                `iban`, `swiftBic`, `accountNumber` y `licenseKey` son
 *                secretos y aun así se pre-rellenan. Son dos ejes distintos.
 *   - numeric:   teclado/inputmode numérico.
 *   - multiline: se pinta como textarea.
 *   - minLength: longitud mínima exigida cuando el campo lleva valor.
 *
 * `subtitleKey` no lo lee nadie hoy; se conserva tal cual estaba, pendiente de
 * decidir si la lista debe mostrar ese subtítulo o si sobra.
 */
export const STORABLE_LABELS = {
  account: {
    label: 'Cuenta', plural: 'Cuentas', newLabel: 'Nueva cuenta', subtitleKey: 'username',
    fields: {
      username: { label: 'Usuario / Email' },
      domain: { label: 'Dominio / Servicio' },
      password: { label: 'Contraseña', prefill: false },
    },
  },
  creditcard: {
    label: 'Tarjeta', plural: 'Tarjetas', newLabel: 'Nueva tarjeta', subtitleKey: 'cardNumber',
    fields: {
      cardHolderName: { label: 'Titular' },
      cardNumber: { label: 'Número de tarjeta', prefill: false, numeric: true, minLength: 4 },
      expirationDate: { label: 'Caducidad (MM/YY)' },
      cvv: { label: 'CVV', prefill: false, numeric: true },
      postalCode: { label: 'Código postal' },
    },
  },
  securenote: {
    label: 'Nota segura', plural: 'Notas', newLabel: 'Nueva nota', subtitleKey: 'content',
    fields: {
      content: { label: 'Contenido', multiline: true },
    },
  },
  identity: {
    label: 'Identidad', plural: 'Identidades', newLabel: 'Nueva identidad', subtitleKey: 'fullName',
    fields: {
      fullName: { label: 'Nombre completo' },
      email: { label: 'Email' },
      phone: { label: 'Teléfono' },
      address: { label: 'Dirección' },
      city: { label: 'Ciudad' },
      country: { label: 'País' },
      documentId: { label: 'Documento (DNI/Pasaporte)' },
    },
  },
  bankaccount: {
    label: 'Cuenta bancaria', plural: 'Bancos', newLabel: 'Nueva cuenta bancaria', subtitleKey: 'bankName',
    fields: {
      bankName: { label: 'Banco' },
      holder: { label: 'Titular' },
      iban: { label: 'IBAN' },
      swiftBic: { label: 'SWIFT / BIC' },
      accountNumber: { label: 'Número de cuenta' },
    },
  },
  wifi: {
    label: 'Wi-Fi', plural: 'Wi-Fi', newLabel: 'Nueva red Wi-Fi', subtitleKey: 'ssid',
    fields: {
      ssid: { label: 'Nombre de red (SSID)' },
      password: { label: 'Contraseña', prefill: false },
      securityType: { label: 'Seguridad (WPA2/WPA3)' },
    },
  },
  license: {
    label: 'Licencia', plural: 'Licencias', newLabel: 'Nueva licencia', subtitleKey: 'product',
    fields: {
      product: { label: 'Producto' },
      licenseKey: { label: 'Clave de licencia' },
      licensedTo: { label: 'Licenciado a' },
      version: { label: 'Versión' },
    },
  },
}
