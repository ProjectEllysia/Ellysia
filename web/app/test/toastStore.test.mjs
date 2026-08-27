/**
 * Tests de `toastStore` — la cuenta atrás del toast (#127).
 *
 * Node puro, sin framework, misma convención que el resto de `test/`.
 * Con timers reales y duraciones cortas, como en `usePolling.test.mjs`.
 *
 * Lo que se comprueba es justo lo que el store hacía mal:
 *   - que `duration <= 0` sea un toast persistente y no uno que desaparece
 *     en el mismo frame (`setTimeout(dismiss, 0)`);
 *   - que `pause()`/`resume()` conserven el tiempo que quedaba en vez de
 *     reiniciarlo o perderlo;
 *   - que `dismiss()` no deje un timeout huérfano capaz de cerrar el toast
 *     siguiente antes de tiempo.
 */

import assert from 'node:assert/strict'
import { createPinia, setActivePinia } from 'pinia'

const { useToastStore } = await import('../src/stores/toastStore.js')

const sleep = (ms) => new Promise(r => setTimeout(r, ms))

let failures = 0
async function test(name, fn) {
  setActivePinia(createPinia())   // store limpio por test
  try { await fn(); console.log(`  ok   ${name}`) }
  catch (err) { failures++; console.error(`  FAIL ${name}\n       ${err.message}`) }
}

console.log('toastStore')

await test('duration <= 0 deja el toast fijo', async () => {
  const toast = useToastStore()
  toast.show('persistente', 'warn', 0)
  assert.equal(toast.visible, true)
  await sleep(80)
  assert.equal(toast.visible, true, 'se cerro solo pese a pedir duracion 0')
  toast.dismiss()
  assert.equal(toast.visible, false, 'dismiss() no cierra el toast persistente')
})

await test('se cierra solo al agotar su duracion', async () => {
  const toast = useToastStore()
  toast.show('efimero', 'info', 60)
  await sleep(30)
  assert.equal(toast.visible, true, 'se cerro antes de tiempo')
  await sleep(60)
  assert.equal(toast.visible, false, 'no se cerro al agotarse')
})

await test('pause() congela la cuenta atras', async () => {
  const toast = useToastStore()
  toast.show('leyendome', 'error', 60)
  await sleep(30)
  toast.pause()
  await sleep(120)              // el doble de su duracion, en pausa
  assert.equal(toast.visible, true, 'se cerro estando pausado')
})

await test('resume() reanuda con lo que quedaba, no con la duracion entera', async () => {
  const toast = useToastStore()
  toast.show('leyendome', 'error', 100)
  await sleep(70)              // consumidos ~70, quedan ~30
  toast.pause()
  await sleep(50)
  toast.resume()
  await sleep(10)
  assert.equal(toast.visible, true, 'se cerro antes de agotar lo que quedaba')
  await sleep(60)              // sobrado para esos ~30 restantes
  assert.equal(toast.visible, false, 'reanudo con la duracion entera en vez de con el resto')
})

await test('resume() no revive un toast ya cerrado', async () => {
  const toast = useToastStore()
  toast.show('efimero', 'info', 30)
  await sleep(60)
  assert.equal(toast.visible, false)
  toast.resume()
  assert.equal(toast.visible, false, 'resume() reabrio un toast cerrado')
})

await test('dismiss() no deja un timeout que cierre el toast siguiente', async () => {
  const toast = useToastStore()
  toast.show('primero', 'success', 40)
  await sleep(10)
  toast.dismiss()              // quedaban ~30 ms del primero
  toast.show('segundo', 'success', 120)
  await sleep(60)              // el timeout huerfano ya habria disparado
  assert.equal(toast.visible, true, 'el timeout del primer toast cerro al segundo')
  assert.equal(toast.message, 'segundo')
})

await test('un show() sobre un toast visible reinicia la cuenta atras', async () => {
  const toast = useToastStore()
  toast.show('primero', 'success', 60)
  await sleep(45)
  toast.show('segundo', 'error', 60)
  await sleep(40)              // el primero ya habria expirado
  assert.equal(toast.visible, true, 'el reemplazo heredo la cuenta atras del anterior')
  assert.equal(toast.message, 'segundo')
  assert.equal(toast.type, 'error')
})

console.log(failures ? `\n${failures} test(s) fallaron` : '\nTodos los tests de toastStore pasaron')
process.exit(failures ? 1 : 0)
