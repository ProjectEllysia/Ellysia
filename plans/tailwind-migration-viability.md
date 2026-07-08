# Viabilidad de migrar el CSS de `web/app` a Tailwind CSS

## Contexto

Se pide evaluar si merece la pena migrar el CSS plano actual de la SPA Vue 3
(`web/app`) a Tailwind CSS. El usuario no conoce el framework, así que este
documento explica primero qué es Tailwind y qué cambiaría en la práctica, y
después da un veredicto de viabilidad basado en el estado real del código
(auditado en esta sesión, no supuesto).

## ¿Qué es Tailwind y qué NO es?

Tailwind es una librería de **clases de utilidad** (`class="flex gap-4
text-sm text-accent"`) que sustituye el CSS escrito a mano por combinaciones
de clases predefinidas, generadas en build time solo para las clases que
realmente usas en el HTML/JSX/Vue. No es una librería de componentes (no trae
botones, modales ni tablas ya hechos, a diferencia de Vuetify o PrimeVue) y
no impone una arquitectura de la app: convive con Vue Router, Pinia y SFCs
sin fricción.

La promesa de Tailwind es reducir el CSS que se escribe a mano y estandarizar
espaciado/colores/breakpoints mediante un fichero de configuración central
(`tailwind.config.js`) del que salen las clases utilitarias.

## Estado actual verificado de `web/app`

- **Sin librería de UI ni CSS-in-JS previa** que migrar o que choque con
  Tailwind: todos los componentes (botones, badges, modales, toasts) son
  hechos a mano. Esto es un punto a favor — no hay que desmontar nada.
- **52 archivos `.vue`**, 51 con bloque `<style>`, 50 de ellos `scoped`.
  **≈5.443 líneas de CSS totales** (4.991 en bloques `<style>` + 452 en
  `src/assets/css/shared.css`).
- **Ya existe un design system centralizado y bien construido**:
  `shared.css` define ~50 CSS custom properties (`--bg`, `--surface`,
  `--text`, `--accent`, `--success/warn/danger/info`, tipografías, radios),
  con **theming multi-eje real**: 2 temas (`dusk`/`dawn`) × 4 módulos de
  producto (`sentinel`/`aegis`/`iris`/`acheron`) vía atributos
  `[data-theme]` / `[data-module]` en cascada.
- **Uso consistente de esos tokens**: 1.550 usos de `var(--...)` en los
  bloques `<style>`. Solo 54 colores hex hardcodeados, concentrados en el
  módulo Acheron (variantes puntuales del acento violeta) — deuda de tokens
  localizada, no generalizada.
- **Ya existe un patrón "utility-first" artesanal**: `.btn`,
  `.btn--primary/ghost/secondary/danger`, `.badge--running/done/error`,
  `.alert`, `.modal-*`, `.empty-state` en `shared.css`, reutilizado entre
  módulos vía `class="btn btn--primary"`. Es decir, el equipo ya reinventó a
  mano una parte de lo que Tailwind ofrecería out-of-the-box.
- **16 componentes con `@keyframes` propios**, varios elaborados
  (`AcheronView.vue`: `vault-item-in`, skeleton shimmer; `LandingView.vue`:
  escena "elísea" con `hero-rise`, `cue-fall`). Tailwind no sustituye esto:
  requeriría declarar las animaciones en `tailwind.config.js` o mantenerlas
  como CSS aparte de todos modos.
- **31 `@media` queries sin escala de breakpoints estandarizada** (640px,
  680px, 768px, 800px, 860px, 900px, 1100px, ...) — cada componente define su
  propio punto de quiebre. Aquí Tailwind sí aportaría disciplina real.
- **`prefers-reduced-motion: reduce`** respetado en 5 vistas — hay que
  preservarlo en cualquier migración.
- Build limpio para integrar Tailwind: Vite `^8`, sin PostCSS ni SCSS
  configurados, sin conflictos previos.

## Análisis de viabilidad

### A favor de migrar

1. **No hay fricción de integración**: Vite + Tailwind es soporte de primera
   clase, instalación de minutos, sin librería de UI que desmontar antes.
2. **Los tokens ya existen**: los ~50 custom properties de `shared.css` se
   pueden mapear casi 1:1 a `tailwind.config.js` (`theme.extend.colors`,
   etc.), reutilizando el trabajo de diseño ya hecho en lugar de tirarlo.
3. **Estandarizaría los breakpoints** (hoy dispersos e inconsistentes) y
   eliminaría los 54 hex sueltos del módulo Acheron.
4. **Reduce CSS nuevo a futuro**: componentes nuevos se escriben más rápido
   sin abrir un bloque `<style>` por cada uno.

### En contra / coste real

1. **~5.400 líneas de CSS ya escrito, funcionando y con theming complejo
   (2×4 combinaciones)** no se traducen solas. Es trabajo manual
   componente a componente, no un `codemod` fiable: el theming vía
   `[data-theme]`+`[data-module]` en cascada no tiene equivalente directo en
   el modelo `dark:` de Tailwind (pensado para un solo eje binario) — hay
   que resolverlo igualmente con `var()` dentro de las utilidades
   (`bg-[var(--surface)]`), lo que diluye buena parte de la ventaja de
   "clases cortas y legibles" que vende Tailwind.
2. **Las animaciones custom (16 componentes) no se migran**: hay que
   trasladarlas a `tailwind.config.js` o dejarlas en CSS plano dentro del
   propio SFC. El ahorro de líneas real es menor de lo que parece a primera
   vista, porque una parte significativa del CSS actual no es "utility CSS
   típico" (padding, flex, color) sino animación y efectos visuales elaborados.
3. **Ya existe una capa de utilidades equivalente** (`.btn--*`,
   `.badge--*`, `.modal-*`). Migrar a Tailwind no añade una capacidad que
   falte hoy, sino que sustituye una convención propia por otra externa —
   el ROI es menor que en un proyecto que parte de cero CSS estructurado.
4. **Riesgo de regresión visual silenciosa**: con 51 componentes a tocar,
   sin librería de tests visuales/E2E de UI en el repo (no se ha detectado
   Playwright/Cypress para la SPA), cada migración de componente depende de
   revisión manual en navegador para no romper theming/responsive.
5. **Curva de aprendizaje del equipo**: el usuario indica desconocer
   Tailwind — hay coste de onboarding, y durante la transición convivirán
   dos convenciones (CSS scoped antiguo + utilidades nuevas) si se hace de
   forma incremental, lo cual es habitual pero añade ruido temporal.

### Coste estimado

Migración completa de los 51 componentes con verificación visual manual:
del orden de **varios días-persona** repartidos por módulo (Sentinel, Aegis,
Iris, Acheron, vistas compartidas), no una tarea de una tarde. Una migración
"big bang" no es recomendable dado el tamaño y el theming multi-eje.

## Recomendación

**Viable pero de ROI moderado, no urgente.** El código actual no está en mal
estado — al contrario, tiene un design system centralizado y consistente,
que es precisamente lo que muchos proyectos migran a Tailwind *para
conseguir*. Aquí ya existe.

Si se decide seguir adelante, el enfoque de menor riesgo es:

1. **Incremental, no big-bang**: instalar Tailwind (vía `@tailwindcss/vite`)
   sin tocar `shared.css` de inicio; mapear los tokens existentes en
   `tailwind.config.js` reutilizando los mismos nombres de `var(--...)`.
2. Migrar **solo componentes nuevos o que se vayan a tocar igualmente** por
   otras tareas (evita una migración dedicada de bajo valor inmediato).
3. Dejar las animaciones complejas y el theming de vistas "hero" (Landing,
   Acheron) como CSS plano — no forzar su traducción a utilidades.
4. Revisar visualmente cada componente migrado en los 2 temas × módulos
   aplicables, dado que no hay tests visuales automatizados.

Si la motivación principal es "estandarizar breakpoints y eliminar los pocos
hex sueltos", ese problema concreto se puede resolver sin Tailwind (añadiendo
2-3 variables de breakpoint más al design system actual), a mucho menor
coste que una migración de framework.
