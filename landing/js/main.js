// ═══════════════════════════════════════════════════════════════
// Ellysia landing — vanilla JS
// Boot log typing → glitch → ambient constellation → hairline draw
// → live clock. Everything honors prefers-reduced-motion.
// ═══════════════════════════════════════════════════════════════

const REDUCE = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── Boot log ──────────────────────────────────────────────────
const BOOT_LINES = [
  { prefix: '> initializing ellysia',                       tail: 'ok', cls: 'mod' },
  { prefix: '> loading sentinel · nmap/nikto/openvas',   tail: 'ok', cls: 'mod' },
  { prefix: '> loading aegis · 73 topics · 19 brands',   tail: 'ok', cls: 'mod' },
  { prefix: '> loading iris · 37 header rules',          tail: 'ok', cls: 'mod' },
  { prefix: '> loading acheron · aes-256-gcm',           tail: 'ok', cls: 'mod' },
];

const padTail = (n) => '.'.repeat(Math.max(0, 46 - n));

async function typeBoot() {
  const log = document.getElementById('bootLog');
  if (!log) return;

  // Reduced motion → drop all lines at once, no cursor, return.
  if (REDUCE) {
    log.innerHTML = BOOT_LINES.map((l) =>
      `<span class="arr">&gt;</span> <span class="mod">${l.prefix}</span><span class="dots">${padTail(l.prefix.length)}</span> <span class="ok">${l.tail}</span>`
    ).join('\n');
    return;
  }

  const cursor = '<span class="cursor"></span>';
  for (let i = 0; i < BOOT_LINES.length; i++) {
    const line = BOOT_LINES[i];
    await typeLine(log, line, cursor);
    await sleep(140);
  }
  // Remove cursor at the end
  const cur = log.querySelector('.cursor');
  if (cur) cur.remove();

  // Subtle glitch on the [Ellysia] title once boot completes
  const title = document.getElementById('heroText');
  if (title) {
    await sleep(220);
    title.classList.add('glitch');
    setTimeout(() => title.classList.remove('glitch'), 320);
  }
}

async function typeLine(log, line, cursor) {
  // Begin this line
  const lineId = `bl${Math.random().toString(36).slice(2)}`;
  log.insertAdjacentHTML('beforeend',
    `<span id="${lineId}"><span class="arr">&gt;</span> <span class="mod"></span><span class="dots"></span> <span class="ok" style="opacity:0"></span></span>${cursor}\n`);

  const lineEl   = log.querySelector(`#${CSS.escape(lineId)}`);
  const prefixEl = lineEl.querySelector('.mod');
  const dotsEl   = lineEl.querySelector('.dots');
  const okEl     = lineEl.querySelector('.ok');

  // Type prefix
  for (let i = 0; i < line.prefix.length; i++) {
    prefixEl.textContent += line.prefix[i];
    await sleep(18 + Math.random() * 14);
  }
  // Fill alignment dots
  const dotCount = 46 - line.prefix.length;
  for (let i = 0; i < dotCount; i++) {
    dotsEl.textContent += '.';
    await sleep(6);
  }
  await sleep(140);
  // Reveal ok marker
  okEl.textContent = line.tail;
  okEl.style.opacity = '1';
  // Move cursor to next line visually by leaving it as-is on its own span
}

// ── Live clock ──────────────────────────────────────────────
function tickClock() {
  const now = new Date().toLocaleTimeString('es-ES', { hour12: false });
  for (const id of ['clock', 'footClock']) {
    const el = document.getElementById(id);
    if (el) el.textContent = now;
  }
}

// ── Ambient constellation (mirrors HubView) ─────────────────
function buildConstellation() {
  const svg = document.querySelector('.bg-constellation');
  if (!svg) return;
  const N = 9;
  const nodes = Array.from({ length: N }, () => ({
    x: 6 + Math.random() * 88,
    y: 6 + Math.random() * 88,
    r: 1.2 + Math.random() * 1.8,
    delay: Math.random() * 4,
  }));
  const links = [
    [0,1],[1,2],[2,4],[4,3],[3,0],
    [4,5],[5,6],[6,7],[7,8],[8,5],
  ];
  const ns = 'http://www.w3.org/2000/svg';
  for (const [a, b] of links) {
    const l = document.createElementNS(ns, 'line');
    l.setAttribute('x1', nodes[a].x + '%');
    l.setAttribute('y1', nodes[a].y + '%');
    l.setAttribute('x2', nodes[b].x + '%');
    l.setAttribute('y2', nodes[b].y + '%');
    svg.appendChild(l);
  }
  for (const n of nodes) {
    const c = document.createElementNS(ns, 'circle');
    c.setAttribute('cx', n.x + '%');
    c.setAttribute('cy', n.y + '%');
    c.setAttribute('r', n.r);
    c.style.animationDelay = n.delay + 's';
    svg.appendChild(c);
  }
}

// ── IntersectionObserver: module rows + spec rows ────────────
function observeReveals() {
  if (!('IntersectionObserver' in window)) {
    document.querySelectorAll('.module, .spec tbody tr').forEach((el) => el.classList.add('is-in'));
    return;
  }
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (e.isIntersecting) {
        e.target.classList.add('is-in');
        io.unobserve(e.target);
      }
    }
  }, { threshold: 0.25, rootMargin: '0px 0px -8% 0px' });

  const modules = document.querySelectorAll('.module');
  modules.forEach((m, i) => {
    m.style.transitionDelay = `${i * 0.05}s`;
    io.observe(m);
  });
  document.querySelectorAll('.spec tbody tr').forEach((tr, i) => {
    tr.style.transitionDelay = `${i * 0.03}s`;
    io.observe(tr);
  });
}

// ── Init ────────────────────────────────────────────────────
async function init() {
  buildConstellation();
  tickClock();
  setInterval(tickClock, 1000);
  observeReveals();
  await typeBoot();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}