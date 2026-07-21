// Registro único de tipos de escaneo de Themis.
//
// Antes cada componente (panel de programados, historial, su gráfico, la
// vista previa) mantenía su propia lista de tipos escrita a mano, y añadir
// Lybra a los escaneos programados dejó claro el problema: siempre se
// quedaba alguna sin actualizar. Añadir un tipo nuevo aquí — y solo aquí —
// basta para que aparezca correctamente en todos esos sitios.
export const SCAN_TYPES = {
  nmap: {
    label: 'Nmap',
    fullLabel: 'Nmap (red)',
    previewLabel: 'Vista Previa — Nmap',
    chartColor: 'var(--info)',
    scheduleFields: [
      { key: 'target_host', label: 'Host', size: 'lg', placeholder: '192.168.1.0/24' },
      { key: 'target_ports', label: 'Puertos', size: 'md', placeholder: '80,443 o 1-1000' },
    ],
    defaultArgs: { target_host: '', target_ports: '1-1000' },
    formatArgs: (args) => {
      const parts = []
      if (args?.target_host) parts.push(args.target_host)
      if (args?.target_ports) parts.push(`puertos ${args.target_ports}`)
      return parts.length ? parts.join(' · ') : '—'
    },
  },
  nikto: {
    label: 'Nikto',
    fullLabel: 'Nikto (web)',
    previewLabel: 'Vista Previa — Nikto',
    chartColor: 'var(--warn)',
    scheduleFields: [
      { key: 'target_domain', label: 'Dominio', size: 'lg', placeholder: 'example.com' },
    ],
    defaultArgs: { target_domain: '' },
    formatArgs: (args) => args?.target_domain || '—',
  },
  openvas: {
    label: 'OpenVAS',
    fullLabel: 'OpenVAS (vulnerabilidades)',
    previewLabel: 'Vista Previa — OpenVAS',
    chartColor: 'var(--danger)',
    scheduleFields: [
      { key: 'target', label: 'Target (IP)', size: 'lg', placeholder: '192.168.1.1' },
    ],
    defaultArgs: { target: '' },
    formatArgs: (args) => args?.target || '—',
  },
  lybra: {
    label: 'Lybra',
    fullLabel: 'Lybra (motor propio)',
    previewLabel: 'Vista Previa — Lybra',
    chartColor: 'var(--accent)',
    scheduleFields: [
      { key: 'target', label: 'Target (IP única)', size: 'lg', placeholder: '192.168.1.1' },
    ],
    defaultArgs: { target: '' },
    formatArgs: (args) => args?.target || '—',
  },
}

export const SCAN_TYPE_ORDER = Object.keys(SCAN_TYPES)

export function scanTypeLabel(type) {
  return SCAN_TYPES[type]?.label ?? type
}
