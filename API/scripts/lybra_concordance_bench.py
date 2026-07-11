"""Banco de concordancia Lybra vs. Nmap — Fases F y T (roadmap §7, §6).

Herramienta manual, no integrada en CI: mide cuánto coincide el transporte y el
fingerprinting propios de Lybra con Nmap (el oráculo) sobre una lista de
objetivos dados por el operador. El roadmap exige que esa medición se repita
tanto en el laboratorio como en objetivos reales de Internet (paridad
laboratorio/real, apartado 6) — este script es agnóstico a cuál de los dos le
pases, ese contraste lo decide el operador eligiendo los objetivos.

Los objetivos deben estar ya autorizados (registro de objetivos autorizados,
apartado 6 del roadmap); este script no comprueba esa autorización, así que es
responsabilidad de quien lo ejecuta pasarle solo objetivos con permiso.

Requiere Nmap instalado y accesible en PATH (Linux/WSL — ver CLAUDE.md). No
necesita la app Flask ni la base de datos: usa directamente las primitivas
puras de ``themis.lybra``.

Uso:
    python scripts/lybra_concordance_bench.py 127.0.0.1 213.97.178.100 81.33.25.87
"""

from __future__ import annotations

import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.modules.themis.lybra import (  # noqa: E402
    scan_ports_sync, port_concordance,
    HttpProbe, SshProbe, is_http_service, Service,
    fingerprint_http, fingerprint_ssh, agrees_with_nmap, concordance_rate,
)


@dataclass
class NmapService:
    port: int
    name: str
    product: Optional[str]
    version: Optional[str]


def run_nmap_sv(host: str) -> Dict[int, NmapService]:
    """Run ``nmap -sV`` against a host and parse its per-port product/version.

    Returns:
        A ``{port: NmapService}`` map — the oracle reading for this host.
    """
    result = subprocess.run(
        ["nmap", "-sV", "-oX", "-", host],
        capture_output=True, text=True, timeout=300, check=True,
    )
    root = ET.fromstring(result.stdout)
    services: Dict[int, NmapService] = {}
    for port_el in root.findall(".//port"):
        state = port_el.find("state")
        if state is None or state.get("state") != "open":
            continue
        portid = int(port_el.get("portid"))
        svc = port_el.find("service")
        services[portid] = NmapService(
            port=portid,
            name=(svc.get("name") if svc is not None else "") or "",
            product=svc.get("product") if svc is not None else None,
            version=svc.get("version") if svc is not None else None,
        )
    return services


def fingerprint_own(host: str, ports: List[int]) -> Dict[int, Tuple[Optional[str], Optional[str]]]:
    """Run Lybra's own HTTP/SSH dissectors against the discovered ports.

    Mirrors ``LybraEngineManager._fingerprint_services`` but standalone, with no
    DB/Finding involved — this script only wants the raw ``(product, version)``.
    """
    http_probe, ssh_probe = HttpProbe(), SshProbe()
    own: Dict[int, Tuple[Optional[str], Optional[str]]] = {}
    for port in ports:
        service = Service(port=port, protocol="tcp", name="", product="", version="", cpe=None)
        if is_http_service(service) or port in (80, 443, 8080, 8443, 8000, 8888, 8008):
            resp = http_probe.fetch(host, port, "GET", "/")
            if resp is None:
                continue
            favicon = http_probe.fetch_bytes(host, port, "/favicon.ico")
            fp = fingerprint_http(resp, favicon)
            own[port] = (fp.product, fp.version)
        elif port == 22:
            probed = ssh_probe.fetch(host, port)
            if probed is None:
                continue
            banner, kexinit = probed
            fp = fingerprint_ssh(banner, kexinit)
            own[port] = (fp.product, fp.version)
    return own


def bench_host(host: str) -> None:
    print(f"\n=== {host} ===")

    own_ports = scan_ports_sync(host)
    nmap_services = run_nmap_sv(host)
    nmap_ports = list(nmap_services.keys())
    port_score = port_concordance(own_ports, nmap_ports)
    print(f"Puertos propios:  {sorted(own_ports)}")
    print(f"Puertos Nmap:     {sorted(nmap_ports)}")
    print(f"Concordancia de puertos (Fase T, objetivo >=0.95): {port_score:.2f}")

    own_fp = fingerprint_own(host, own_ports)
    pairs = []
    for port, (product, version) in own_fp.items():
        nmap_svc = nmap_services.get(port)
        nmap_product = nmap_svc.product if nmap_svc else None
        nmap_version = nmap_svc.version if nmap_svc else None
        agrees = agrees_with_nmap(product, version, nmap_product, nmap_version)
        pairs.append((product, version, nmap_product, nmap_version))
        print(
            f"  puerto {port}: propio={product or '?'} {version or ''} | "
            f"nmap={nmap_product or '?'} {nmap_version or ''} | "
            f"{'concuerda' if agrees else 'no concuerda'}"
        )
    fp_score = concordance_rate(pairs)
    print(f"Concordancia de fingerprint (Fase F, objetivo >=0.90): {fp_score:.2f}")


def main() -> None:
    targets = sys.argv[1:]
    if not targets:
        print(__doc__)
        sys.exit(1)
    print(
        "Advertencia: este banco envía tráfico activo a cada objetivo. "
        "Úsalo solo con objetivos ya autorizados (roadmap §6)."
    )
    for host in targets:
        bench_host(host)


if __name__ == "__main__":
    main()
