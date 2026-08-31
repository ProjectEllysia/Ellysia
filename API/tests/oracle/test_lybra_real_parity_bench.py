"""Paridad laboratorio/real: el mismo motor, contra objetivos de verdad (L48).

El §9 del roadmap declara esta paridad **no negociable** para dar por cerradas
las fases F (fingerprinting), T (transporte propio) y N (protocolos no-HTTP), y
lo argumenta bien: *«eso no puede convertirse en la excusa de "el objetivo real
es más difícil" cuando Nmap identifica con soltura servicios en hosts públicos
reales. Si aparece un caso como "en localhost identificamos producto y versión,
pero en un host público real sólo vemos puertos abiertos", no es un resultado
aceptable por ser "un objetivo más duro": es una brecha concreta que hay que
cerrar»*.

Un contenedor Docker es un objetivo dócil. Responde al instante, no tiene un
CDN delante, ni un WAF que corte la conexión al tercer intento, ni una latencia
que agote un timeout, ni un balanceador que conteste una cosa distinta en cada
petición. Medir sólo ahí produce un número alto y poco informativo.

## Por qué esto se salta por defecto, y qué hay que hacer para que no

Escanear una máquina ajena sin permiso no es un detalle de configuración. Por
eso este banco no trae ninguna lista de objetivos: la aporta quien ejecuta la
suite, en ``LYBRA_REAL_TARGETS``, y esa declaración **es** la afirmación de que
tiene autorización sobre esos hosts. Sin la variable el módulo entero se salta,
que es lo que ocurre en CI y en cualquier máquina que no haya decidido lo
contrario.

El sello de red de la suite (``_no_outbound_sockets``) sigue puesto: lo único
que cambia es que las direcciones declaradas entran en una lista blanca
resuelta antes de instalarlo. No se apaga nada.

    LYBRA_REAL_TARGETS="host1.example,host2.example,..." \\
        pytest tests/oracle/test_lybra_real_parity_bench.py -m oracle -s

El ``-s`` importa: el informe por familia se imprime, porque el entregable de
este ítem es el número, no un booleano.

## Qué mide

Lo mismo que el banco de laboratorio (``test_lybra_concordance_bench.py``), con
las mismas funciones, para que los dos números sean comparables:

- **Fase T** — concordancia de puertos: qué encuentra el connect scan propio
  frente a lo que encuentra Nmap sobre el mismo objetivo.
- **Fases F y N** — concordancia de fingerprint: si el dissector que aplica a
  cada servicio identifica el mismo producto que Nmap.

El umbral del roadmap es 0,95 en puertos y 0,90 en fingerprint, y el criterio
de cierre de L48 pide al menos diez objetivos variados.
"""

from __future__ import annotations

import os
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

import pytest

from src.modules.features.themis.lybra import (
    DEFAULT_PORTS,
    HostRateLimiter,
    default_dissectors,
    scan_ports_sync,
    services_from_discovered_ports,
)

from ._concordance import agrees_with_nmap, concordance_rate, port_concordance
from ._docker_helpers import resolve_docker
from ._nmap_oracle import run_nmap_sv
# El mismo módulo que lee el sello de red: la lista que este banco escanea y la
# que el sello permite tienen que ser el mismo dato, no dos lecturas parecidas.
from ._real_targets import declared_real_targets

pytestmark = [pytest.mark.oracle, pytest.mark.integration]

_TARGETS = declared_real_targets()
pytestmark.append(pytest.mark.skipif(
    not _TARGETS,
    reason="Sin LYBRA_REAL_TARGETS: el lado real de la paridad lo declara el operador",
))

# El mínimo que pide el criterio de cierre de L48. Se comprueba en su propio
# test en vez de dentro de la medición: "no hay bastantes objetivos" y "los
# objetivos que hay concuerdan poco" son dos problemas distintos y merecen dos
# mensajes distintos.
_MINIMUM_TARGETS = 10

# Los umbrales del roadmap (§9).
_PORT_THRESHOLD = 0.95
_FINGERPRINT_THRESHOLD = 0.90


@pytest.fixture(scope="module")
def measurements() -> List[dict]:
    """Mide todos los objetivos una vez y reparte el resultado a los tests.

    Un escaneo real no es instantáneo —Nmap con detección de versión sobre una
    lista de puertos tarda—, así que repetirlo por test convertiría el banco en
    algo que nadie ejecuta. Se mide una vez por módulo.
    """
    docker_path = resolve_docker()
    results = []
    for target in _TARGETS:
        results.append(_measure(target, docker_path))
    _print_report(results)
    return results


def _measure(target: str, docker_path: Optional[str]) -> dict:
    """Un objetivo: puertos propios, puertos de Nmap, y fingerprint de cada servicio."""
    own_ports = scan_ports_sync(target, list(DEFAULT_PORTS))
    nmap_services = run_nmap_sv(docker_path, DEFAULT_PORTS, host=target)

    # Se compara sobre el mismo conjunto de puertos que ambos examinaron; de lo
    # contrario el número mediría qué lista de puertos se le pasó a cada uno.
    ports_score = port_concordance(own_ports, list(nmap_services))

    rate_limiter = HostRateLimiter()
    dissectors = default_dissectors()
    pairs: List[Tuple] = []
    for service in services_from_discovered_ports(own_ports):
        dissector = next((candidate for candidate in dissectors if candidate.applies(service)), None)
        if dissector is None:
            continue
        try:
            result = dissector.probe(target, service, rate_limiter)
        except Exception:
            result = None
        nmap = nmap_services.get(service.port)
        pairs.append((
            result.product if result else None,
            result.version if result else None,
            nmap.product if nmap else None,
            nmap.version if nmap else None,
            dissector.label or type(dissector).__name__,
            service.port,
        ))
    return {"target": target, "own_ports": own_ports, "nmap_ports": sorted(nmap_services),
            "ports_score": ports_score, "pairs": pairs}


def _fingerprint_pairs(results: List[dict]) -> List[Tuple]:
    """Los pares de concordancia de todos los objetivos, sin la etiqueta."""
    return [pair[:4] for result in results for pair in result["pairs"]]


def _by_family(results: List[dict]) -> Dict[str, List[Tuple]]:
    """Agrupa los pares por la familia del dissector que los produjo.

    La paridad se cierra **por familia**, no en promedio: un número global alto
    puede esconder que HTTP va perfecto y FTP no identifica nada, que es
    justamente el caso que el §9 se niega a dar por bueno.
    """
    families: Dict[str, List[Tuple]] = defaultdict(list)
    for result in results:
        for pair in result["pairs"]:
            families[pair[4]].append(pair[:4])
    return families


def _ascii(value) -> str:
    """Un banner de un servidor real puede traer cualquier byte, y la consola de
    Windows (cp1252) no codifica todo Unicode: un solo carácter raro en un
    producto hacía reventar el ``print`` del informe y con él la medición
    entera. El informe es el entregable de L48, así que no puede caerse por un
    acento de más — cualquier carácter fuera de ASCII se sustituye."""
    return str(value).encode("ascii", "replace").decode("ascii")


def _print_report(results: List[dict]) -> None:
    """Imprime la comparativa. El entregable de L48 es el número, no un OK."""
    print("\n=== Paridad real (L48) - objetivos declarados en LYBRA_REAL_TARGETS ===")
    for result in results:
        print(f"  {result['target']}: puertos propios={result['own_ports']} "
              f"nmap={result['nmap_ports']} concordancia={result['ports_score']:.2f}")
        for product, version, nmap_product, nmap_version, label, port in result["pairs"]:
            verdict = "==" if agrees_with_nmap(product, version, nmap_product, nmap_version) else "!="
            print(f"      {port:>5}/{_ascii(label):<6} {verdict} "
                  f"propio={_ascii(product)} {_ascii(version)} "
                  f"| nmap={_ascii(nmap_product)} {_ascii(nmap_version)}")
    print("  --- por familia ---")
    for family, pairs in sorted(_by_family(results).items()):
        print(f"      {family:<8} n={len(pairs):<3} concordancia={concordance_rate(pairs):.2f}")
    ports = [result["ports_score"] for result in results]
    print(f"  puertos (Fase T): {sum(ports) / len(ports):.2f} sobre {len(ports)} objetivos")
    print(f"  fingerprint (F/N): {concordance_rate(_fingerprint_pairs(results)):.2f} "
          f"sobre {len(_fingerprint_pairs(results))} servicios")


# =========================================================================

def test_the_real_side_has_enough_targets():
    """El criterio de cierre pide diez objetivos variados, no tres.

    El lado real llevaba desde julio en N=3 (``scanme.nmap.org`` y dos hosts
    autorizados). Con esa muestra no se cierra ninguna fase: un solo objetivo
    raro mueve el número medio punto.
    """
    assert len(_TARGETS) >= _MINIMUM_TARGETS, (
        f"Sólo {len(_TARGETS)} objetivos declarados; L48 pide al menos "
        f"{_MINIMUM_TARGETS} y variados (con y sin CDN/WAF, con y sin TLS, con "
        f"cabecera Server presente y suprimida, y alguno con servicios no-HTTP)"
    )


def test_port_discovery_matches_nmap_on_real_targets(measurements):
    """Fase T contra objetivos reales: es donde aparecen el WAF que corta a la
    tercera conexión y el balanceador que responde distinto en cada intento."""
    scores = [result["ports_score"] for result in measurements]
    average = sum(scores) / len(scores)
    detail = [(result["target"], round(result["ports_score"], 2)) for result in measurements]
    assert average >= _PORT_THRESHOLD, f"concordancia de puertos real {average:.2f} — {detail}"


def test_fingerprinting_matches_nmap_on_real_targets(measurements):
    """Fases F y N contra objetivos reales."""
    pairs = _fingerprint_pairs(measurements)
    assert pairs, "Ningún servicio identificable en los objetivos declarados"
    rate = concordance_rate(pairs)
    assert rate >= _FINGERPRINT_THRESHOLD, f"concordancia de fingerprint real {rate:.2f}"


def test_no_family_is_left_behind(measurements):
    """La paridad se cierra por familia, no en promedio.

    Un número global alto puede esconder que HTTP va perfecto y que FTP no
    identifica nada — que es exactamente el caso que el §9 se niega a dar por
    bueno. Una familia con un solo servicio observado no se juzga: no hay
    muestra, y suspender por ella mediría el catálogo de objetivos y no el
    motor.
    """
    behind = {
        family: round(concordance_rate(pairs), 2)
        for family, pairs in _by_family(measurements).items()
        if len(pairs) >= 3 and concordance_rate(pairs) < _FINGERPRINT_THRESHOLD
    }
    assert not behind, f"familias por debajo del umbral en objetivos reales: {behind}"
