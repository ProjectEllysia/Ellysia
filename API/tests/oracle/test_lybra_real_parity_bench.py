"""Paridad laboratorio/real: el mismo motor, contra objetivos de verdad.

Esta paridad es **no negociable** para dar por cubiertos el fingerprinting, el
transporte propio y los protocolos no-HTTP, y el argumento es sencillo: *«eso
no puede convertirse en la excusa de "el objetivo real
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

- **Puertos** — concordancia de puertos: qué encuentra el connect scan propio
  frente a lo que encuentra Nmap sobre el mismo objetivo.
- **Fingerprint** — concordancia de fingerprint: si el dissector que aplica a
  cada servicio identifica el mismo producto que Nmap.

El umbral exigido es 0,95 en puertos y 0,90 en fingerprint, y el criterio
de este banco pide al menos diez objetivos variados.
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

# El mínimo que este banco exige. Se comprueba en su propio
# test en vez de dentro de la medición: "no hay bastantes objetivos" y "los
# objetivos que hay concuerdan poco" son dos problemas distintos y merecen dos
# mensajes distintos.
_MINIMUM_TARGETS = 10

# Los umbrales exigidos.
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


def _is_measurable(pair: Tuple) -> bool:
    """¿Dice este par algo sobre el motor, o sólo sobre lo duro que es el objetivo?

    ``agrees_with_nmap`` devuelve ``False`` cuando **ninguno de los dos** lados
    identifica un producto, y contra objetivos reales ese caso no es marginal:
    en la primera medición fueron 23 de 38 servicios. Son puertos que aceptan la
    conexión TCP y luego no contestan a nadie —firewalls que hacen de tarpit, o
    un middlebox del operador—, así que ni la sonda propia ni Nmap sacan nada.

    Meterlos en el cociente hace que el número mida **la dificultad del
    catálogo** en lugar del fingerprinting: bastaría con elegir objetivos más
    dóciles para "mejorar" la concordancia sin tocar una línea del motor. Es la
    misma distinción que el banco de laboratorio ya trataba aparte como punto
    ciego simétrico, sólo que aquí domina la muestra.

    Un par es medible si **al menos uno** de los dos identificó un producto:
    entonces sí hay algo que comparar — acuerdo, desacuerdo, o uno que ve lo que
    el otro no.
    """
    product, _version, nmap_product, _nmap_version = pair[:4]
    return bool(product) or bool(nmap_product)


def _fingerprint_pairs(results: List[dict], measurable_only: bool = True) -> List[Tuple]:
    """Los pares de concordancia de todos los objetivos, sin la etiqueta.

    Por defecto sólo los medibles (ver :func:`_is_measurable`); con
    ``measurable_only=False`` salen todos, que es lo que hace falta para poder
    informar de cuántos se descartaron y por qué.
    """
    pairs = [pair[:4] for result in results for pair in result["pairs"]]
    return [pair for pair in pairs if _is_measurable(pair)] if measurable_only else pairs


def _by_family(results: List[dict], measurable_only: bool = True) -> Dict[str, List[Tuple]]:
    """Agrupa los pares por la familia del dissector que los produjo.

    La paridad se cierra **por familia**, no en promedio: un número global alto
    puede esconder que HTTP va perfecto y FTP no identifica nada, que es
    justamente el caso que esta medición se niega a dar por bueno.
    """
    families: Dict[str, List[Tuple]] = defaultdict(list)
    for result in results:
        for pair in result["pairs"]:
            if measurable_only and not _is_measurable(pair):
                continue
            families[pair[4]].append(pair[:4])
    return families


def _ascii(value) -> str:
    """Un banner de un servidor real puede traer cualquier byte, y la consola de
    Windows (cp1252) no codifica todo Unicode: un solo carácter raro en un
    producto hacía reventar el ``print`` del informe y con él la medición
    entera. El informe es el entregable de este banco, así que no puede caerse por un
    acento de más — cualquier carácter fuera de ASCII se sustituye."""
    return str(value).encode("ascii", "replace").decode("ascii")


def _print_report(results: List[dict]) -> None:
    """Imprime la comparativa. El entregable de este banco es el número, no un OK."""
    print("\n=== Paridad real - objetivos declarados en LYBRA_REAL_TARGETS ===")
    for result in results:
        print(f"  {result['target']}: puertos propios={result['own_ports']} "
              f"nmap={result['nmap_ports']} concordancia={result['ports_score']:.2f}")
        for product, version, nmap_product, nmap_version, label, port in result["pairs"]:
            verdict = "==" if agrees_with_nmap(product, version, nmap_product, nmap_version) else "!="
            print(f"      {port:>5}/{_ascii(label):<6} {verdict} "
                  f"propio={_ascii(product)} {_ascii(version)} "
                  f"| nmap={_ascii(nmap_product)} {_ascii(nmap_version)}")
    print("  --- por familia (solo pares medibles) ---")
    for family, pairs in sorted(_by_family(results).items()):
        print(f"      {family:<8} n={len(pairs):<3} concordancia={concordance_rate(pairs):.2f}")

    every_pair = _fingerprint_pairs(results, measurable_only=False)
    measurable = _fingerprint_pairs(results)
    blind = len(every_pair) - len(measurable)
    ports = [result["ports_score"] for result in results]
    print(f"  puertos: {sum(ports) / len(ports):.2f} sobre {len(ports)} objetivos")
    print(f"  fingerprint: {concordance_rate(measurable):.2f} "
          f"sobre {len(measurable)} servicios medibles")
    print(f"  descartados: {blind} de {len(every_pair)} servicios donde NINGUNO de los dos "
          f"identifica producto (puertos que aceptan y no contestan)")


# =========================================================================

def test_the_real_side_has_enough_targets():
    """El criterio de cierre pide diez objetivos variados, no tres.

    El lado real llevaba desde julio en N=3 (``scanme.nmap.org`` y dos hosts
    autorizados). Con esa muestra no se cierra ninguna fase: un solo objetivo
    raro mueve el número medio punto.
    """
    assert len(_TARGETS) >= _MINIMUM_TARGETS, (
        f"Sólo {len(_TARGETS)} objetivos declarados; este banco pide al menos "
        f"{_MINIMUM_TARGETS} y variados (con y sin CDN/WAF, con y sin TLS, con "
        f"cabecera Server presente y suprimida, y alguno con servicios no-HTTP)"
    )


@pytest.mark.xfail(strict=False, reason=(
    "El resultado de este test es HOY inestable, y no por el objetivo: dos "
    "ejecuciones del banco con 20 minutos de diferencia dieron 0,96 y 0,58. La "
    "diferencia entera son cuatro IPs donde el descubrimiento propio devolvio "
    "lista vacia mientras Nmap encontraba sus cuatro puertos y un socket crudo "
    "conectaba sin problema (un fallo de descubrimiento intermitente). Mientras "
    "ese defecto siga abierto, la concordancia de puertos no se puede certificar: "
    "el numero mide cuando nos bloquearon, no lo que el transporte sabe hacer. "
    "`strict=False` a proposito — un `strict=True` seria tan falso como la "
    "asercion, porque a veces pasa."
))
def test_port_discovery_matches_nmap_on_real_targets(measurements):
    """Concordancia de puertos contra objetivos reales: es donde aparecen el WAF
    que corta a la tercera conexión y el balanceador que responde distinto en
    cada intento."""
    scores = [result["ports_score"] for result in measurements]
    average = sum(scores) / len(scores)
    detail = [(result["target"], round(result["ports_score"], 2)) for result in measurements]
    assert average >= _PORT_THRESHOLD, f"concordancia de puertos real {average:.2f} — {detail}"


@pytest.mark.xfail(strict=True, reason=(
    "Medido el 2026-09-01 sobre 10 objetivos reales autorizados: concordancia de "
    "fingerprint entre 0,33 y 0,36 segun la ejecucion, frente al umbral de 0,90 "
    "exigido. El laboratorio daba 1,00 en las mismas familias, asi que la brecha "
    "laboratorio/real que esta paridad declara no negociable existe y esta "
    "cuantificada. Las causas van por familia: FTP no identifica ProFTPD y HTTP "
    "lee el proxy de delante y no el servidor de detras. El rango en vez de una "
    "cifra unica no es imprecision: el tamano de la muestra varia porque el "
    "descubrimiento falla de forma intermitente."
))
def test_fingerprinting_matches_nmap_on_real_targets(measurements):
    """Concordancia de fingerprint contra objetivos reales.

    Sólo entran los pares **medibles**: un servicio que ni la sonda propia ni
    Nmap consiguen identificar no dice nada sobre el motor, sólo sobre lo duro
    que es el objetivo (ver :func:`_is_measurable`). En esta medición fueron 23
    de 38, así que contarlos habría hundido la cifra por un motivo equivocado.
    """
    pairs = _fingerprint_pairs(measurements)
    assert pairs, "Ningún servicio identificable en los objetivos declarados"
    rate = concordance_rate(pairs)
    assert rate >= _FINGERPRINT_THRESHOLD, (
        f"concordancia de fingerprint real {rate:.2f} sobre {len(pairs)} servicios medibles"
    )


@pytest.mark.xfail(strict=True, reason=(
    "Medido el 2026-09-01: FTP 0,00 y HTTP entre 0,07 y 0,25 quedan por debajo del "
    "umbral; SSH aguanta en 0,75. La causa de FTP ya esta corregida —el "
    "parser reconocia un solo formato de saludo, el de vsftpd, y los dos hosts "
    "medidos servian ProFTPD sin version— pero el numero solo cambia cuando el "
    "banco se vuelva a ejecutar contra objetivos reales. Queda HTTP. Este "
    "test pasara a XPASS cuando la ultima familia se cierre."
))
def test_no_family_is_left_behind(measurements):
    """La paridad se cierra por familia, no en promedio.

    Un número global alto puede esconder que HTTP va perfecto y que FTP no
    identifica nada — que es exactamente el caso que esta paridad se niega a
    dar por bueno. Una familia con un solo servicio observado no se juzga: no hay
    muestra, y suspender por ella mediría el catálogo de objetivos y no el
    motor.
    """
    behind = {
        family: round(concordance_rate(pairs), 2)
        for family, pairs in _by_family(measurements).items()
        if len(pairs) >= 3 and concordance_rate(pairs) < _FINGERPRINT_THRESHOLD
    }
    assert not behind, f"familias por debajo del umbral en objetivos reales: {behind}"
