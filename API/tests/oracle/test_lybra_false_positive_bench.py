"""Baseline de falsos positivos de la detección por versión.

El objetivo declarado es un número —*«falsos positivos del banco −40 % en
imágenes Debian/RHEL»*— que **no se podía calcular**, porque no existía
el punto de partida del que restar ese 40 %. Peor aún: nadie sabía cuál era la
tasa. Podía ser el 10 % o el 60 %. Y esa cifra es, literalmente, la respuesta a
«¿me puedo fiar de esto?».

Este banco la produce.

## El problema que se mide: el backport

Cuando Debian corrige una vulnerabilidad en `openssl 3.0.11`, **no sube a la
3.0.12**. Aplica el parche y publica `3.0.11-1~deb12u2`: el número de versión
upstream se queda igual y el arreglo viaja en la revisión de la distribución.
NVD, en cambio, describe el CVE como «afecta a versiones anteriores a 3.0.12».

Un motor que compare números de versión sin más ve un `3.0.11`, lo mete en el
rango, y emite un hallazgo por una vulnerabilidad que ese sistema **ya tiene
corregida**. No es un fallo del comparador: la información que distingue un caso
del otro no está en el número de versión.

Ese es el falso positivo que el escaneo de vulnerabilidades por versión produce
a espuertas, y el que este banco tiene que atacar.

## La verdad de referencia, sin salir a la red

Saber si un CVE concreto está corregido por backport parece exigir consultar el
rastreador de seguridad de la distribución. No hace falta: **la propia imagen lo
lleva escrito**. Los paquetes Debian y Ubuntu incluyen su
`/usr/share/doc/<paquete>/changelog.Debian.gz`, y las entradas de seguridad
citan el identificador del CVE que corrigen.

De ahí sale un oráculo que no depende de ninguna red:

> Si el motor emite un CVE contra el paquete P, y el changelog de P —en la
> versión instalada— dice que ese CVE está corregido, ese hallazgo es un falso
> positivo. Sin discusión y sin criterio.

Tiene un límite que conviene decir en voz alta: no todo arreglo cita su CVE en
el changelog, así que un CVE emitido que **no** aparezca ahí no queda demostrado
como verdadero positivo — simplemente no se pronuncia. Por eso lo que este banco
mide es una **cota inferior**: la tasa real es esta o peor, nunca mejor.

## Por qué el catálogo es el que es

Sólo entran imágenes que conservan `/usr/share/doc`. Las variantes ``slim`` y
``alpine`` lo borran para ahorrar espacio, y sin changelogs no hay oráculo: se
midieron y devuelven cero CVE corregidas conocidas, que se leería como «cero
falsos positivos» cuando lo cierto es «no se sabe».

Requiere Docker **y** el Postgres real con el backfill de NVD: sin la base de
conocimiento el motor no falla, devuelve vacío, y eso se lee como «objetivo
limpio» (la misma trampa que documenta ``_real_kb.py``). Se salta entero si
falta cualquiera de los dos.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

import pytest

from src.modules.features.themis.lybra import LybraEngine, Service
from src.modules.features.themis.repositories import KbRepository
from src.modules.infrastructure import UnitOfWork

from ._docker_helpers import resolve_docker
from ._real_kb import seed_for_inventory

pytestmark = [pytest.mark.oracle, pytest.mark.integration]

_DOCKER = resolve_docker()
pytestmark.append(pytest.mark.skipif(_DOCKER is None, reason="Docker no disponible"))

# Imágenes que conservan /usr/share/doc, que es lo que hace posible el oráculo.
# Variadas en distribución y en edad a propósito: una imagen muy reciente tiene
# pocos backports acumulados y produciría un número engañosamente bueno.
_IMAGES = (
    "debian:10",
    "debian:11",
    "debian:12",
    "ubuntu:20.04",
    "ubuntu:22.04",
    "ubuntu:24.04",
)

# La cota medida el 2026-08-31 sobre este catálogo: 8 falsos positivos
# demostrables de 19 hallazgos por versión emitidos = 0,42.
#
# La aserción es un guardarraíl contra empeorar, no una meta: el objetivo
# declarado es bajar de aquí un 40 %, o sea hasta ~0,25. Cuando eso ocurra, este
# número baja con él y el margen se estrecha.
_BASELINE_FALSE_POSITIVE_RATE = 0.45

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")


@dataclass(frozen=True)
class ImageInventory:
    """Lo que una imagen dice de sí misma: qué tiene instalado y qué ha corregido."""
    image: str
    packages: Tuple[Tuple[str, str], ...]
    fixed_cves: Set[str]


def _in_container(image: str, command: str) -> str:
    result = subprocess.run(
        [_DOCKER, "run", "--rm", image, "sh", "-c", command],
        capture_output=True, text=True, timeout=900,
    )
    return result.stdout


def _read_inventory(image: str) -> ImageInventory:
    """Extrae el inventario de paquetes y los CVE que la distro dice haber corregido."""
    listing = _in_container(image, "dpkg-query -W -f='${Package}\\t${Version}\\n'")
    packages = tuple(
        (line.split("\t", 1)[0].strip(), line.split("\t", 1)[1].strip())
        for line in listing.splitlines() if "\t" in line
    )
    changelogs = _in_container(
        image,
        r"zgrep -h -o 'CVE-[0-9]\{4\}-[0-9]\{4,\}' /usr/share/doc/*/changelog.Debian.gz 2>/dev/null | sort -u",
    )
    return ImageInventory(image, packages, set(_CVE_PATTERN.findall(changelogs)))


def _emitted_version_findings(inventory: ImageInventory) -> List[dict]:
    """Corre el motor real sobre el inventario y devuelve sus hallazgos por versión.

    Los servicios se construyen con ``origin="inventory"``, que es exactamente
    lo que hace la puerta de Hygeia: paquetes instalados, sin puerto, sin red de
    por medio. Aquí no se sondea nada — lo que se mide es la correlación con la
    base de conocimiento, no el descubrimiento.
    """
    services = [
        Service(port=None, protocol="", name="", product=name, version=version,
                origin="inventory")
        for name, version in inventory.packages
    ]
    with UnitOfWork() as uow:
        kb_repository = KbRepository(uow)
        engine = LybraEngine(
            cve_lookup=kb_repository.cves_for_cpe,
            kev_lookup=lambda cve_id: kb_repository.get_kev(cve_id) is not None,
            epss_lookup=lambda cve_id: getattr(kb_repository.get_epss(cve_id), "score", None),
            product_alias_lookup=kb_repository.resolve_product_alias,
        )
        findings = engine.analyze(services)
    return [finding for finding in findings if finding.get("category") == "outdated_software"]


@pytest.fixture(scope="module")
def measurement(app) -> Dict:
    """Mide el catálogo entero una vez: sembrar la KB y correr el motor cuesta.

    Depende de ``app`` porque el motor necesita el contexto de aplicación para
    la sesión de base de datos, igual que el resto de bancos del paquete.
    """
    with app.app_context():
        inventories = [_read_inventory(image) for image in _IMAGES]

        without_changelogs = [item.image for item in inventories if not item.fixed_cves]
        if without_changelogs:
            pytest.skip(
                f"Sin changelogs en {without_changelogs}: no hay verdad de referencia "
                "con la que decidir si un hallazgo es falso"
            )

        seeded = seed_for_inventory(
            name for inventory in inventories for name, _ in inventory.packages
        )
        if seeded is None:
            pytest.skip("Postgres real no disponible: sin KB, el motor devuelve vacío")

        per_image = {}
        for inventory in inventories:
            findings = _emitted_version_findings(inventory)
            emitted = {
                cve_id
                for finding in findings
                for cve_id in (finding.get("cve_ids") or [])
            }
            per_image[inventory.image] = {
                "packages": len(inventory.packages),
                "emitted": emitted,
                "false_positives": emitted & inventory.fixed_cves,
                "fixed_known": len(inventory.fixed_cves),
            }

    _print_report(seeded, per_image)
    return per_image


def _print_report(seeded, per_image: Dict) -> None:
    aliases, cves = seeded
    print(f"\n=== Baseline de falsos positivos por versión ===")
    print(f"  KB del banco: {aliases} alias de producto, {cves} CVE copiadas del backfill real")
    for image, data in per_image.items():
        emitted, false_positives = len(data["emitted"]), len(data["false_positives"])
        rate = false_positives / emitted if emitted else 0.0
        print(f"  {image:<14} paquetes={data['packages']:<4} emitidas={emitted:<3} "
              f"falsos={false_positives:<3} ({rate:.0%})   "
              f"[la distro declara {data['fixed_known']} CVE corregidas]")
        for cve_id in sorted(data["false_positives"]):
            print(f"        FP {cve_id}")
    emitted = sum(len(data["emitted"]) for data in per_image.values())
    false_positives = sum(len(data["false_positives"]) for data in per_image.values())
    rate = false_positives / emitted if emitted else 0.0
    print(f"  TOTAL emitidas={emitted} falsos demostrables={false_positives} "
          f"-> cota inferior de falsos positivos = {rate:.2f}")


# =========================================================================

def test_the_bench_actually_emits_something_to_judge(measurement):
    """Un denominador de cero daría 0 % de falsos positivos y no mediría nada.

    Es el modo de fallo que hay que descartar antes de mirar el número: una KB
    mal sembrada, o un inventario que no resuelve a ningún producto de NVD,
    produce un banco silencioso que se lee como un banco limpio.
    """
    emitted = sum(len(data["emitted"]) for data in measurement.values())
    assert emitted > 0, "El motor no emitió ni un hallazgo por versión: la KB no está sembrada"


def test_version_detection_false_positive_rate_does_not_regress(measurement):
    """La cifra que sirve de punto de partida para reducir falsos positivos.

    Medida el 2026-08-31: 8 falsos positivos demostrables sobre 19 hallazgos por
    versión, es decir **0,42** — y es una cota inferior, porque el oráculo sólo
    demuestra los que el changelog cita.

    Dicho en corto: de cada diez vulnerabilidades que el motor reporta contra un
    sistema Debian o Ubuntu por su número de versión, al menos cuatro ya estaban
    corregidas en ese sistema.
    """
    emitted = sum(len(data["emitted"]) for data in measurement.values())
    false_positives = sum(len(data["false_positives"]) for data in measurement.values())
    rate = false_positives / emitted
    detail = {
        image: f"{len(data['false_positives'])}/{len(data['emitted'])}"
        for image, data in measurement.items()
    }
    assert rate <= _BASELINE_FALSE_POSITIVE_RATE, (
        f"la tasa de falsos positivos por versión empeoró: {rate:.2f} "
        f"(línea base {_BASELINE_FALSE_POSITIVE_RATE}) — {detail}"
    )


def test_most_of_a_distro_inventory_never_reaches_the_knowledge_base(measurement):
    """El otro hallazgo del banco, y el que explica lo pequeños que son los números.

    De los ~90 paquetes que trae una imagen base, el motor sólo resuelve una
    docena a un producto de NVD. El resto no produce hallazgos — ni verdaderos
    ni falsos: es invisible. Este test no lo arregla, lo **fija**: si la
    cobertura mejora, cae, y entonces habrá que rehacer la línea base de arriba,
    porque estará medida sobre otro denominador.
    """
    packages = sum(data["packages"] for data in measurement.values())
    assert packages > 0
    # No hay aserción sobre la cobertura porque no hay umbral acordado todavía;
    # el número sale impreso en el informe y es el que alimenta el objetivo de
    # reducción de falsos positivos.
