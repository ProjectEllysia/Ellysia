"""Congela el trozo de la base de conocimiento que los bancos necesitan (L51).

Los bancos oráculo miden contra CVE reales, y hasta ahora las sacaban del
Postgres de desarrollo: el backfill completo de NVD, ~2,5 millones de filas de
aplicabilidad. Eso funciona en el equipo que lo tiene y en ningún otro sitio —
y es la razón de que las cifras del roadmap fueran instantáneas manuales
fechadas en vez de un número que se recalcula solo.

Este script extrae el subconjunto que los bancos consultan de verdad y lo deja
en un fichero versionado, para que el mismo banco pueda correr en un runner de
CI que no tiene ninguna base de datos.

**No se congela la KB entera, ni de lejos.** Sólo los productos que los
contenedores del catálogo hablan (Apache, nginx) y aquellos a los que resuelven
los paquetes de las imágenes de distribución del banco de falsos positivos. Son
unas decenas de miles de filas frente a millones, y el criterio para ampliarlo
es el mismo que ya rige en ``_real_kb.py``: crece cuando crece el catálogo de
contenedores, no antes.

Uso, desde ``API/`` y con el Postgres de desarrollo levantado:

    python scripts/freeze_bench_kb.py

Rehacerlo tiene sentido cuando el catálogo de imágenes cambia o cuando el
backfill se actualiza y se quiere que los bancos midan contra datos más
recientes. Ojo con lo segundo: cambiar la KB congelada cambia los números que
los bancos publican, así que conviene hacerlo en un commit propio y anotar el
salto — igual que se haría con cualquier otro cambio de instrumento de medida.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

_API_DIR = Path(__file__).resolve().parent.parent
if str(_API_DIR) not in sys.path:
    sys.path.insert(0, str(_API_DIR))

sys.path.insert(0, str(_API_DIR / "tests"))

from oracle._real_kb import BENCH_PRODUCTS, export_frozen_kb, FROZEN_KB_PATH  # noqa: E402
from oracle._docker_helpers import resolve_docker  # noqa: E402

# Las mismas imágenes que el banco de falsos positivos analiza. Se listan aquí
# y no se importan del test para que este script no arrastre pytest.
_IMAGES = ("debian:10", "debian:11", "debian:12",
           "ubuntu:20.04", "ubuntu:22.04", "ubuntu:24.04")


def _packages_of(docker_path: str, image: str) -> list:
    result = subprocess.run(
        [docker_path, "run", "--rm", image, "sh", "-c",
         "dpkg-query -W -f='${Package}\\n'"],
        capture_output=True, text=True, timeout=900,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def main() -> int:
    docker_path = resolve_docker()
    if docker_path is None:
        print("Docker no disponible: hace falta para leer los paquetes de las imágenes")
        return 1

    names = []
    for image in _IMAGES:
        packages = _packages_of(docker_path, image)
        print(f"  {image}: {len(packages)} paquetes")
        names.extend(packages)

    counts = export_frozen_kb(names, BENCH_PRODUCTS, FROZEN_KB_PATH)
    if counts is None:
        print("Postgres real no disponible: no hay de dónde congelar")
        return 1

    aliases, cves, matches = counts
    size = FROZEN_KB_PATH.stat().st_size / 1024
    print(f"\nCongelado en {FROZEN_KB_PATH.relative_to(_API_DIR)}:")
    print(f"  {aliases} alias de producto, {cves} CVE, {matches} reglas de aplicabilidad")
    print(f"  {size:.0f} KB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
