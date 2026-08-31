"""Puente de solo lectura entre el backfill NVD real y la KB del banco oráculo.

**El problema que resuelve.** El roadmap (Fase U, "qué no se puede verificar en
este equipo") ya lo había anotado como la fila que gobierna a todas las demás:
*"sin KB poblada el motor no falla, devuelve vacío — que es peor, porque se lee
como 'objetivo limpio'"*. Y eso es literalmente lo que hacía el oráculo
diferencial: sobre sus tres objetivos reportaba `corroborated: [] · lybra_only:
[] · nuclei_only: []`, un empate perfecto que no medía nada, porque la mitad
Lybra de la comparación no tenía ninguna CVE que consultar. La suite corre sobre
un SQLite efímero y ahí la KB nace vacía siempre.

**La solución, y sus dos límites deliberados.** El equipo de desarrollo sí tiene
el backfill real (NVD + KEV + EPSS, ~370k CVE) en su Postgres. Este módulo copia
de él, **en solo lectura y solo hacia el SQLite del test**, las filas de los
productos que los contenedores del banco hablan de verdad. Los dos límites:

1. **Nunca escribe en Postgres.** Una sola SELECT con `JOIN`; ninguna sesión de
   escritura, ningún `create_all`, ninguna migración. El backfill costó más de
   una hora de descarga bajo el límite de tasa de NVD y no se toca.
2. **Copia por producto, no entera.** Traer 370k CVE a un SQLite de test sería
   lento y no mediría nada más: lo que la correlación necesita para un
   `httpd:2.4.49` son las filas de `apache:http_server`. El catálogo de
   productos crece cuando crezca el de contenedores, no antes.

**Y cuando no hay Postgres real** —un runner de CI, un portátil recién
clonado— se cae al subconjunto congelado que vive versionado en este mismo
directorio (``frozen_kb.json.gz``, unos 24 KB comprimidos: 14 alias de producto,
424 CVE y 4.085 reglas de aplicabilidad). Eso es lo que convierte estas
mediciones en algo repetible fuera del equipo que tiene el backfill, que era
todo el problema de L51: las cifras del roadmap iban fechadas porque eran
instantáneas manuales.

Se regenera con ``scripts/freeze_bench_kb.py``. Cambiarlo cambia los números que
los bancos publican, así que conviene hacerlo en un commit propio.

Si tampoco hay fichero congelado, las funciones devuelven ``None`` y el test que
las use debe saltarse: medir contra una KB vacía es exactamente lo que este
módulo existe para evitar.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

import sqlalchemy as sa

import src.modules.system.config_reading as CR
from src.modules.infrastructure import UnitOfWork
from src.modules.features.themis.model import CpeProductAlias
from src.modules.features.themis.lybra import normalize_product_name
from src.modules.features.themis.repositories import KbRepository

#: El subconjunto congelado de la KB, versionado en el repositorio para que los
#: bancos puedan medir en un runner de CI que no tiene ninguna base de datos
#: (L51). Se regenera con ``scripts/freeze_bench_kb.py``.
FROZEN_KB_PATH = Path(__file__).resolve().parent / "frozen_kb.json.gz"

# (vendor, product) tal y como el backfill de NVD los escribe. Un producto por
# familia de contenedor del banco: httpd:2.4.49 y las imágenes nginx:alpine.
BENCH_PRODUCTS: Tuple[Tuple[str, str], ...] = (
    ("apache", "http_server"),
    ("f5", "nginx"),
    ("nginx", "nginx"),
)

_QUERY = sa.text(
    '''
    SELECT c.cve_id, c.cvss_score, c.cvss_vector, c.severity, c.description,
           c.cwe_ids, c.source,
           m.vendor, m.product, m.exact_version,
           m.version_start_including, m.version_start_excluding,
           m.version_end_including, m.version_end_excluding
    FROM "CpeMatch" m
    JOIN "CveEntry" c ON c.id = m.cve_id
    WHERE (m.vendor, m.product) IN :products
    '''
).bindparams(sa.bindparam("products", expanding=True))


def _real_engine() -> Optional[sa.Engine]:
    """Engine de solo lectura contra el Postgres real, o ``None`` si no responde."""
    try:
        creds = CR.get_db_credentials()
    except EnvironmentError:
        return None

    url = (
        f"{creds['dialect']}://{creds['username']}:{creds['password']}"
        f"@{creds['host']}:{creds['port']}/{creds['dbname']}"
    )
    engine = sa.create_engine(url, pool_pre_ping=True, connect_args={"connect_timeout": 5})
    try:
        with engine.connect() as conn:
            conn.execute(sa.text("SELECT 1"))
    except sa.exc.SQLAlchemyError:
        engine.dispose()
        return None
    return engine


def seed_from_real_backfill(products: Iterable[Tuple[str, str]] = BENCH_PRODUCTS) -> Optional[int]:
    """Copia a la KB del test las CVE del backfill real para ``products``.

    Args:
        products: pares ``(vendor, product)`` de NVD a traer.

    Returns:
        Cuántas CVE distintas se copiaron, o ``None`` si el Postgres real no
        está disponible (el llamador debe saltarse la medición en ese caso).
    """
    engine = _real_engine()
    if engine is None:
        # Sin Postgres real se cae al subconjunto congelado, que es lo que hace
        # que estos bancos puedan correr en un runner de CI (L51).
        frozen = seed_from_frozen()
        return frozen[1] if frozen else None

    try:
        with engine.connect() as conn:
            rows = conn.execute(_QUERY, {"products": list(products)}).mappings().all()
    finally:
        engine.dispose()

    return _write_cves(_group(rows))


_ALIAS_QUERY = sa.text(
    """
    SELECT normalized_name, vendor, product
    FROM "CpeProductAlias"
    WHERE normalized_name IN :names
    """
).bindparams(sa.bindparam("names", expanding=True))


def seed_for_inventory(package_names: Iterable[str]) -> Optional[Tuple[int, int]]:
    """Copia a la KB del test lo que hace falta para analizar un inventario.

    Un inventario de paquetes (Fase I) no llega con un CPE puesto, como sí hace
    un servicio identificado por Nmap: llega con el nombre que le da la
    distribución —``zlib1g``, ``perl-base``— y hay que resolverlo primero al
    vocabulario de NVD. Esa resolución la hace ``CpeProductAlias``, un índice
    derivado del propio ``CpeMatch``, así que el banco necesita **dos** cosas
    del backfill real y no una: las filas del índice para los nombres que va a
    ver, y las CVE de los productos a los que esos nombres resuelvan.

    Sin la primera mitad el motor no resuelve nada y el banco mediría cero
    hallazgos sobre cero productos, que se lee como "no hay falsos positivos".

    Args:
        package_names: Nombres de paquete tal y como los da la distribución.

    Returns:
        ``(alias_copiados, cve_copiadas)``, o ``None`` si el Postgres real no
        está disponible.
    """
    engine = _real_engine()
    if engine is None:
        return seed_from_frozen(package_names)

    normalized = sorted({normalize_product_name(name) for name in package_names})
    try:
        with engine.connect() as conn:
            alias_rows = conn.execute(_ALIAS_QUERY, {"names": normalized}).mappings().all()
    finally:
        engine.dispose()

    if not alias_rows:
        return (0, 0)

    with UnitOfWork() as uow:
        for row in alias_rows:
            uow.session.merge(CpeProductAlias(
                normalized_name=row["normalized_name"],
                vendor=row["vendor"],
                product=row["product"],
            ))
        uow.commit()

    products = {(row["vendor"], row["product"]) for row in alias_rows}
    copied = seed_from_real_backfill(sorted(products))
    return (len(alias_rows), copied or 0)


def _load_frozen() -> Optional[dict]:
    """El subconjunto congelado, o ``None`` si no está versionado todavía."""
    if not FROZEN_KB_PATH.exists():
        return None
    # Comprimido: el mismo contenido en claro pesa diez veces más, y esto es un
    # fichero que se versiona y viaja en cada clon del repositorio.
    return json.loads(gzip.decompress(FROZEN_KB_PATH.read_bytes()).decode("utf-8"))


def _write_cves(grouped: dict) -> int:
    """Vuelca a la KB del test las CVE ya agrupadas por identificador."""
    with UnitOfWork() as uow:
        repo = KbRepository(uow)
        for entry in grouped.values():
            repo.upsert_cve(entry["cve"], entry["matches"])
        uow.commit()
    return len(grouped)


def _group(rows: Iterable[dict]) -> dict:
    """Agrupa filas planas ``CpeMatch``+``CveEntry`` por CVE.

    Una CVE trae varias filas de aplicabilidad y ``upsert_cve`` las reemplaza en
    bloque, así que hay que agruparlas antes: llamar una vez por fila dejaría
    sólo la última regla de cada CVE, que es una forma silenciosa de perder
    detecciones.
    """
    grouped: dict = {}
    for row in rows:
        cve = grouped.setdefault(row["cve_id"], {
            "cve": {
                "cve_id": row["cve_id"],
                "cvss_score": row["cvss_score"],
                "cvss_vector": row["cvss_vector"],
                "severity": row["severity"],
                "description": row["description"],
                "cwe_ids": row["cwe_ids"],
                "source": row["source"],
            },
            "matches": [],
        })
        cve["matches"].append({
            "vendor": row["vendor"],
            "product": row["product"],
            "exact_version": row["exact_version"],
            "version_start_including": row["version_start_including"],
            "version_start_excluding": row["version_start_excluding"],
            "version_end_including": row["version_end_including"],
            "version_end_excluding": row["version_end_excluding"],
        })
    return grouped


def seed_from_frozen(package_names: Iterable[str] = ()) -> Optional[Tuple[int, int]]:
    """Siembra la KB del test desde el subconjunto congelado del repositorio.

    Es el camino que hace que los bancos puedan correr en CI. Copia **todo** lo
    congelado y no sólo lo que pidan los nombres recibidos: el fichero ya es un
    subconjunto elegido, y filtrarlo otra vez sólo añadiría una forma de que el
    banco midiera menos de lo que cree.

    Args:
        package_names: Se acepta por simetría con :func:`seed_for_inventory`,
            y se ignora a propósito (ver arriba).

    Returns:
        ``(alias_sembrados, cve_sembradas)``, o ``None`` si no hay fichero.
    """
    frozen = _load_frozen()
    if frozen is None:
        return None

    with UnitOfWork() as uow:
        for alias in frozen["aliases"]:
            uow.session.merge(CpeProductAlias(
                normalized_name=alias["normalized_name"],
                vendor=alias["vendor"],
                product=alias["product"],
            ))
        uow.commit()

    return (len(frozen["aliases"]), _write_cves(_group(frozen["cves"])))


def export_frozen_kb(
    package_names: Iterable[str],
    products: Iterable[Tuple[str, str]],
    path: Path,
) -> Optional[Tuple[int, int, int]]:
    """Extrae del backfill real el subconjunto que los bancos consultan.

    Lo invoca ``scripts/freeze_bench_kb.py``; vive aquí porque las consultas y
    la forma de las filas son las mismas que las de la siembra, y tenerlas en
    dos sitios sería la manera más rápida de que el fichero congelado dejara de
    parecerse a lo que la siembra espera leer.

    Returns:
        ``(alias, cve, reglas)`` escritos, o ``None`` si no hay Postgres real.
    """
    engine = _real_engine()
    if engine is None:
        return None

    normalized = sorted({normalize_product_name(name) for name in package_names})
    try:
        with engine.connect() as conn:
            alias_rows = [dict(row) for row in
                          conn.execute(_ALIAS_QUERY, {"names": normalized}).mappings().all()]
            wanted = {(row["vendor"], row["product"]) for row in alias_rows}
            wanted.update(products)
            cve_rows = [dict(row) for row in
                        conn.execute(_QUERY, {"products": sorted(wanted)}).mappings().all()]
    finally:
        engine.dispose()

    # La descripción de cada CVE es el 90 % del peso del fichero y no participa
    # en ninguna medición: los bancos cuentan identificadores, no leen prosa.
    # Se congela vacía para que esto siga siendo un fichero versionable y no un
    # volcado de base de datos dentro del repositorio.
    for row in cve_rows:
        row["description"] = ""

    document = json.dumps({"aliases": alias_rows, "cves": cve_rows},
                          default=str, ensure_ascii=False)
    path.write_bytes(gzip.compress(document.encode("utf-8"), mtime=0))
    return (len(alias_rows), len({row["cve_id"] for row in cve_rows}), len(cve_rows))
