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

Si el Postgres real no está levantado, :func:`seed_from_real_backfill` devuelve
``None`` y el test que lo use debe saltarse: medir contra una KB vacía es
exactamente lo que este módulo existe para evitar.
"""

from __future__ import annotations

from typing import Iterable, Optional, Tuple

import sqlalchemy as sa

import src.modules.system.config_reading as CR
from src.modules.infrastructure import UnitOfWork
from src.modules.features.themis.repositories import KbRepository

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
        return None

    try:
        with engine.connect() as conn:
            rows = conn.execute(_QUERY, {"products": list(products)}).mappings().all()
    finally:
        engine.dispose()

    # Una CVE trae varias filas de aplicabilidad; upsert_cve las reemplaza en
    # bloque, así que hay que agruparlas antes y no llamar una vez por fila.
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

    with UnitOfWork() as uow:
        repo = KbRepository(uow)
        for entry in grouped.values():
            repo.upsert_cve(entry["cve"], entry["matches"])
        uow.commit()

    return len(grouped)
