"""aegis: productos vigilados desde la BD en vez de un catálogo de config

``AegisOrgProfile.associated_brands`` guardaba etiquetas libres ("Microsoft")
que solo tenían sentido contra una lista fija de 19 marcas en
``SecOpsConfig.json``. Pasa a ``tracked_products``: pares ``(vendor, product)``
de CPE, que es lo que indexa el espejo local de NVD, así que cualquier producto
que NVD conozca puede vigilarse.

La conversión no necesita adivinar nada: el catálogo que se retira ya contenía
el mapeo (sus claves ``circl_vendor``/``circl_product`` **son** coordenadas
CPE, porque la API de CIRCL se direcciona por CPE). Se embebe aquí como
literal, en vez de leerlo de la config, porque una migración tiene que seguir
dando el mismo resultado dentro de un año, cuando ese bloque de configuración
ya no exista.

Se añade también ``use_hygeia_inventory``, por defecto cierto: los productos
se deducen del inventario que reporten los agentes de Hygeia cuando los haya,
y quien no tenga agentes no nota diferencia (se cae a la lista manual).

Revision ID: 98b18ef22160
Revises: 6192692bd7d7
Create Date: 2026-08-04 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "98b18ef22160"
down_revision: Union[str, None] = "6192692bd7d7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


#: El catálogo retirado de ``features.aegis.brands``, congelado.
_LABEL_TO_CPE: dict[str, tuple[str, str]] = {
    "Microsoft": ("microsoft", "windows"),
    "Cisco":     ("cisco", "ios"),
    "Apple":     ("apple", "macos"),
    "Google":    ("google", "chrome"),
    "Adobe":     ("adobe", "acrobat"),
    "Android":   ("google", "android"),
    "HPE":       ("hpe", "hpe"),
    "SonicWall": ("sonicwall", "sonicos"),
    "Konica":    ("konicaminolta", "printer"),
    "Juniper":   ("juniper", "junos"),
    "VMware":    ("vmware", "esxi"),
    "Palo Alto": ("paloaltonetworks", "pan-os"),
    "SAP":       ("sap", "netweaver"),
    "Oracle":    ("oracle", "database"),
    "Mozilla":   ("mozilla", "firefox"),
    "Linux":     ("linux", "kernel"),
    "Fortinet":  ("fortinet", "fortios"),
    "IBM":       ("ibm", ""),
    "Chrome":    ("google", "chrome"),
}

#: Inverso para el downgrade. Es **lossy a propósito y sin remedio**: el
#: catálogo original tenía etiquetas distintas apuntando al mismo CPE
#: ("Google" y "Chrome" son ambas ``google:chrome``, "Android" es
#: ``google:android``), así que volver atrás recupera un conjunto equivalente
#: de etiquetas, no necesariamente el literal que había. Da igual: apuntan al
#: mismo producto, que es lo único que se consultaba con ellas.
_CPE_TO_LABEL = {cpe: label for label, cpe in _LABEL_TO_CPE.items()}


def _profiles_table() -> sa.Table:
    """Tabla mínima para el paso de datos, sin depender del modelo vivo."""
    return sa.table(
        "AegisOrgProfile",
        sa.column("id", sa.Integer),
        sa.column("associated_brands", postgresql.JSONB),
        sa.column("tracked_products", postgresql.JSONB),
    )


def upgrade() -> None:
    op.add_column(
        "AegisOrgProfile",
        sa.Column("tracked_products", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column(
        "AegisOrgProfile",
        sa.Column(
            "use_hygeia_inventory", sa.Boolean(), nullable=False, server_default=sa.true(),
        ),
    )

    # En modo offline (``alembic upgrade --sql``) no hay conexión que consultar:
    # se emite el DDL y el paso de datos se omite, que es lo único que puede
    # hacerse al generar un script sin ver la base.
    if op.get_context().as_sql:
        op.drop_column("AegisOrgProfile", "associated_brands")
        return

    connection = op.get_bind()
    profiles = _profiles_table()
    rows = connection.execute(
        sa.select(profiles.c.id, profiles.c.associated_brands)
    ).fetchall()

    for profile_id, brands in rows:
        if not brands:
            continue
        products, seen = [], set()
        for label in brands:
            pair = _LABEL_TO_CPE.get(label)
            # Una etiqueta fuera del catálogo no es convertible a un CPE:
            # descartarla es preferible a inventar un vendor que casaría
            # CVEs contra software que no es el del usuario.
            if pair is None or pair in seen:
                continue
            seen.add(pair)
            products.append({"vendor": pair[0], "product": pair[1]})
        if products:
            connection.execute(
                profiles.update()
                .where(profiles.c.id == profile_id)
                .values(tracked_products=products)
            )

    op.drop_column("AegisOrgProfile", "associated_brands")


def downgrade() -> None:
    op.add_column(
        "AegisOrgProfile",
        sa.Column("associated_brands", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )

    if op.get_context().as_sql:
        op.drop_column("AegisOrgProfile", "use_hygeia_inventory")
        op.drop_column("AegisOrgProfile", "tracked_products")
        return

    connection = op.get_bind()
    profiles = _profiles_table()
    rows = connection.execute(
        sa.select(profiles.c.id, profiles.c.tracked_products)
    ).fetchall()

    for profile_id, products in rows:
        if not products:
            continue
        labels, seen = [], set()
        for entry in products:
            label = _CPE_TO_LABEL.get((entry.get("vendor"), entry.get("product")))
            # Los productos elegidos del índice CPE que no estaban en el
            # catálogo original no tienen etiqueta a la que volver.
            if label is None or label in seen:
                continue
            seen.add(label)
            labels.append(label)
        if labels:
            connection.execute(
                profiles.update()
                .where(profiles.c.id == profile_id)
                .values(associated_brands=labels)
            )

    op.drop_column("AegisOrgProfile", "use_hygeia_inventory")
    op.drop_column("AegisOrgProfile", "tracked_products")
