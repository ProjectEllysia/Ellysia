"""
shared._white_label
───────────────────
White-labeling: cuánto de la marca del producto ve el destinatario final de
algo que la plataforma le entrega (un correo de campaña, la página pública de
un test, …) y con qué marca se sustituye.

Aquí vive el concepto en crudo — niveles, logo y validación — sin saber en qué
canal se va a pintar. La proyección a un canal concreto vive en el canal:
``tools.herald.branding`` lo traduce a la marca de un correo y a su imagen
incrustada; un endpoint que sirva marca a la SPA lo traduce a JSON.

Piezas:
    WhiteLabelLevel     — los tres niveles.
    WhiteLabel          — los ajustes ya resueltos, con el logo decodificable.
    WhiteLabelColumns   — mixin de columnas para persistirlos en cualquier modelo.
    validate_logo_data_uri / validate_brand_color — validación en el borde de
        confianza.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from enum import Enum

from sqlalchemy import Column, String, Text


#: Formatos admitidos para el logo. Sin SVG a propósito: prácticamente ningún
#: cliente de correo lo renderiza, y es un vector de script embebido.
ALLOWED_LOGO_MIMETYPES: frozenset[str] = frozenset({"image/png", "image/jpeg", "image/gif"})

#: Tope del logo ya decodificado. Un correo entero debería quedar holgadamente
#: por debajo de los límites de recorte de Gmail (~102 KB de HTML) y de los
#: tamaños de mensaje que aceptan los relays.
MAX_LOGO_BYTES: int = 200 * 1024

#: Color de énfasis: solo hexadecimal de 6 dígitos. Este valor acaba dentro de
#: atributos ``style`` de la plantilla del correo, así que la validación es
#: estricta a propósito — no se admite ningún valor CSS libre.
_BRAND_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")

_DATA_URI_RE = re.compile(r"^data:(?P<mimetype>[\w.+-]+/[\w.+-]+);base64,(?P<payload>[A-Za-z0-9+/=\s]+)$")


class WhiteLabelLevel(str, Enum):
    """Cuánta marca propia sustituye a la del producto.

    NONE  — nada: el destinatario ve exactamente lo de siempre.
    COLOR — el color de énfasis pasa a ser el del cliente. Es el escalón
            barato: un color lo tiene a mano cualquier marca, mientras que un
            logo con fondo transparente y proporciones sanas no siempre.
    LOGO  — además, se añade el logo del cliente al contenido; la marca del
            producto sigue en cabecera y pie.
    FULL  — además, la marca del producto desaparece: cabecera, pie y página
            pública pasan a la del cliente.
    """

    NONE = "none"
    COLOR = "color"
    LOGO = "logo"
    FULL = "full"

    @property
    def rank(self) -> int:
        """Posición en la escalera. Es también el valor que concede el plan."""
        return _LEVEL_ORDER.index(self)

    @classmethod
    def from_allowance(cls, allowance: int | None) -> "WhiteLabelLevel":
        """El nivel máximo que concede un tope de plan.

        Traduce el ``value`` de una fila de ``PlanLimit`` (``None`` = sin
        techo, ``0`` = no incluido, ``n`` = escalón n) al nivel. Un tope mayor
        que el último escalón no es un error: concede el más alto, para que
        añadir escalones más adelante no obligue a reescribir los planes.
        """
        if allowance is None:
            return _LEVEL_ORDER[-1]
        return _LEVEL_ORDER[max(0, min(allowance, len(_LEVEL_ORDER) - 1))]

    @classmethod
    def coerce(cls, value: "WhiteLabelLevel | str | None") -> "WhiteLabelLevel":
        """Convierte lo que haya en la BD (o None) en un nivel válido.

        Un valor desconocido cae a NONE en vez de reventar: quedarse corto de
        personalización es un defecto cosmético, romper el envío de una
        campaña entera no.
        """
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value or "").lower())
        except ValueError:
            return cls.NONE


#: La escalera, de menos a más. El índice es el ``rank`` y el valor que un plan
#: declara en ``PlanLimit`` para conceder ese nivel.
_LEVEL_ORDER: tuple[WhiteLabelLevel, ...] = (
    WhiteLabelLevel.NONE,
    WhiteLabelLevel.COLOR,
    WhiteLabelLevel.LOGO,
    WhiteLabelLevel.FULL,
)


def validate_logo_data_uri(value: str) -> tuple[str, bytes]:
    """
    Valida un logo recibido como data URI y lo devuelve ya decodificado.

    Es la validación del borde de confianza: el data URI llega del navegador,
    así que ni el tipo declarado ni el tamaño son de fiar hasta pasar por aquí.

    Args:
        value: Data URI en base64 ('data:image/png;base64,iVBORw0…').

    Returns:
        ``(mimetype, bytes)``.

    Raises:
        ValueError: Si el formato, el tipo o el tamaño no son admisibles.
    """
    value = (value or "").strip()
    # Corte antes de decodificar: base64 abulta ~4/3, así que cualquier cadena
    # más larga que esto no puede caber en el tope una vez decodificada, y no
    # tiene sentido gastar la decodificación (ni la memoria) en descubrirlo.
    if len(value) > MAX_LOGO_BYTES * 2:
        raise ValueError(f"El logo supera el máximo de {MAX_LOGO_BYTES // 1024} KB.")

    match = _DATA_URI_RE.match(value)
    if not match:
        raise ValueError("El logo debe ser un data URI en base64 ('data:image/png;base64,…').")

    mimetype = match.group("mimetype").lower()
    if mimetype not in ALLOWED_LOGO_MIMETYPES:
        allowed = ", ".join(sorted(ALLOWED_LOGO_MIMETYPES))
        raise ValueError(f"Formato de logo no admitido: '{mimetype}'. Admitidos: {allowed}.")

    try:
        data = base64.b64decode(match.group("payload"), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("El logo no es base64 válido.") from exc

    if not data:
        raise ValueError("El logo está vacío.")
    if len(data) > MAX_LOGO_BYTES:
        raise ValueError(f"El logo supera el máximo de {MAX_LOGO_BYTES // 1024} KB.")

    return mimetype, data


def validate_brand_color(value: str) -> str:
    """
    Valida un color de énfasis y lo normaliza a minúsculas.

    Args:
        value: Color hexadecimal de 6 dígitos ('#1a73e8').

    Returns:
        El mismo color en minúsculas.

    Raises:
        ValueError: Si no es un hexadecimal de 6 dígitos.
    """
    value = (value or "").strip()
    if not _BRAND_COLOR_RE.match(value):
        raise ValueError("El color debe ser hexadecimal de 6 dígitos ('#1a73e8').")
    return value.lower()


@dataclass(frozen=True)
class WhiteLabel:
    """
    Ajustes de white-labeling ya resueltos, listos para proyectar a un canal.

    Attributes:
        level: Nivel aplicado.
        logo: Logo del cliente como data URI, o cadena vacía.
        color: Color de énfasis del cliente ('#1a73e8'), o cadena vacía.
        brand_name: Nombre con el que sustituir la marca del producto en el
            nivel FULL. Sin él, el nivel FULL se queda sin nombre que poner y
            degrada un escalón (ver ``effective_level``).
    """

    level: WhiteLabelLevel = WhiteLabelLevel.NONE
    logo: str = ""
    color: str = ""
    brand_name: str = ""

    @classmethod
    def from_stored(
        cls,
        level: "WhiteLabelLevel | str | None",
        logo: str | None,
        color: str | None,
        brand_name: str | None,
    ) -> "WhiteLabel":
        """Construye los ajustes a partir de lo persistido, tolerando NULLs."""
        return cls(
            level=WhiteLabelLevel.coerce(level),
            logo=(logo or "").strip(),
            color=(color or "").strip(),
            brand_name=(brand_name or "").strip(),
        )

    @property
    def effective_level(self) -> WhiteLabelLevel:
        """El nivel que de verdad puede aplicarse con los datos que hay.

        Cada escalón necesita su dato: FULL un nombre con el que sustituir la
        marca, LOGO un logo, COLOR un color. Si falta, se baja un escalón (y se
        vuelve a comprobar) en vez de entregar algo a medias — un FULL sin
        nombre dejaría el correo sin cabecera ni pie legibles.
        """
        requirements = {
            WhiteLabelLevel.FULL:  self.brand_name,
            WhiteLabelLevel.LOGO:  self.logo,
            WhiteLabelLevel.COLOR: self.color,
        }
        level = self.level
        while level is not WhiteLabelLevel.NONE and not requirements[level]:
            level = _LEVEL_ORDER[level.rank - 1]
        return level

    def capped_to(self, maximum: WhiteLabelLevel) -> "WhiteLabel":
        """Los mismos ajustes, sin pasar de ``maximum``.

        El tope lo pone el plan, y se aplica **también al usar** los ajustes,
        no solo al guardarlos: al bajar de plan, un nivel que era legal deja de
        serlo, y nadie borra nada — igual que unas existencias que quedan por
        encima del tope entran en solo lectura en vez de desaparecer.
        """
        if self.level.rank <= maximum.rank:
            return self
        return WhiteLabel(
            level=maximum, logo=self.logo, color=self.color, brand_name=self.brand_name,
        )

    def decoded_logo(self) -> tuple[str, bytes] | None:
        """El logo como ``(mimetype, bytes)``, o None si no hay o no es válido.

        No lanza: lo que está guardado ya pasó la validación de entrada, y un
        logo corrupto no debe tumbar un envío en curso.
        """
        if not self.logo:
            return None
        try:
            return validate_logo_data_uri(self.logo)
        except ValueError:
            return None


class WhiteLabelColumns:
    """
    Mixin de columnas para persistir el white-labeling en cualquier modelo.

    Un modelo que quiera ofrecerlo hereda de aquí y añade su migración; el
    nombre de marca no se incluye a propósito, porque cada modelo ya suele
    tener el suyo (``company``, ``name``, …) y duplicarlo lo dejaría
    desincronizado.
    """

    white_label_level = Column(
        String(16), nullable=False, default=WhiteLabelLevel.NONE.value, server_default=WhiteLabelLevel.NONE.value,
    )
    #: Data URI del logo. Text, no bytes: se guarda como llega del navegador y
    #: se sirve igual al frontend para previsualizarlo, sin recodificar.
    brand_logo = Column(Text, nullable=True)
    #: Color de énfasis en hexadecimal ('#1a73e8').
    brand_color = Column(String(7), nullable=True)
