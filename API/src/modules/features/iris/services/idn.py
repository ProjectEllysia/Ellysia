"""
Dominios internacionalizados (IDN): cuándo son legítimos y cuándo un homógrafo.

Un dominio con caracteres no ASCII viaja en punycode (``xn--mnchen-3ya.de`` es
``münchen.de``). Hasta ahora cualquier etiqueta ``xn--`` se trataba como
sospechosa, lo que penalizaba a todo remitente legítimo de un idioma con
tildes, cirílico, griego o escrituras asiáticas. Lo sospechoso no es el IDN en
sí, sino dos cosas concretas:

- **Mezcla de alfabetos** en una misma etiqueta (``pаypal`` con una ``а``
  cirílica entre letras latinas): ningún idioma la produce, salvo las
  combinaciones que Unicode admite para el japonés, el coreano y el chino
  (perfil *highly restrictive* de UTS #39).
- **Homógrafo de una marca**: el *esqueleto* visual de una etiqueta —cada
  carácter sustituido por la letra latina con la que se confunde, según la
  tabla oficial de confusables de Unicode, y sin tildes— coincide con una
  marca conocida aunque la etiqueta no sea la marca.

Un IDN de un solo alfabeto cuyo esqueleto no es una marca es un dominio
internacionalizado válido y no se penaliza.

Módulo puro: sin base de datos ni red. Los datos de confusables vienen del
paquete ``confusable_homoglyphs``, que empaqueta la tabla de Unicode.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from typing import Iterable, Optional, Tuple

from confusable_homoglyphs import categories, confusables

#: Alfabetos que no cuentan para decidir si una etiqueta mezcla escrituras:
#: dígitos, guion y marcas combinantes son comunes a todas.
_NEUTRAL_SCRIPTS = frozenset({"COMMON", "INHERITED"})

#: Combinaciones de alfabetos que un idioma real usa en una misma palabra
#: (UTS #39, perfil *highly restrictive*): japonés, coreano y chino con latín.
_ALLOWED_SCRIPT_COMBINATIONS = (
    frozenset({"LATIN", "HAN", "HIRAGANA", "KATAKANA"}),
    frozenset({"LATIN", "HAN", "HANGUL"}),
    frozenset({"LATIN", "HAN", "BOPOMOFO"}),
)


class IdnVerdict(StrEnum):
    """Qué es un dominio desde el punto de vista de la suplantación visual.

    Attributes:
        ASCII: Solo ASCII; no hay nada internacionalizado que evaluar.
        VALID_IDN: Internacionalizado legítimo: un solo alfabeto (o una
            combinación admitida) y ningún homógrafo de marca.
        MIXED_SCRIPT: Alguna etiqueta mezcla alfabetos que ningún idioma
            combina.
        BRAND_HOMOGRAPH: Alguna etiqueta es visualmente una marca conocida
            sin serlo.
    """
    ASCII = "ascii"
    VALID_IDN = "valid_idn"
    MIXED_SCRIPT = "mixed_script"
    BRAND_HOMOGRAPH = "brand_homograph"


@dataclass(frozen=True)
class IdnAssessment:
    """Resultado de evaluar un dominio.

    Attributes:
        verdict: ``IdnVerdict``.
        unicode_domain: El dominio con las etiquetas punycode decodificadas.
        label: La etiqueta que decidió el veredicto (en Unicode); ``None`` en
            ``ASCII`` y ``VALID_IDN``.
        scripts: Alfabetos de esa etiqueta, ordenados; vacío si no aplica.
        brand: La marca que imita, en ``BRAND_HOMOGRAPH``; ``None`` si no.
    """
    verdict: IdnVerdict
    unicode_domain: str
    label: Optional[str] = None
    scripts: Tuple[str, ...] = ()
    brand: Optional[str] = None

    @property
    def is_suspicious(self) -> bool:
        """``True`` en mezcla de alfabetos y en homógrafo de marca."""
        return self.verdict in (IdnVerdict.MIXED_SCRIPT, IdnVerdict.BRAND_HOMOGRAPH)


def to_unicode(domain: str) -> str:
    """Decodifica las etiquetas punycode (``xn--``) de un dominio.

    Args:
        domain: Dominio tal como aparece en una cabecera o una URL.

    Returns:
        str: El dominio en minúsculas con cada etiqueta ``xn--`` decodificada;
            una etiqueta que no decodifica se deja tal cual.
    """
    labels = []
    for label in (domain or "").strip(".").lower().split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


def label_scripts(label: str) -> frozenset[str]:
    """Alfabetos de una etiqueta, sin contar los comunes (dígitos, guion).

    Args:
        label: Una etiqueta de dominio en Unicode.

    Returns:
        frozenset[str]: Nombres Unicode de los alfabetos (``LATIN``,
            ``CYRILLIC``, ``HAN``…); vacío si solo hay caracteres comunes.
    """
    return frozenset(categories.unique_aliases(label)) - _NEUTRAL_SCRIPTS


def is_mixed_script(label: str) -> bool:
    """Si una etiqueta mezcla alfabetos que ningún idioma combina.

    Args:
        label: Una etiqueta de dominio en Unicode.

    Returns:
        bool: ``True`` si tiene dos o más alfabetos y no son una de las
            combinaciones de ``_ALLOWED_SCRIPT_COMBINATIONS``.
    """
    scripts = label_scripts(label)
    if len(scripts) <= 1:
        return False
    return not any(scripts <= allowed for allowed in _ALLOWED_SCRIPT_COMBINATIONS)


@lru_cache(maxsize=4096)
def _skeleton_char(char: str) -> str:
    """Letra latina con la que se confunde visualmente un carácter.

    Args:
        char: Un carácter.

    Returns:
        str: El carácter ASCII equivalente (sin tildes, sin anchura completa,
            sin variantes matemáticas, o su confusable latino según Unicode);
            el propio carácter si no se parece a ninguno.
    """
    if char.isascii():
        return char
    decomposed = "".join(c for c in unicodedata.normalize("NFKD", char) if not unicodedata.combining(c))
    if decomposed and decomposed.isascii():
        return decomposed.lower()
    matches = confusables.is_confusable(char, preferred_aliases=["latin"]) or []
    for match in matches:
        for homoglyph in match.get("homoglyphs", []):
            candidate = homoglyph.get("c", "")
            if len(candidate) == 1 and candidate.isascii() and candidate.isalnum():
                return candidate.lower()
    return char


def skeleton(text: str) -> str:
    """Esqueleto visual de un texto: cómo lo lee un humano, en ASCII.

    ``pаypаl`` (con ``а`` cirílicas) -> ``paypal``; ``gööglé`` -> ``google``;
    ``ｇｏｏｇｌｅ`` (anchura completa) -> ``google``.

    Args:
        text: Texto en cualquier escritura.

    Returns:
        str: El texto en minúsculas con cada carácter sustituido por su
            equivalente latino cuando lo tiene.
    """
    return "".join(_skeleton_char(char) for char in (text or "").lower())


def assess_domain(domain: str, brands: Iterable[str]) -> IdnAssessment:
    """Decide si un dominio internacionalizado es legítimo o una suplantación.

    Se evalúan todas las etiquetas, no solo la registrable: un homógrafo de
    marca en un subdominio (``pаypal.ejemplo.com``) engaña igual.

    Args:
        domain: Dominio en punycode o en Unicode.
        brands: Marcas conocidas (``wordlists.canonical_brands``).

    Returns:
        IdnAssessment: ``ASCII`` si no hay nada internacionalizado;
            ``BRAND_HOMOGRAPH`` si alguna etiqueta no ASCII tiene por esqueleto
            una marca; si no, ``MIXED_SCRIPT`` si alguna mezcla alfabetos; y
            ``VALID_IDN`` en el resto.
    """
    unicode_domain = to_unicode(domain)
    if unicode_domain.isascii():
        return IdnAssessment(IdnVerdict.ASCII, unicode_domain)

    brand_set = frozenset(brands)
    labels = [label for label in unicode_domain.split(".") if not label.isascii()]
    for label in labels:
        # Un homógrafo es una marca escrita con caracteres que no lo son: la
        # palabra tiene que cambiar al leerla. «paypal» tal cual dentro de
        # «paypal-segurídad» no es un homógrafo sino un dominio primo, y de
        # eso se encarga el análisis normal de la regla sobre el esqueleto.
        for token in [label, *label.split("-")]:
            visual = skeleton(token)
            if visual in brand_set and visual != token:
                return IdnAssessment(IdnVerdict.BRAND_HOMOGRAPH, unicode_domain, label,
                                     tuple(sorted(label_scripts(label))), visual)
    for label in labels:
        if is_mixed_script(label):
            return IdnAssessment(IdnVerdict.MIXED_SCRIPT, unicode_domain, label,
                                 tuple(sorted(label_scripts(label))))
    return IdnAssessment(IdnVerdict.VALID_IDN, unicode_domain)
