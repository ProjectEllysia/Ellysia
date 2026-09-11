"""
Excepciones de confianza por usuario: remitentes y dominios de confianza.

Un falso positivo recurrente —el boletín de un proveedor que siempre usa un
``Reply-To`` distinto, la alerta de un banco que siempre dice «urgente»— solo
se podía quitar tocando la configuración global, que afecta a toda la
instalación. Una excepción de confianza lo quita para **un** usuario, con
motivo y caducidad, y deja rastro en cada análisis al que se aplica.

Dos reglas de diseño que este módulo hace cumplir y que no se relajan:

- **Solo se aplica a correo que demuestra venir de ese remitente.** Coincidir
  con el ``From`` no basta: el ``From`` lo escribe cualquiera. Hace falta que
  DMARC pase **y** que la cabecera ``Authentication-Results`` que lo afirma la
  haya escrito un servidor por encima de la frontera de confianza de la cadena
  ``Received`` (regla «Auth Results Provenance», ver ``services/auth_trust.py``).
  Sin eso, la excepción se ignora y el análisis dice por qué.
- **Solo modula las señales que cubre.** Una excepción dice «conozco a este
  remitente y sé que escribe así»; responde a las heurísticas de lenguaje y de
  forma que un remitente legítimo dispara (``TRUST_MODULATED_RULES``). Nunca
  toca la autenticación, los adjuntos, los enlaces (incluidos los *cloaked* y
  los QR), las suplantaciones de dominio ni las falsificaciones estructurales:
  esas reglas no están en la lista, así que sus gates siguen disparando.

Módulo puro: sin base de datos ni red. El manager le pasa las excepciones
activas ya cargadas como ``TrustEntry``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .text import extract_domain

#: Reglas cuya penalización puede neutralizar una excepción de confianza.
#:
#: Son las que un remitente legítimo conocido dispara por su forma de escribir
#: o de enviar: lenguaje de urgencia, saludos genéricos, enlaces de
#: seguimiento, un ``Reply-To`` o un ``Return-Path`` en otro dominio. Quedan
#: fuera a propósito la familia ``auth``, la familia ``attachment``, la familia
#: ``links`` (enlaces *cloaked*, QR, dominios comprometidos), las suplantaciones
#: (dominios parecidos, marca en subdominio, dirección en el nombre visible),
#: las evasiones Unicode y de *encoded-word*, las falsificaciones de hilo y de
#: cadena ``Received``, y los patrones de fraude (BEC, TOAD): una cuenta de
#: confianza comprometida es justo el caso en que esas señales importan.
TRUST_MODULATED_RULES = frozenset({
    "Alarming Keywords",
    "Body Content",
    "Generic Greeting",
    "URL in Subject",
    "External Login Link",
    "External Image Tracking",
    "Reply-To check",
    "Reply-To Free Provider",
    "Return-Path mismatch",
    "From Reply-To Return-Path Triangulation",
    "Display Name Email Mismatch",
    "Suspicious TLD",
    "Misspelled Brand Names",
    "Message-ID Domain",
    "Undisclosed Recipients",
})

#: ``verdict`` que recibe una regla neutralizada por una excepción. El
#: veredicto y el score originales viajan en ``details["trustOverride"]``.
TRUST_OVERRIDE_VERDICT = "trusted"

#: Caducidad por defecto de una excepción, en días.
DEFAULT_TRUST_EXPIRY_DAYS = 90

#: Caducidad máxima de una excepción, en días. Es código y no configuración a
#: propósito: una excepción sin fin es un bypass permanente que nadie vuelve a
#: revisar, y esa garantía no debe poder rebajarse desde ``SecOpsConfig.json``.
MAX_TRUST_EXPIRY_DAYS = 365

#: Longitud máxima del motivo de una excepción.
MAX_TRUST_REASON_LENGTH = 500

_ANGLE_ADDRESS_RE = re.compile(r"<\s*([^<>@\s]+@[^<>\s]+?)\s*>")
_BARE_ADDRESS_RE = re.compile(r"[\w.+'-]+@[\w-]+(?:\.[\w-]+)+")
_DOMAIN_RE = re.compile(r"^(?=.{3,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")


@dataclass(frozen=True)
class TrustEntry:
    """Una excepción de confianza activa, reducida a lo que el motor necesita.

    Attributes:
        id: Primary key de la fila ``IrisTrustedSender``.
        kind: ``sender`` (una dirección exacta) o ``domain`` (el dominio del
            ``From`` y sus subdominios).
        value: Dirección o dominio ya normalizado (ver
            ``normalize_trust_value``).
        reason: Motivo que escribió el usuario al crearla.
    """

    id: int
    kind: str
    value: str
    reason: str


def normalize_trust_value(kind: str, value: str) -> str:
    """Normaliza y valida el valor de una excepción antes de guardarla.

    Args:
        kind: ``sender`` o ``domain``.
        value: Lo que escribió el usuario. Para ``sender``, una dirección
            (``nombre@dominio.tld``, admite ``Nombre <dir>``); para ``domain``,
            un dominio (se quita un ``@`` inicial si lo trae).

    Returns:
        str: El valor en minúsculas y sin espacios: la dirección sola, o el
            dominio sin punto final.

    Raises:
        ValueError: Si ``kind`` no es uno de los dos, o si el valor no tiene
            forma de dirección o de dominio. El mensaje es apto para el usuario.
    """
    cleaned = (value or "").strip().lower()
    if kind == "sender":
        address = sender_address(cleaned)
        if not address:
            raise ValueError("El remitente debe ser una dirección de correo (nombre@dominio).")
        return address
    if kind == "domain":
        domain = cleaned.lstrip("@").rstrip(".")
        if not _DOMAIN_RE.match(domain):
            raise ValueError("El dominio no es válido (ejemplo: proveedor.com).")
        return domain
    raise ValueError(f"Tipo de excepción desconocido: {kind!r}.")


def sender_address(from_header: str) -> Optional[str]:
    """Dirección de correo de un valor de cabecera ``From``.

    Prefiere la dirección entre ángulos (``"Nombre" <dir>``) porque el nombre
    visible puede contener otra dirección escrita a mano para engañar.

    Args:
        from_header: Valor crudo de la cabecera, o una dirección suelta.

    Returns:
        Optional[str]: La dirección en minúsculas, o ``None`` si no hay ninguna.
    """
    text = from_header or ""
    match = _ANGLE_ADDRESS_RE.search(text) or _BARE_ADDRESS_RE.search(text)
    return match.group(1 if match.re is _ANGLE_ADDRESS_RE else 0).lower() if match else None


def find_matching_entry(headers: Mapping[str, Any], entries: Sequence[TrustEntry]) -> Optional[TrustEntry]:
    """Excepción que cubre el remitente de un mensaje, si alguna lo hace.

    Una excepción de dirección gana a una de dominio: es la más específica, y
    su motivo describe mejor este mensaje.

    Args:
        headers: Cabeceras parseadas del mensaje evaluado (claves en minúscula).
        entries: Excepciones activas del usuario.

    Returns:
        Optional[TrustEntry]: La que coincide con el ``From``, o ``None``.
    """
    address = sender_address(str(headers.get("from") or ""))
    if not address:
        return None
    domain = extract_domain(address) or ""
    by_address = [entry for entry in entries if entry.kind == "sender" and entry.value == address]
    if by_address:
        return by_address[0]
    for entry in entries:
        if entry.kind == "domain" and (domain == entry.value or domain.endswith("." + entry.value)):
            return entry
    return None


def is_sender_authenticated(named_results: Mapping[str, Any]) -> bool:
    """¿Demuestra el mensaje venir del dominio de su ``From``?

    DMARC en ``pass`` ata SPF o DKIM al dominio visible; «Auth Results
    Provenance» en ``pass`` garantiza que esa afirmación la escribió un
    verificador por encima de la frontera de confianza y no el propio
    remitente. Hacen falta las dos.

    Args:
        named_results: ``RuleResult`` por nombre de regla del contexto evaluado.

    Returns:
        bool: ``True`` solo si las dos reglas pasaron.
    """
    dmarc = named_results.get("DMARC")
    provenance = named_results.get("Auth Results Provenance")
    return (dmarc is not None and dmarc.verdict == "pass"
            and provenance is not None and provenance.verdict == "pass")


def apply_trust(rules_defs: Sequence[dict], results: Sequence[Any],
                entry: TrustEntry) -> Tuple[List[Any], List[str]]:
    """Neutraliza las penalizaciones que cubre una excepción de confianza.

    Cada regla de ``TRUST_MODULATED_RULES`` que penalizó pasa a score ``0`` y
    veredicto ``trusted``, así que ni resta puntos ni dispara su gate; su
    veredicto y su score originales quedan en ``details["trustOverride"]`` para
    que el informe diga qué se neutralizó y por qué. «Body Content» con texto
    oculto no se toca: esconder texto es evasión, no un estilo de redacción.

    Args:
        rules_defs: Catálogo evaluado, emparejado por posición con ``results``.
        results: Un ``RuleResult`` por regla.
        entry: Excepción que se aplica.

    Returns:
        Tuple[List[RuleResult], List[str]]: Los resultados ya modulados (los
            no afectados, tal cual) y los nombres de las reglas neutralizadas,
            en el orden del catálogo; lista vacía si ninguna penalizaba.
    """
    modulated_results: List[Any] = []
    modulated_names: List[str] = []
    for rule_def, result in zip(rules_defs, results):
        details = result.details or {}
        is_covered = (rule_def["name"] in TRUST_MODULATED_RULES and result.score < 0
                      and not details.get("hidden_text"))
        if not is_covered:
            modulated_results.append(result)
            continue
        modulated_names.append(rule_def["name"])
        modulated_results.append(replace(
            result, score=0.0, verdict=TRUST_OVERRIDE_VERDICT, recommendation=None,
            details={**details, "trustOverride": {
                "entryId": entry.id, "originalVerdict": result.verdict, "originalScore": result.score,
            }},
        ))
    return modulated_results, modulated_names


def build_trust_record(entry: TrustEntry, modulated_rules: List[str], is_applied: bool) -> Dict[str, Any]:
    """Rastro de una excepción en el análisis al que se intentó aplicar.

    Args:
        entry: Excepción que coincidió con el remitente.
        modulated_rules: Reglas que neutralizó; vacía si no se aplicó.
        is_applied: ``False`` cuando coincidió pero el mensaje no demostró
            venir de ese remitente.

    Returns:
        dict: ``entryId``, ``kind``, ``value``, ``reason``, ``applied`` y
            ``modulatedRules``, con claves camelCase para guardarlo en JSONB y
            devolverlo tal cual en el informe.
    """
    return {
        "entryId": entry.id, "kind": entry.kind, "value": entry.value, "reason": entry.reason,
        "applied": is_applied, "modulatedRules": modulated_rules,
    }


def describe_trust_record(record: Mapping[str, Any]) -> str:
    """Frase legible del rastro de una excepción, para los motivos del veredicto.

    Args:
        record: Salida de ``build_trust_record``.

    Returns:
        str: Qué excepción se aplicó y cuántas reglas neutralizó, o por qué no
            se aplicó.
    """
    target = f"{'el remitente' if record['kind'] == 'sender' else 'el dominio'} {record['value']}"
    if not record["applied"]:
        return (f"Hay una excepción de confianza para {target}, pero no se aplicó: el mensaje "
                "no demuestra venir de ahí (DMARC no pasa o lo afirma un servidor no verificable).")
    count = len(record["modulatedRules"])
    return (f"Excepción de confianza aplicada a {target} ({record['reason']}): "
            f"{count} {'regla neutralizada' if count == 1 else 'reglas neutralizadas'}. "
            "Autenticación, adjuntos y enlaces se evaluaron sin excepción.")
