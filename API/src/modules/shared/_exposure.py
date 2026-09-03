"""¿Este objetivo está expuesto a internet, o vive en una red interna?

Es una regla de negocio con consecuencias reales en dos sitios a la vez: acota
la prioridad de todo hallazgo en red privada (tope HIGH en ``score_finding``) y
entra en el prompt del informe, que le dice al modelo *"MÁXIMO risk_level
permitido en LAN sin anomalías confirmadas: MEDIO"*.

Estaba implementada dos veces —``lybra.correlation.classify_exposure`` y
``analyzers._classify_network_context``— y la duplicación estaba documentada en
el propio código como concesión consciente: la capa pura de Lybra no puede
importar el módulo del escritor de IA, que arrastra dependencias pesadas.

La razón era buena y la consecuencia mala. Si las dos implementaciones
divergen, el scoring y el informe dicen cosas distintas sobre el mismo host y
**nada lo detecta**: no fallan tests, no hay error, sólo dos respuestas que ya
no coinciden. Es el patrón que el propio proyecto cataloga como
``bloque:verdad``.

Vive en ``shared/`` porque es lo único que las dos capas pueden importar sin
arrastrarse la una a la otra. La invariante de ``themis/lybra/`` es estar libre
de ORM y de efectos de red, no estar libre de imports — y este módulo no tiene
más dependencia que ``ipaddress``.
"""

from __future__ import annotations

import ipaddress

#: Sufijos de nombre que identifican una red interna.
#:
#: ``.local`` es mDNS (RFC 6762) y ``.home.arpa`` es el nombre que el RFC 8375
#: reserva para redes domésticas; ``.internal`` lo reserva el ICANN para uso
#: privado. El resto son convenciones muy extendidas en redes corporativas que,
#: sin estar reservadas por ningún estándar, no resuelven en la internet
#: pública.
#:
#: Errar aquí es asimétrico: clasificar como pública una red interna sólo infla
#: la prioridad de un hallazgo, mientras que lo contrario la rebaja y puede
#: esconder algo que sí está expuesto. Por eso la lista se queda en nombres que
#: de verdad no salen a internet.
PRIVATE_HOST_SUFFIXES = (
    ".local",
    ".home.arpa",
    ".internal",
    ".lan",
    ".intranet",
    ".corp",
    ".home",
)

#: Nombres sin sufijo que también son la máquina local.
PRIVATE_HOST_NAMES = ("localhost",)


def is_private_target(target: str) -> bool:
    """Si un objetivo vive en una red interna.

    Args:
        target: Una dirección IP o un nombre de host.

    Returns:
        ``True`` para una dirección privada, de loopback o link-local, y para
        un nombre que sólo resuelve dentro de una red interna. Un nombre que no
        se reconoce se trata como público: es la respuesta prudente, porque
        equivocarse hacia "privado" rebajaría la prioridad de un hallazgo que
        quizá sí está expuesto.
    """
    stripped = target.strip()
    try:
        address = ipaddress.ip_address(stripped)
    except ValueError:
        lowered = stripped.lower()
        return (lowered in PRIVATE_HOST_NAMES
                or any(lowered.endswith(suffix) for suffix in PRIVATE_HOST_SUFFIXES))
    return address.is_private or address.is_loopback or address.is_link_local


def classify_exposure(target: str) -> str:
    """La exposición de un objetivo, en la forma que consume el scoring.

    Args:
        target: Una dirección IP o un nombre de host.

    Returns:
        ``"private"`` o ``"public"``.
    """
    return "private" if is_private_target(target) else "public"
