"""
themis.services.parsing
──────────────────────────
Parsers y validadores de especificaciones de IP y puertos para escaneos
Themis (Nmap/Nikto/Lybra/Nuclei). Aislado de managers.py: son funciones puras
sobre strings, sin sesión de BD ni TaskQueue de por medio.

Formatos de IP soportados (``validate_ip``):
    - IP individual: "192.168.1.1"
    - CIDR: "192.168.1.0/24"
    - Rangos por octeto: "192.168.1.1-10" o "192.168.1-2.1-10"
    - Lista separada por comas: "192.168.1.1,192.168.1.5"
    - Wildcards: "192.168.1.*" (equivalente a 192.168.1.0-255)

Formatos de puertos soportados (``validate_port``):
    "80", "80,443", "1-1000", "80,443-8080,9000"
"""

import ipaddress
import itertools
import socket
from typing import List

import src.modules.system.config_reading as CR
from ..exceptions import (
    IPValidationError,
    MaxHostsExceededError,
    PortValidationError,
    PrivateIPRequested,
)


def _require_non_empty(
    value: object,
    ErrorClass: type,
    default_msg: str = "El parámetro debe ser una cadena no vacía"
) -> str:
    """Validate and strip a string, raising ErrorClass if empty/invalid.

    ``IPValidationError`` y ``PortValidationError`` toman el valor inválido
    en un kwarg de nombre distinto (``ip_spec`` / ``port_spec``); se elige
    aquí según ``ErrorClass`` para no pasarle a una el kwarg de la otra.
    """
    spec_kwarg = "port_spec" if ErrorClass.__name__ == "PortValidationError" else "ip_spec"

    if not value or not isinstance(value, str):
        raise ErrorClass(message=default_msg, **{spec_kwarg: str(value)})
    stripped = value.strip()
    if not stripped:
        msg_map = {
            "IPValidationError": "La cadena de IPs está vacía",
            "PortValidationError": "La cadena de puertos está vacía",
        }
        raise ErrorClass(
            message=msg_map.get(ErrorClass.__name__, default_msg),
            **{spec_kwarg: stripped}
        )
    return stripped


# =============================================================================
# IPs
# =============================================================================

def _expand_octal_range(rango_str: str) -> List[str]:
    """Expand an octet-range/wildcard IP spec (e.g. ``192.168.1-2.1-10``)."""
    rango_str = rango_str.replace("*", "0-255")
    octetos = rango_str.split(".")

    if len(octetos) != 4:
        raise IPValidationError(
            message="Deben ser exactamente 4 octetos",
            ip_spec=rango_str
        )

    rangos_octetos: List[range | List[int]] = []

    for octeto in octetos:
        if "-" in octeto:
            partes = octeto.split("-")
            if len(partes) != 2:
                raise IPValidationError(
                    message="Rango de octeto inválido",
                    ip_spec=rango_str
                )
            try:
                inicio = int(partes[0])
                fin = int(partes[1])
            except ValueError:
                raise IPValidationError(
                    message="Los límites del rango deben ser numéricos",
                    ip_spec=rango_str
                )
            if inicio > fin:
                raise IPValidationError(
                    message="El inicio del rango no puede ser mayor que el fin",
                    ip_spec=rango_str
                )
            rangos_octetos.append(range(inicio, fin + 1))
        else:
            try:
                valor = int(octeto)
            except ValueError:
                raise IPValidationError(
                    message="El octeto debe ser numérico",
                    ip_spec=rango_str
                )
            rangos_octetos.append([valor])

    lista_ips = []
    for combinacion in itertools.product(*rangos_octetos):
        ip_str = ".".join(map(str, combinacion))
        try:
            ipaddress.ip_address(ip_str)
            lista_ips.append(ip_str)
        except ValueError:
            continue

    if not lista_ips:
        raise IPValidationError(
            message="No se generaron IPs válidas desde el rango",
            ip_spec=rango_str
        )
    return lista_ips


def _expand_cidr_segment(segmento: str, max_hosts: int) -> List[str]:
    """Expand a CIDR segment (e.g. ``192.168.1.0/24``) into host IPs."""
    try:
        red = ipaddress.ip_network(segmento, strict=False)
        num_hosts = red.num_addresses - 2 if red.num_addresses > 2 else red.num_addresses

        if num_hosts > max_hosts:
            raise MaxHostsExceededError(max_hosts=max_hosts, found=num_hosts)

        lista_ips = [str(ip) for ip in red.hosts()]
        if not lista_ips or red.prefixlen >= 31:
            lista_ips.extend([str(ip) for ip in red])
        return lista_ips
    except ValueError as e:
        raise IPValidationError(
            message=f"Notación CIDR inválida: {str(e)}",
            ip_spec=segmento
        )


def _expand_dash_range_segment(segmento: str, max_hosts: int) -> List[str]:
    """Expand an octet-range segment (e.g. ``192.168.1.1-10``)."""
    try:
        ips_expandidas = _expand_octal_range(segmento)
        if len(ips_expandidas) > max_hosts:
            raise MaxHostsExceededError(max_hosts=max_hosts, found=len(ips_expandidas))
        return ips_expandidas
    except (ValueError, OSError) as e:
        raise IPValidationError(
            message=f"Error al procesar rango: {str(e)}",
            ip_spec=segmento
        )


def _expand_single_ip_segment(segmento: str) -> List[str]:
    """Validate a single literal IP segment."""
    try:
        ip = ipaddress.ip_address(segmento)
        return [str(ip)]
    except ValueError:
        raise IPValidationError(
            message="Dirección IP inválida",
            ip_spec=segmento
        )


def _reject_private_ips(lista_ips: List[str]) -> None:
    """Raise if any IP is private and local IPs aren't allowed by config."""
    if not CR.themis_config().are_local_ips_allowed:
        private_ips = [
            ip for ip in lista_ips
            if ipaddress.ip_address(ip).is_private
        ]
        if private_ips:
            raise PrivateIPRequested(private_ips)


def _resolved_addresses(target: str) -> List[str]:
    """Las direcciones IP a las que apunta ``target``.

    Si ya es una IP, se devuelve tal cual. Si es un nombre, **se resuelve**, y
    esa resolución es parte de la defensa y no una comodidad: sin ella, un
    nombre que apunta a 127.0.0.1 o a 169.254.169.254 atraviesa el guardia
    anti-SSRF sin que nadie lo mire. Comprobar sólo lo que *parece* una IP deja
    la puerta abierta al caso más fácil de explotar.

    Se comprueban **todas** las direcciones devueltas, no la primera: un nombre
    con varios registros basta con que tenga uno privado para ser peligroso.

    Args:
        target: Una IP o un nombre de host.

    Returns:
        Las direcciones a comprobar.

    Raises:
        IPValidationError: Si el nombre no resuelve.
    """
    try:
        return [str(ipaddress.ip_address(target))]
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(target, None)
    except OSError as exc:
        raise IPValidationError(
            message=f"No se pudo resolver el objetivo '{target}'",
            ip_spec=target,
        ) from exc
    return sorted({info[4][0] for info in infos})


def reject_private_ip(target: str) -> None:
    """Rechaza un objetivo que apunte a una IP privada o de loopback.

    Punto de entrada de objetivo único, para los llamantes que no expanden una
    especificación CIDR/rango con ``validate_ip``: Nikto, y el arranque directo
    de un escaneo Lybra (autodescubrimiento) que no pasa por el endpoint HTTP.

    Acepta un nombre además de una IP, y lo resuelve antes de decidir (ver
    :func:`_resolved_addresses`). Antes no lo hacía y explotaba con un
    ``ValueError`` sin capturar en cuanto le llegaba un nombre — un fallo que
    estuvo tapado mientras ``areLocalIpsAllowed`` estuvo en ``true``, porque ese
    flag cortocircuita la comprobación entera antes de mirar el valor.

    Lo que esto **no** resuelve es el desfase entre comprobar y escanear: entre
    la resolución de aquí y la conexión real, el nombre puede cambiar de
    dirección (DNS rebinding). Cerrar eso exige fijar la IP resuelta y escanear
    esa, no el nombre, y es un cambio de mayor alcance.
    """
    _reject_private_ips(_resolved_addresses(target))


def validate_ip(ips_str: str, max_hosts: int = 10) -> List[str]:
    """
    Valida y expande una especificación de IPs/rangos.

    Formatos soportados:
    - IP individual: "192.168.1.1"
    - CIDR: "192.168.1.0/24"
    - Rangos por octeto: "192.168.1.1-10" o "192.168.1-2.1-10"
    - Lista separada por comas: "192.168.1.1,192.168.1.5"
    - Wildcards: "192.168.1.*" (equivalente a 192.168.1.0-255)

    Raises:
        IPValidationError: Si el formato es inválido.
        MaxHostsExceededError: Si se excede max_hosts.

    Returns:
        Lista de IPs expandidas (sin duplicados).
    """
    ips_str = _require_non_empty(ips_str, IPValidationError)

    segmentos = [ip_string.strip() for ip_string in ips_str.split(",")]
    lista_ips = []
    for segmento in segmentos:
        if not segmento:
            raise IPValidationError(
                message="Segmento vacío encontrado",
                ip_spec=ips_str
            )

        if "/" in segmento:
            lista_ips.extend(_expand_cidr_segment(segmento, max_hosts))
        elif "-" in segmento:
            lista_ips.extend(_expand_dash_range_segment(segmento, max_hosts))
        else:
            lista_ips.extend(_expand_single_ip_segment(segmento))

    if not lista_ips:
        raise IPValidationError(
            message="No se generaron IPs válidas",
            ip_spec=ips_str
        )

    _reject_private_ips(lista_ips)

    return list(dict.fromkeys(lista_ips))


# =============================================================================
# Puertos
# =============================================================================

def _parse_port_range_token(segmento: str, ports_str: str) -> tuple[int, int]:
    """Parse a single port-range token (``-N``, ``N-`` or ``N-M``) into ``(inicio, fin)``."""
    partes = segmento.split("-")

    if segmento.startswith("-"):
        if len(partes) != 2 or partes[0] != "":
            raise PortValidationError(
                message=f"Formato de rango incorrecto: '{segmento}'",
                port_spec=ports_str
            )
        try:
            fin = int(partes[1])
        except ValueError:
            raise PortValidationError(
                message=f"Puerto de fin no válido en rango: '{segmento}'",
                port_spec=ports_str
            )
        if fin < 1 or fin > 65535:
            raise PortValidationError(
                message=f"Puerto de fin fuera de rango (1-65535): {fin}",
                port_spec=ports_str
            )
        return 1, fin

    if segmento.endswith("-"):
        if len(partes) != 2 or partes[1] != "":
            raise PortValidationError(
                message=f"Formato de rango incorrecto: '{segmento}'",
                port_spec=ports_str
            )
        try:
            inicio = int(partes[0])
        except ValueError:
            raise PortValidationError(
                message=f"Puerto de inicio no válido en rango: '{segmento}'",
                port_spec=ports_str
            )
        if inicio < 1 or inicio > 65535:
            raise PortValidationError(
                message=f"Puerto de inicio fuera de rango (1-65535): {inicio}",
                port_spec=ports_str
            )
        return inicio, 65535

    if len(partes) != 2:
        raise PortValidationError(
            message=f"Formato de rango incorrecto (demasiados guiones): '{segmento}'",
            port_spec=ports_str
        )
    try:
        inicio = int(partes[0])
        fin = int(partes[1])
    except ValueError:
        raise PortValidationError(
            message=f"Puertos no numéricos en rango: '{segmento}'",
            port_spec=ports_str
        )
    if inicio < 1 or inicio > 65535:
        raise PortValidationError(
            message=f"Puerto de inicio fuera de rango (1-65535): {inicio}",
            port_spec=ports_str
        )
    if fin < 1 or fin > 65535:
        raise PortValidationError(
            message=f"Puerto de fin fuera de rango (1-65535): {fin}",
            port_spec=ports_str
        )
    if inicio >= fin:
        raise PortValidationError(
            message=f"Rango inválido: el inicio ({inicio}) debe ser menor que el fin ({fin})",
            port_spec=ports_str
        )
    return inicio, fin


def _parse_port_token(segmento: str, ports_str: str) -> int:
    """Parse a single literal port token."""
    try:
        puerto = int(segmento)
    except ValueError:
        raise PortValidationError(
            message=f"Puerto no numérico: '{segmento}'",
            port_spec=ports_str
        )
    if puerto < 1 or puerto > 65535:
        raise PortValidationError(
            message=f"Puerto fuera de rango (1-65535): {puerto}",
            port_spec=ports_str
        )
    return puerto


def validate_port(ports_str: str) -> List[int]:
    """
    Valida y expande una especificación de puertos.

    Reglas de validación:
    - Puertos en rango 1-65535
    - Puertos y rangos en orden ascendente
    - Rangos válidos (inicio < fin)
    - No solapamiento de rangos
    - Formato: "80", "80,443", "1-1000", "80,443-8080,9000"

    Raises:
        PortValidationError: Si el formato es inválido.

    Returns:
        Lista de puertos expandida (sin duplicados, ordenada).
    """
    ports_str = _require_non_empty(ports_str, PortValidationError)

    segmentos = ports_str.split(",")
    ultimo_puerto = 0
    lista_puertos: List[int] = []

    for i, segmento in enumerate(segmentos):
        segmento = segmento.strip()

        if not segmento:
            raise PortValidationError(
                message=f"Segmento vacío encontrado en la posición {i + 1}",
                port_spec=ports_str
            )

        if "-" in segmento:
            inicio, fin = _parse_port_range_token(segmento, ports_str)

            if inicio <= ultimo_puerto:
                raise PortValidationError(
                    message=f"Los puertos no están en orden ascendente: {inicio} aparece después de {ultimo_puerto}",
                    port_spec=ports_str
                )

            lista_puertos.extend(range(inicio, fin + 1))
            ultimo_puerto = fin

        else:
            puerto = _parse_port_token(segmento, ports_str)

            if puerto <= ultimo_puerto:
                raise PortValidationError(
                    message=f"Los puertos no están en orden ascendente: {puerto} aparece después de {ultimo_puerto}",
                    port_spec=ports_str
                )
            lista_puertos.append(puerto)
            ultimo_puerto = puerto

    return list(dict.fromkeys(lista_puertos))
