"""Comprobación de alcanzabilidad de red (A1: extraído de ScanManager).

Funciones puras sin estado ni acceso a BD — no tenían nada que ver con un
manager de persistencia; estaban ahí solo porque `ScanManager` era la clase
base común a todos los escaneos y "cabía".
"""

import socket
import subprocess


def is_host_reachable(host: str, port: int = 80, timeout: float = 3.0) -> bool:
    """
    Verifica conectividad básica con un host sin dependencias externas.

    Primero intenta TCP con ``socket.create_connection`` (maneja resolución
    DNS automáticamente). Si el host responde con ``ConnectionRefusedError``
    se considera alcanzable (el puerto está cerrado pero el host está vivo
    y responde).

    Si el puerto TCP no responde (timeout/sin ruta), se hace un fallback a
    ``ping`` (ICMP echo): un host con firewall que descarta silenciosamente
    los paquetes a puertos cerrados (p. ej. Windows Firewall por defecto)
    daría un falso "inalcanzable" con solo el chequeo TCP, aunque nmap
    encontraría puertos abiertos en otros rangos.

    Args:
        host:    Dirección IP o hostname a comprobar.
        port:    Puerto TCP de destino (default: 80).
        timeout: Tiempo máximo de espera en segundos (default: 3.0).

    Returns:
        ``True`` si el host responde (TCP aceptado/rechazado o ping ICMP).
        ``False`` si no hay respuesta por ninguna vía.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except ConnectionRefusedError:
        return True
    except (socket.timeout, OSError):
        pass

    return _ping_host(host, timeout)


def _ping_host(host: str, timeout: float) -> bool:
    """Fallback ICMP echo (``ping -c 1``) cuando el puerto TCP no responde."""
    deadline = max(1, int(round(timeout)))
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(deadline), host],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=deadline + 1,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False
