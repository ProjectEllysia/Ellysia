"""Banco de concordancia no-HTTP: qué identifica Lybra frente a lo que identifica Nmap.

El roadmap dice, sobre la Fase N, que *«medir la concordancia de fingerprint
sólo sobre HTTP/SSH/TLS dejaría de ser representativo justo cuando la
superficie se amplía»*. Y eso era exactamente lo que pasaba: los ocho
dissectors que la Fase N añadió —FTP, SMTP, IMAP, POP3, SMB, MySQL, Redis, VNC
y SNMP— no tenían ni un objetivo real contra el que medirse. Su única cobertura
eran tests unitarios con sockets falsos, que verifican que el parser hace lo que
su autor creía, no que reciba lo que un servidor de verdad emite. El criterio de
cierre de la Fase N pide concordancia ≥ 0,90 en cuatro protocolos no-HTTP; ese
número no existía, ni bueno ni malo.

Este módulo lo produce. Levanta un contenedor por protocolo, deja que el
dissector real lo interrogue, y compara su lectura con la de ``nmap -sV`` sobre
el mismo servidor.

## Medir contra Nmap no es depender de Nmap

Conviene decirlo porque la Fase 1 se abrió retirando justo lo contrario (L52):
el motor ya no lanza otros escáneres, no arranca desde ellos, y su lectura
propia no está subordinada a ninguno. Nada de eso está aquí en cuestión. Nmap
aparece en ``tests/``, nunca en el producto, y sólo como **regla graduada**: la
independencia se demuestra midiéndose contra el mejor del mercado y empatando o
ganando, no negándose a la comparación.

## El oráculo también es un contenedor

El banco anterior —borrado en julio de 2026 junto al script manual del que
dependía— exigía un ``nmap`` instalado en la máquina y se saltaba entero si
faltaba. En la práctica eso significaba saltarse casi siempre. Aquí Nmap se
ejecuta en un contenedor (ver ``_nmap_oracle.py``), así que basta con lo que el
resto de ``tests/oracle/`` ya necesita: Docker.

## Lo que este banco encontró

Tres protocolos concuerdan (FTP, Redis, VNC) y cuatro no (SMTP, MySQL, SMB,
SNMP). Los cuatro fallos están documentados uno a uno más abajo con
``xfail(strict=True)``: son defectos reales, no ruido, y cuando cada uno se
arregle su test pasará a XPASS y habrá que quitarle el marcador — la convención
del repositorio para un bug documentado.

Requiere Docker. Marcado ``oracle``, fuera del run por defecto de CI (#280).
"""

from __future__ import annotations

import socket
import subprocess
import time
from dataclasses import dataclass
from typing import Optional, Tuple

import pytest

from src.modules.features.themis.lybra import (
    HostRateLimiter,
    Service,
    default_dissectors,
)

from ._concordance import agrees_with_nmap, concordance_rate
from ._docker_helpers import resolve_docker, docker_rm, port_is_free, wait_for_port
from ._nmap_oracle import run_nmap_sv

pytestmark = [pytest.mark.oracle, pytest.mark.integration]

_DOCKER = resolve_docker()
pytestmark.append(pytest.mark.skipif(_DOCKER is None, reason="Docker no disponible"))

_HOST = "127.0.0.1"

# Rango propio, separado del que usa ``test_lybra_oracle_bench.py``, para que
# los dos módulos puedan correr en la misma máquina sin pelearse por un puerto.
#
# Ninguno es el puerto canónico del protocolo, y eso es deliberado: el 445 lo
# tiene tomado el propio Windows, y el 3306 o el 6379 los tiene cualquier
# entorno de desarrollo con una base de datos levantada. Como el nombre del
# servicio se pasa explícitamente al construir el ``Service`` —que es lo que el
# mapa de puertos conocidos haría en producción— el número de puerto no cambia
# qué dissector se elige ni qué lee.
_PORTS = {
    "ftp": 12121, "smtp": 12525, "mysql": 13306, "smb": 14445,
    "vnc": 15900, "snmp": 16161, "redis": 16379,
}


@dataclass(frozen=True)
class Target:
    """Un objetivo del catálogo, ya levantado y listo para interrogar."""
    protocol: str
    port: int
    service_name: str
    transport: str = "tcp"


def _docker(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([_DOCKER, *args], capture_output=True, text=True, timeout=120, check=True)


def _wait_for_greeting(port: int, expect: bytes, timeout: float = 240.0) -> None:
    """Esperar a que el servidor emita **su** saludo, no a que el puerto acepte.

    Es la lección que dejó #265 en la Fase 0 y aquí vuelve a hacer falta: el
    proxy de Docker acepta la conexión TCP en cuanto existe el espacio de red
    del contenedor, mucho antes de que el servidor de dentro haya terminado de
    instalarse y arrancar. Un ``wait_for_port`` que sólo conecta da por listo un
    contenedor que todavía está haciendo ``apk add``, y la medición sale vacía
    sin que nada parezca haber fallado.
    """
    deadline = time.monotonic() + timeout
    last = "sin intentos"
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((_HOST, port), timeout=3.0) as sock:
                sock.settimeout(3.0)
                banner = sock.recv(64)
            if banner.startswith(expect):
                return
            last = f"saludo inesperado: {banner!r}"
        except OSError as exc:
            last = str(exc)
        time.sleep(1.0)
    raise TimeoutError(f"{_HOST}:{port} no emitió {expect!r} en {timeout}s ({last})")


def _start(name: str, port: int, inner: int, image: str, *command: str,
           udp: bool = False, env: Tuple[str, ...] = ()) -> None:
    # Primero se retira un contenedor nuestro que hubiera quedado vivo de una
    # ejecución anterior, y sólo después se mira si el puerto está libre. Al
    # revés, un contenedor huérfano del propio banco haría que el objetivo se
    # saltara en silencio — que es exactamente lo que le pasó a Redis la
    # primera vez que se corrió esto.
    docker_rm(_DOCKER, name)
    if not port_is_free(_HOST, port):
        pytest.skip(f"Puerto {port} ocupado por algo ajeno al banco; se necesita libre")
    publish = f"{port}:{inner}/udp" if udp else f"{port}:{inner}"
    arguments = ["run", "-d", "--name", name, "-p", publish]
    for variable in env:
        arguments += ["-e", variable]
    _docker(*arguments, image, *command)


# ================================================================== catálogo

@pytest.fixture(scope="module")
def ftp_target():
    """vsftpd, que anuncia producto y versión en su saludo — el caso fácil."""
    port, name = _PORTS["ftp"], "lybra-concordance-ftp"
    _start(name, port, 21, "alpine:latest", "sh", "-c",
           "apk add --no-cache vsftpd >/dev/null 2>&1 && "
           "mkdir -p /var/lib/ftp && chmod 555 /var/lib/ftp && "
           "printf '%s\\n' 'listen=YES' 'listen_ipv6=NO' 'anonymous_enable=YES' "
           "'local_enable=NO' 'no_anon_password=NO' 'seccomp_sandbox=NO' "
           "'anon_root=/var/lib/ftp' > /etc/vsftpd/vsftpd.conf && "
           "vsftpd /etc/vsftpd/vsftpd.conf")
    try:
        _wait_for_greeting(port, b"220")
        yield Target("ftp", port, "ftp")
    finally:
        docker_rm(_DOCKER, name)


@pytest.fixture(scope="module")
def smtp_target():
    """Postfix, que da producto pero **no** versión: el caso que el roadmap
    llama "no inventar CPE". Nmap sí extrae el producto de ese mismo saludo."""
    port, name = _PORTS["smtp"], "lybra-concordance-smtp"
    _start(name, port, 25, "alpine:latest", "sh", "-c",
           "apk add --no-cache postfix >/dev/null 2>&1 && "
           "postconf -e 'inet_interfaces=all' 'mynetworks=0.0.0.0/0' "
           "'smtpd_client_restrictions=' && newaliases; postfix start-fg")
    try:
        _wait_for_greeting(port, b"220")
        yield Target("smtp", port, "smtp")
    finally:
        docker_rm(_DOCKER, name)


@pytest.fixture(scope="module")
def mysql_target():
    """MariaDB, que habla el protocolo de MySQL pero no es MySQL. El caso que
    obliga a distinguir el protocolo del producto."""
    port, name = _PORTS["mysql"], "lybra-concordance-mysql"
    _start(name, port, 3306, "mariadb:11", env=("MARIADB_ROOT_PASSWORD=bench",))
    try:
        wait_for_port(_HOST, port, 240)
        # MariaDB no saluda hasta que ha terminado de inicializar el datadir, y
        # su saludo es binario: no hay prefijo estable que esperar, así que aquí
        # sí toca dar tiempo en vez de esperar una cadena.
        time.sleep(20)
        yield Target("mysql", port, "mysql")
    finally:
        docker_rm(_DOCKER, name)


@pytest.fixture(scope="module")
def smb_target():
    """Samba: el objetivo que faltaba. El dissector de SMB era el único que
    negocia en vez de leer, y hasta ahora su corrección era una afirmación —
    se ejercitaba sólo contra un fixture de bytes escrito a mano por quien
    escribió el parser."""
    port, name = _PORTS["smb"], "lybra-concordance-smb"
    _start(name, port, 445, "dperson/samba", "-p", "-s", "public;/tmp;yes;no;yes")
    try:
        wait_for_port(_HOST, port, 240)
        time.sleep(10)
        yield Target("smb", port, "microsoft-ds")
    finally:
        docker_rm(_DOCKER, name)


@pytest.fixture(scope="module")
def redis_target():
    port, name = _PORTS["redis"], "lybra-concordance-redis"
    _start(name, port, 6379, "redis:7")
    try:
        wait_for_port(_HOST, port, 240)
        time.sleep(3)
        yield Target("redis", port, "redis")
    finally:
        docker_rm(_DOCKER, name)


@pytest.fixture(scope="module")
def vnc_target():
    """x11vnc sobre un Xvfb. El paréntesis alrededor del ``&`` no es adorno:
    en ``sh``, ``A && B & C && D`` se parte por el ``&`` y arrancaría x11vnc
    antes de que exista el display."""
    port, name = _PORTS["vnc"], "lybra-concordance-vnc"
    _start(name, port, 5900, "alpine:latest", "sh", "-c",
           "apk add --no-cache x11vnc xvfb >/dev/null 2>&1 && "
           "(Xvfb :1 -screen 0 800x600x16 &) && sleep 3 && "
           "x11vnc -display :1 -nopw -forever -rfbport 5900")
    try:
        _wait_for_greeting(port, b"RFB")
        yield Target("vnc", port, "vnc")
    finally:
        docker_rm(_DOCKER, name)


@pytest.fixture(scope="module")
def snmp_target():
    """net-snmp sobre UDP — el único protocolo del catálogo que no es TCP."""
    port, name = _PORTS["snmp"], "lybra-concordance-snmp"
    _start(name, port, 161, "polinux/snmpd", udp=True)
    try:
        time.sleep(10)
        yield Target("snmp", port, "snmp", transport="udp")
    finally:
        docker_rm(_DOCKER, name)


# ================================================================== medición

def _own_reading(target: Target) -> Tuple[Optional[str], Optional[str]]:
    """Lo que lee Lybra: el registro de dissectors real, sin atajos.

    El ``Service`` se construye con el nombre que el mapa de puertos conocidos
    le habría puesto en producción; a partir de ahí, la selección del dissector
    y la sonda son exactamente las de un escaneo de verdad.
    """
    service = Service(port=target.port, protocol=target.transport, name=target.service_name)
    dissector = next((candidate for candidate in default_dissectors() if candidate.applies(service)), None)
    assert dissector is not None, f"Ningún dissector aplica a {target.service_name}"
    result = dissector.probe(_HOST, service, HostRateLimiter())
    return (result.product, result.version) if result else (None, None)


def _pair(target: Target) -> Tuple:
    """El par ``(propio, propio_version, nmap, nmap_version)`` de un objetivo."""
    product, version = _own_reading(target)
    nmap = run_nmap_sv(_DOCKER, [target.port], protocol=target.transport).get(target.port)
    return (product, version,
            nmap.product if nmap else None,
            nmap.version if nmap else None)


def _assert_agrees(target: Target) -> None:
    pair = _pair(target)
    assert agrees_with_nmap(*pair), f"{target.protocol}: propio vs nmap = {pair}"


# ============================================== los que concuerdan hoy

def test_ftp_fingerprint_agrees_with_nmap(ftp_target):
    _assert_agrees(ftp_target)


def test_redis_fingerprint_agrees_with_nmap(redis_target):
    _assert_agrees(redis_target)


def test_vnc_fingerprint_agrees_with_nmap(vnc_target):
    """Lybra lee ``VNC (RFB) 3.8``, Nmap lee ``VNC`` sin versión. Cuenta como
    acuerdo: la comparación sólo exige coincidir en versión cuando ambos lados
    la dan, y aquí es Nmap quien no la tiene."""
    _assert_agrees(vnc_target)


# ================================== los que no, cada uno con su motivo

@pytest.mark.xfail(strict=True, reason=(
    "El dissector SMTP sólo extrae producto cuando el saludo trae también "
    "versión, porque su expresión regular exige las dos cosas. Postfix anuncia "
    "'220 host ESMTP Postfix' sin versión a propósito, así que Lybra se queda "
    "sin producto — mientras que Nmap sí lee 'Postfix smtpd'. No es abstenerse "
    "de inventar una versión, que sería correcto: es perder un producto que "
    "estaba escrito en el saludo."
))
def test_smtp_fingerprint_agrees_with_nmap(smtp_target):
    _assert_agrees(smtp_target)


@pytest.mark.xfail(strict=True, reason=(
    "MariaDB habla el protocolo de MySQL, y el dissector confunde el protocolo "
    "con el producto: informa 'MySQL' cuando el servidor es MariaDB, y arrastra "
    "el sufijo de distribución en la versión ('11.8.9-MariaDB-ubu2404' frente al "
    "'11.8.9' de Nmap). Un CPE construido con eso apunta al producto equivocado."
))
def test_mysql_fingerprint_agrees_with_nmap(mysql_target):
    _assert_agrees(mysql_target)


@pytest.mark.xfail(strict=True, reason=(
    "El dissector SMB sí habla con un Samba real —negocia y lee el dialecto "
    "3.0.2 y el modo de seguridad—, pero lo que devuelve como 'producto' es una "
    "descripción del protocolo en castellano ('SMB2 (firma no requerida)') y "
    "como 'versión' el dialecto negociado. Nmap devuelve 'Samba smbd 4', que es "
    "el producto y su versión. No son comparables porque no responden a la "
    "misma pregunta."
))
def test_smb_fingerprint_agrees_with_nmap(smb_target):
    _assert_agrees(smb_target)


@pytest.mark.xfail(strict=True, reason=(
    "El dissector SNMP devuelve el 'sysDescr' entero como producto — en Linux, "
    "la línea de 'uname -a' completa. Es información legítima y útil, pero no "
    "es un nombre de producto, así que no puede coincidir con el 'net-snmp' que "
    "identifica Nmap ni servir para resolver un CPE."
))
def test_snmp_fingerprint_agrees_with_nmap(snmp_target):
    _assert_agrees(snmp_target)


# ============================================================== el número

@pytest.mark.xfail(strict=True, reason=(
    "La concordancia no-HTTP medida hoy sobre los siete protocolos del catálogo "
    "es 3/7 = 0,43, muy por debajo del 0,90 que pide el criterio de cierre de la "
    "Fase N. Los cuatro fallos están documentados uno a uno arriba. Este test es "
    "el número agregado: pasará a XPASS cuando se cierre el último hueco, y "
    "entonces habrá que quitarle el marcador."
))
def test_non_http_concordance_reaches_the_phase_n_threshold(
    ftp_target, smtp_target, mysql_target, smb_target, redis_target, vnc_target, snmp_target,
):
    """El número que la Fase N pide y que hasta ahora no existía.

    No mide si los dissectors son *útiles* —el de SNMP lo es, y el de SMB
    también— sino si su lectura es comparable con la de la herramienta de
    referencia. Un producto que no se puede comparar tampoco se puede convertir
    en CPE, y sin CPE no hay detección por versión.
    """
    targets = [ftp_target, smtp_target, mysql_target, smb_target,
               redis_target, vnc_target, snmp_target]
    pairs = [_pair(target) for target in targets]
    rate = concordance_rate(pairs)
    detail = list(zip((target.protocol for target in targets), pairs))
    assert rate >= 0.90, f"concordancia no-HTTP {rate:.2f} — detalle: {detail}"
