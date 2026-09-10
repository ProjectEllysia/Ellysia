"""The SMB dissector — the highest-value protocol by port frequency.

Sends a minimal SMB2 NEGOTIATE request and reads the response's negotiated
dialect and security mode — the wire format is fixed and publicly documented
(MS-SMB2 §2.2.3 "SMB2 NEGOTIATE Request", §2.2.4 "SMB2 NEGOTIATE Response"),
so this is a byte-offset parser in the same spirit as the SSH dissector's raw
``SSH_MSG_KEXINIT`` parsing — no SMB client library involved.

Deliberate simplifications, both documented rather than discovered by
surprise:

- Only SMB2 dialects are offered (``0x0202``/``0x0210``/``0x0300``/``0x0302``),
  never ``0x0311`` (SMB 3.1.1). Offering 3.1.1 requires the request to also
  carry SMB2 "negotiate contexts" (preauth integrity + encryption
  capabilities) — a second layer of variable-length, offset-addressed
  structure this dissector does not build. Consequence: a modern
  Windows/Samba server that would negotiate 3.1.1 instead reports the
  highest dialect actually offered here, 3.0.2 — still correct and useful
  identification, just not the exact ceiling the server supports.
- SMB1 is not spoken at all: a server that has SMB1 fully disabled (the
  now-common hardened configuration) and does not also answer a direct SMB2
  negotiate simply yields no identification here, same as any other
  unrecognised response.

**Verificado contra un Samba real** (banco de concordancia): el
negociado funciona —el dissector habla con un ``dperson/samba`` de verdad y
lee dialecto ``3.0.2`` y modo de seguridad, exactamente lo que los offsets
predecían—, así que el parser deja de ser una afirmación apoyada sólo en un
fixture escrito a mano por quien lo escribió.

Lo que esa verificación sí destapó es otra cosa: **lo que este dissector
devuelve como ``product`` no es un producto**. Es una descripción del
protocolo en castellano (``"SMB2 (firma no requerida)"``) y, como ``version``,
el dialecto negociado. Nmap, sobre el mismo servidor, devuelve ``Samba smbd``
y ``4``. Las dos lecturas son correctas y ninguna contradice a la otra, pero
responden a preguntas distintas, y la de aquí no sirve para resolver un CPE
—que es lo que la detección por versión necesita—. Está medido y documentado
en ``tests/oracle/test_lybra_concordance_bench.py``.

**Dos intercambios más, y por qué**. El NEGOTIATE de arriba dice qué
dialecto habla el servidor y si exige firma, y eso era todo. Faltaban tres
datos que el propio protocolo ofrece sin autenticar:

- **SMBv1 habilitado**, el hallazgo clásico del protocolo —el que WannaCry
  convirtió en historia— y que el NEGOTIATE de SMB2 **no puede ver**: son dos
  protocolos distintos con dos saludos distintos, así que un servidor con
  SMB1 activo contesta igual al SMB2 y no dice ni una palabra sobre el otro.
  Hace falta preguntar en SMB1, con su propia sonda
  (:func:`build_smb1_negotiate`).
- **Nombre de equipo y dominio**, que llegan en el ``SESSION_SETUP`` y son el
  mejor identificador de activo que existe en una red Windows. Un informe que
  dice ``10.0.0.37`` y otro que dice ``WIN-SRV01 (CORP)`` cuestan lo mismo y
  no valen lo mismo.
- **Versión del sistema**, cuando el servidor la ofrece en su respuesta NTLM.

Los tres salen de mensajes que se mandan **sin credenciales** y que no llegan
a establecer sesión: el ``SESSION_SETUP`` se corta en el primer paso de la
negociación NTLM, justo cuando el servidor ya ha dicho quién es y todavía no
ha pedido nada. No se prueba ninguna contraseña.

**Una simplificación deliberada del ``SESSION_SETUP``.** El token de seguridad
se manda como NTLMSSP crudo y no envuelto en SPNEGO, que es lo que la
especificación describe. En la práctica lo aceptan tanto Windows como Samba;
un servidor que exija el envoltorio no contestará nada reconocible, y el
resultado será que este intercambio no aporta identidad — nunca una
identidad equivocada. El **lector**, en cambio, es tolerante a las dos formas:
busca la firma ``NTLMSSP`` dentro de la respuesta en vez de fiarse de un
desplazamiento fijo, así que da igual cómo venga envuelta.
"""

from __future__ import annotations

import logging
import socket
import struct
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from ..checks import is_smb_service
from .dispatch import Dissector, DissectorResult
from .registry import register_dissector

logger = logging.getLogger(__name__)

# SMB2 dialect revisions this dissector offers, and their human labels — see
# the module docstring for why 0x0311 (SMB 3.1.1) is deliberately excluded.
_DIALECTS: Tuple[int, ...] = (0x0202, 0x0210, 0x0300, 0x0302)
_DIALECT_LABELS = {
    0x0202: "2.0.2",
    0x0210: "2.1",
    0x0300: "3.0",
    0x0302: "3.0.2",
    0x0311: "3.1.1",
}

# SMB2_NEGOTIATE_SIGNING_REQUIRED (MS-SMB2 §2.2.4, SecurityMode bit 0x0002).
#
# Público a propósito: es el hecho de seguridad que el servidor declara sobre
# sí mismo, y quien tenga que decidir sobre él —el fingerprint de aquí abajo,
# el plugin `smb-signing-not-required` de ``script_checks``— debe leer este
# bit y no la etiqueta legible que se deriva de él. Una etiqueta es prosa para
# humanos; convertirla en el protocolo entre dos piezas de código hace que
# retocar el texto apague un check en silencio.
SIGNING_REQUIRED_BIT = 0x0002

_SMB2_HEADER_LEN = 64
_PROTOCOL_ID = b"\xfeSMB"

# La cabecera de SMB1 empieza por 0xFF en vez de 0xFE — un solo bit de
# diferencia entre los dos protocolos, y toda una década de vulnerabilidades.
_SMB1_PROTOCOL_ID = b"\xffSMB"
_SMB1_COMMAND_NEGOTIATE = 0x72
_SMB1_HEADER_LEN = 32

# El dialecto de SMB1 que pide cualquier cliente moderno que aún lo hable. Si
# el servidor lo acepta, SMB1 está habilitado; no hay más que interpretar.
SMB1_DIALECT = b"NT LM 0.12"

# SMB2 SESSION_SETUP (MS-SMB2 §2.2.5). El cuerpo fijo mide 24 bytes, así que
# el token de seguridad empieza en 64 + 24 = 88.
_SMB2_COMMAND_SESSION_SETUP = 0x0001
_SESSION_SETUP_BODY_LEN = 24
_SECURITY_BUFFER_OFFSET = _SMB2_HEADER_LEN + _SESSION_SETUP_BODY_LEN

# NTLM (MS-NLMP). Sólo se construye el mensaje de tipo 1 (NEGOTIATE) y se lee
# el de tipo 2 (CHALLENGE): el 3 sería la autenticación, y aquí no se
# autentica nadie.
NTLM_SIGNATURE = b"NTLMSSP\x00"
NTLM_NEGOTIATE = 0x00000001
NTLM_CHALLENGE = 0x00000002

# Las banderas que hacen falta para que el servidor conteste con su bloque de
# información de destino, que es donde vienen el nombre de equipo y el
# dominio. NEGOTIATE_VERSION es la que pide además su versión de sistema.
_NTLM_NEGOTIATE_UNICODE = 0x00000001
_NTLM_REQUEST_TARGET = 0x00000004
_NTLM_NEGOTIATE_NTLM = 0x00000200
_NTLM_NEGOTIATE_EXTENDED_SECURITY = 0x00080000
_NTLM_NEGOTIATE_VERSION = 0x02000000
_NTLM_FLAGS = (
    _NTLM_NEGOTIATE_UNICODE
    | _NTLM_REQUEST_TARGET
    | _NTLM_NEGOTIATE_NTLM
    | _NTLM_NEGOTIATE_EXTENDED_SECURITY
    | _NTLM_NEGOTIATE_VERSION
)

# Identificadores del bloque AV_PAIR de la respuesta NTLM (MS-NLMP §2.2.2.1).
# Cada uno es una cadena en UTF-16LE.
AV_PAIR_NAMES: Dict[int, str] = {
    1: "netbios_computer_name",
    2: "netbios_domain_name",
    3: "dns_computer_name",
    4: "dns_domain_name",
    5: "dns_tree_name",
}
_AV_PAIR_EOL = 0


@dataclass(frozen=True)
class SmbFingerprint:  # pylint: disable=too-many-instance-attributes
    """The result of fingerprinting an SMB service.

    Es un objeto de valor: cada atributo es un dato distinto que el servidor
    declaró en uno de los tres intercambios, y agruparlos en sub-objetos sólo
    añadiría un nivel de acceso sin quitar ninguno.

    Attributes:
        product: ``"SMB2"``, or ``"SMB2 (firma no requerida)"`` when the
            server's negotiated security mode does not require message
            signing — a real, directly-observed configuration fact (not a
            guess), folded into the product string since it is the single
            most actionable thing this dissector can report. ``None`` if the
            response was not recognisable.
        version: The negotiated dialect's label, e.g. ``"3.0.2"``.
        confidence: A 0.0-1.0 self-assessed confidence in the identification.
        hostname: El nombre NetBIOS del equipo, leído del ``SESSION_SETUP``.
            Es el mejor identificador de activo que existe en una red Windows:
            un informe que dice ``10.0.0.37`` y otro que dice ``WIN-SRV01``
            cuestan lo mismo y no valen lo mismo.
        domain: El dominio NetBIOS al que pertenece.
        dns_name: El nombre DNS completo del equipo, cuando el servidor lo da.
        os_version: La versión de sistema que el servidor declara en su
            respuesta NTLM (``"10.0.19041"``), o ``None``. Se reporta como
            hecho observado y **no** se convierte en producto: Samba rellena
            ese campo emulando una versión de Windows, así que deducir el
            fabricante de ahí sería inventarlo.
        speaks_smb1: ``True`` si el servidor aceptó una negociación de SMB1,
            ``False`` si la rechazó, ``None`` si no se llegó a preguntar.
    """
    product: Optional[str]
    version: Optional[str]
    confidence: float
    hostname: Optional[str] = None
    domain: Optional[str] = None
    dns_name: Optional[str] = None
    os_version: Optional[str] = None
    speaks_smb1: Optional[bool] = None


def _smb2_header(command: int, message_id: int = 0) -> bytes:
    """Build a 64-byte SMB2 "SYNC" header (MS-SMB2 §2.2.1.1).

    Every field this dissector does not need (CreditCharge, Flags, SessionId,
    Signature...) is left at its zero default, valid for an unauthenticated
    NEGOTIATE — the very first request on a connection, which is required to
    carry ``MessageId = 0``.
    """
    return b"".join([
        _PROTOCOL_ID,                    # ProtocolId (4)
        struct.pack("<H", 64),           # StructureSize (2)
        struct.pack("<H", 0),            # CreditCharge (2)
        struct.pack("<I", 0),            # Status / ChannelSequence+Reserved (4)
        struct.pack("<H", command),      # Command (2)
        struct.pack("<H", 1),            # CreditRequest (2)
        struct.pack("<I", 0),            # Flags (4)
        struct.pack("<I", 0),            # NextCommand (4)
        struct.pack("<Q", message_id),   # MessageId (8)
        struct.pack("<I", 0),            # Reserved (4)
        struct.pack("<I", 0),            # TreeId (4)
        struct.pack("<Q", 0),            # SessionId (8)
        b"\x00" * 16,                    # Signature (16)
    ])


def build_negotiate_request() -> bytes:
    """Build a full NetBIOS-wrapped SMB2 NEGOTIATE request (MS-SMB2 §2.2.3).

    Returns:
        The wire bytes: the 4-byte NetBIOS Session Service header (RFC 1002)
        followed by the SMB2 header and NEGOTIATE request body.
    """
    body = b"".join([
        struct.pack("<H", 36),                # StructureSize (fixed part only)
        struct.pack("<H", len(_DIALECTS)),    # DialectCount
        struct.pack("<H", 0x0001),            # SecurityMode: SIGNING_ENABLED
        struct.pack("<H", 0),                 # Reserved
        struct.pack("<I", 0),                 # Capabilities
        b"\x00" * 16,                          # ClientGuid
        struct.pack("<Q", 0),                  # ClientStartTime (reserved pre-3.1.1)
    ]) + b"".join(struct.pack("<H", dialect) for dialect in _DIALECTS)

    message = _smb2_header(command=0x0000) + body
    length = len(message)
    netbios_header = bytes([0x00]) + length.to_bytes(3, "big")
    return netbios_header + message


def parse_negotiate_response(message: bytes) -> Optional[Tuple[int, int]]:
    """Parse an SMB2 NEGOTIATE response (MS-SMB2 §2.2.4).

    Args:
        message: The SMB2 message *without* its 4-byte NetBIOS wrapper (see
            :meth:`SmbProbe.fetch`).

    Returns:
        A ``(dialect_revision, security_mode)`` tuple, or ``None`` if the
        message is too short, does not carry the SMB2 protocol id, or is not
        a NEGOTIATE response.
    """
    if len(message) < _SMB2_HEADER_LEN + 6:
        return None
    if message[0:4] != _PROTOCOL_ID:
        return None
    command = struct.unpack_from("<H", message, 12)[0]
    if command != 0x0000:
        return None
    security_mode = struct.unpack_from("<H", message, _SMB2_HEADER_LEN + 2)[0]
    dialect_revision = struct.unpack_from("<H", message, _SMB2_HEADER_LEN + 4)[0]
    return dialect_revision, security_mode


# =========================================================================
# SMB1 — el otro protocolo, con su propio saludo
# =========================================================================

def build_smb1_negotiate() -> bytes:
    """Construye un ``SMB_COM_NEGOTIATE`` de SMB1 ofreciendo ``NT LM 0.12``.

    Es un intercambio **distinto**, no una variante del de SMB2: cabecera
    propia (que empieza por ``0xFF`` en vez de ``0xFE``), comando propio y
    lista de dialectos propia. Por eso el NEGOTIATE de SMB2 no puede ver si
    SMB1 está habilitado — son dos protocolos que comparten puerto y poco más.

    Returns:
        Los bytes de red: la cabecera NetBIOS de cuatro bytes seguida del
        mensaje SMB1.
    """
    header = b"".join([
        _SMB1_PROTOCOL_ID,                          # ProtocolId (4)
        bytes((_SMB1_COMMAND_NEGOTIATE,)),          # Command (1)
        struct.pack("<I", 0),                       # Status (4)
        bytes((0x18,)),                             # Flags: canonical + case-insensitive
        struct.pack("<H", 0xC853),                  # Flags2: unicode + NT status + ext. sec.
        struct.pack("<H", 0),                       # PIDHigh (2)
        b"\x00" * 8,                                # SecuritySignature (8)
        struct.pack("<H", 0),                       # Reserved (2)
        struct.pack("<H", 0),                       # TreeId (2)
        struct.pack("<H", 0xFEFF),                  # ProcessId (2)
        struct.pack("<H", 0),                       # UserId (2)
        struct.pack("<H", 0),                       # MultiplexId (2)
    ])
    # El "dialect buffer": un byte de formato (0x02) y el nombre terminado en
    # NUL, por cada dialecto ofrecido.
    dialects = bytes((0x02,)) + SMB1_DIALECT + b"\x00"
    body = bytes((0,)) + struct.pack("<H", len(dialects)) + dialects
    message = header + body
    return bytes((0x00,)) + len(message).to_bytes(3, "big") + message


def parse_smb1_negotiate_response(message: bytes) -> bool:
    """Decide si una respuesta demuestra que SMB1 está habilitado.

    Args:
        message: El mensaje SMB1 **sin** su envoltorio NetBIOS.

    Returns:
        ``True`` sólo cuando el servidor ha contestado un ``NEGOTIATE`` de SMB1
        con estado correcto **y** ha elegido un dialecto. Cualquier otra cosa
        —silencio, un error, una respuesta de SMB2— es ``False``: un servidor
        que no habla SMB1 no tiene por qué contestar de ninguna forma concreta,
        así que sólo la aceptación explícita cuenta como prueba.
    """
    if len(message) < _SMB1_HEADER_LEN + 3:
        return False
    if message[0:4] != _SMB1_PROTOCOL_ID:
        return False
    if message[4] != _SMB1_COMMAND_NEGOTIATE:
        return False
    if struct.unpack_from("<I", message, 5)[0] != 0:
        return False
    word_count = message[_SMB1_HEADER_LEN]
    if word_count == 0:
        return False
    # DialectIndex: 0xFFFF significa "ninguno de los que ofreces me vale".
    dialect_index = struct.unpack_from("<H", message, _SMB1_HEADER_LEN + 1)[0]
    return dialect_index != 0xFFFF


# =========================================================================
# SESSION_SETUP y NTLM — de dónde salen el nombre de equipo y el dominio
# =========================================================================

def build_ntlm_negotiate() -> bytes:
    """Construye el mensaje NTLM de tipo 1 (``NEGOTIATE``).

    Sólo declara qué sabe hacer el cliente y pide que el servidor conteste con
    su bloque de información de destino. **No lleva usuario ni contraseña**:
    esos irían en el mensaje de tipo 3, que este módulo nunca construye.

    Returns:
        Los cuarenta bytes del mensaje.
    """
    return b"".join([
        NTLM_SIGNATURE,
        struct.pack("<I", NTLM_NEGOTIATE),
        struct.pack("<I", _NTLM_FLAGS),
        struct.pack("<HHI", 0, 0, 0),      # DomainNameFields: vacío
        struct.pack("<HHI", 0, 0, 0),      # WorkstationFields: vacío
        b"\x00" * 8,                       # Version del cliente: irrelevante
    ])


def build_session_setup_request(token: bytes, message_id: int = 1) -> bytes:
    """Construye un ``SMB2 SESSION_SETUP`` con el token de seguridad dado.

    Ver el docstring del módulo para por qué el token va como NTLMSSP crudo y
    no envuelto en SPNEGO.

    Args:
        token: El token de seguridad (aquí, el NTLM de tipo 1).
        message_id: El identificador del mensaje. El NEGOTIATE gastó el 0.

    Returns:
        Los bytes de red, con su envoltorio NetBIOS.
    """
    body = b"".join([
        struct.pack("<H", 25),                          # StructureSize
        bytes((0,)),                                    # Flags
        bytes((0x01,)),                                 # SecurityMode: SIGNING_ENABLED
        struct.pack("<I", 0),                           # Capabilities
        struct.pack("<I", 0),                           # Channel
        struct.pack("<H", _SECURITY_BUFFER_OFFSET),     # SecurityBufferOffset
        struct.pack("<H", len(token)),                  # SecurityBufferLength
        struct.pack("<Q", 0),                           # PreviousSessionId
    ]) + token
    message = _smb2_header(command=_SMB2_COMMAND_SESSION_SETUP, message_id=message_id) + body
    return bytes((0x00,)) + len(message).to_bytes(3, "big") + message


def _parse_av_pairs(block: bytes) -> Dict[str, str]:
    """Descompone el bloque de información de destino de un NTLM ``CHALLENGE``.

    Args:
        block: Los bytes del ``TargetInfo``.

    Returns:
        Un mapa nombre → valor, con los identificadores traducidos por
        :data:`AV_PAIR_NAMES`. Los que no están en la tabla se saltan; un
        bloque truncado devuelve lo leído hasta ese punto.
    """
    pairs: Dict[str, str] = {}
    offset = 0
    while offset + 4 <= len(block):
        av_id, av_len = struct.unpack_from("<HH", block, offset)
        offset += 4
        if av_id == _AV_PAIR_EOL:
            break
        value = block[offset:offset + av_len]
        if len(value) < av_len:
            break
        offset += av_len
        name = AV_PAIR_NAMES.get(av_id)
        if name:
            pairs[name] = value.decode("utf-16-le", "ignore")
    return pairs


def parse_ntlm_challenge(data: bytes) -> Dict[str, str]:
    """Extrae la identidad del servidor de una respuesta NTLM ``CHALLENGE``.

    Busca la firma ``NTLMSSP`` **dentro** del buffer en vez de fiarse de un
    desplazamiento fijo: así da igual que el servidor conteste con el token
    crudo o envuelto en SPNEGO, y da igual cuánta cabecera SMB2 haya delante.

    Args:
        data: El mensaje SMB2 completo de la respuesta.

    Returns:
        Un mapa con lo que se haya podido leer: ``netbios_computer_name``,
        ``netbios_domain_name``, ``dns_computer_name``, ``dns_domain_name``,
        ``dns_tree_name`` y ``os_version``. Vacío si no hay ningún
        ``CHALLENGE`` legible.
    """
    start = data.find(NTLM_SIGNATURE)
    if start == -1:
        return {}
    challenge = data[start:]
    if len(challenge) < 48:
        return {}
    if struct.unpack_from("<I", challenge, 8)[0] != NTLM_CHALLENGE:
        return {}

    identity: Dict[str, str] = {}
    target_info_length, _max_length, target_info_offset = struct.unpack_from(
        "<HHI", challenge, 40)
    end = target_info_offset + target_info_length
    if target_info_length and end <= len(challenge):
        identity.update(_parse_av_pairs(challenge[target_info_offset:end]))

    # El campo Version (MS-NLMP §2.2.2.10) sólo viene si el servidor negoció
    # NEGOTIATE_VERSION. Un build de cero significa que no lo ha rellenado.
    if len(challenge) >= 56:
        major, minor, build = struct.unpack_from("<BBH", challenge, 48)
        if build:
            identity["os_version"] = f"{major}.{minor}.{build}"
    return identity


def fingerprint_smb(
    dialect_revision: int,
    security_mode: int,
    identity: Optional[Dict[str, str]] = None,
    speaks_smb1: Optional[bool] = None,
) -> SmbFingerprint:
    """Fingerprint an SMB service from its negotiated dialect and security mode.

    Args:
        dialect_revision: El dialecto que el servidor eligió.
        security_mode: Su modo de seguridad, tal cual lo devolvió.
        identity: Lo que :func:`parse_ntlm_challenge` haya conseguido leer del
            ``SESSION_SETUP``, si se llegó a hacer.
        speaks_smb1: El resultado de la sonda de SMB1, si se llegó a hacer.

    Returns:
        El :class:`SmbFingerprint`. Sin producto cuando el dialecto no se
        reconoce: una respuesta que no se entiende no es prueba de nada, y en
        particular no es prueba de que la firma no se exija.
    """
    version = _DIALECT_LABELS.get(dialect_revision)
    if version is None:
        return SmbFingerprint(product=None, version=None, confidence=0.0)
    signing_required = bool(security_mode & SIGNING_REQUIRED_BIT)
    product = "SMB2" if signing_required else "SMB2 (firma no requerida)"
    identity = identity or {}
    return SmbFingerprint(
        product=product,
        version=version,
        confidence=0.9,
        hostname=identity.get("netbios_computer_name"),
        domain=identity.get("netbios_domain_name"),
        dns_name=identity.get("dns_computer_name"),
        os_version=identity.get("os_version"),
        speaks_smb1=speaks_smb1,
    )


# =========================================================================
# PROBE (the network edge: raw socket, no SMB client library)
# =========================================================================

def _read_exact(sock, n: int) -> bytes:
    """Read up to ``n`` bytes, returning fewer if the connection closes early."""
    buffer = b""
    while len(buffer) < n:
        chunk = sock.recv(n - len(buffer))
        if not chunk:
            break
        buffer += chunk
    return buffer


class SmbProbe:
    """Sends a NEGOTIATE request and reads the response over a raw socket.

    Args:
        timeout: The connection timeout, in seconds.
        connect: An injectable ``(address, timeout) -> socket`` callable.
    """

    def __init__(self, timeout: float = 5.0, connect: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._connect = connect or socket.create_connection

    def _exchange(self, host: str, port: int, requests: List[bytes]) -> List[bytes]:
        """Manda una secuencia de mensajes y devuelve las respuestas leídas.

        Cada mensaje SMB viene precedido de una cabecera NetBIOS de cuatro
        bytes cuyo último tres es la longitud del que sigue, así que la lectura
        es exacta y no depende de dónde corte el sistema operativo.

        Args:
            host: El objetivo.
            port: El puerto.
            requests: Los mensajes a enviar, en orden.

        Returns:
            Las respuestas que se hayan podido leer enteras. La lista puede ser
            más corta que ``requests`` si el servidor cortó por el camino.
        """
        try:
            sock = self._connect((host, port), self._timeout)
        except OSError as err:
            logger.debug("SMB probe connect failed for %s:%s: %s", host, port, err)
            return []
        replies: List[bytes] = []
        try:
            sock.settimeout(self._timeout)
            for request in requests:
                sock.sendall(request)
                netbios_header = _read_exact(sock, 4)
                if len(netbios_header) < 4:
                    break
                length = int.from_bytes(netbios_header[1:4], "big")
                message = _read_exact(sock, length)
                if len(message) < length:
                    break
                replies.append(message)
        except OSError as err:
            logger.debug("SMB probe failed for %s:%s: %s", host, port, err)
        finally:
            try:
                sock.close()
            except OSError:
                pass
        return replies

    def fetch_identity(self, host: str, port: int = 445) -> Dict[str, str]:
        """Lee el nombre de equipo y el dominio con un ``SESSION_SETUP`` anónimo.

        El intercambio se corta en el primer paso de la negociación NTLM, justo
        cuando el servidor ya ha dicho quién es y todavía no ha pedido nada:
        **no se manda ninguna credencial y no se establece sesión**.

        Args:
            host: El objetivo.
            port: El puerto de SMB.

        Returns:
            Lo que se haya podido leer, o un mapa vacío.
        """
        replies = self._exchange(host, port, [
            build_negotiate_request(),
            build_session_setup_request(build_ntlm_negotiate()),
        ])
        if len(replies) < 2:
            return {}
        return parse_ntlm_challenge(replies[1])

    def speaks_smb1(self, host: str, port: int = 445) -> bool:
        """Comprueba si el servidor acepta una negociación de SMB1.

        Conexión aparte de la de SMB2, y no por descuido: son dos protocolos
        distintos y un servidor que ya ha negociado SMB2 sobre una conexión no
        va a aceptar un saludo de SMB1 sobre la misma.

        Args:
            host: El objetivo.
            port: El puerto de SMB.

        Returns:
            ``True`` sólo ante una aceptación explícita.
        """
        replies = self._exchange(host, port, [build_smb1_negotiate()])
        return bool(replies) and parse_smb1_negotiate_response(replies[0])

    def fetch(self, host: str, port: int = 445) -> Optional[Tuple[int, int]]:
        """Negotiate with an SMB service and return its dialect and security mode.

        Returns:
            A ``(dialect_revision, security_mode)`` tuple, or ``None`` on
            connection failure or an unparseable response.
        """
        try:
            sock = self._connect((host, port), self._timeout)
        except OSError as err:
            logger.debug("SMB probe connect failed for %s:%s: %s", host, port, err)
            return None
        try:
            sock.sendall(build_negotiate_request())
            nb_header = _read_exact(sock, 4)
            if len(nb_header) < 4:
                return None
            length = int.from_bytes(nb_header[1:4], "big")
            message = _read_exact(sock, length)
            if len(message) < length:
                return None
            return parse_negotiate_response(message)
        except OSError as err:
            logger.debug("SMB probe failed for %s:%s: %s", host, port, err)
            return None
        finally:
            try:
                sock.close()
            except OSError:
                pass


def _label_with_identity(fingerprint: SmbFingerprint) -> str:
    """Compone la etiqueta del dissector con lo que se sepa del activo.

    El nombre de equipo y el dominio no caben en ``product``/``version`` —esos
    dos campos alimentan la resolución de un CPE, y meter ahí un nombre de
    máquina lo estropearía— pero sí merecen llegar al título del hallazgo, que
    es lo que alguien lee en el informe. ``SMB`` a secas cuando no se sabe
    nada; ``SMB en WIN-SRV01 (CORP)`` cuando sí.

    Args:
        fingerprint: El fingerprint ya construido.

    Returns:
        La etiqueta.
    """
    if not fingerprint.hostname and not fingerprint.domain:
        return SmbDissector.label
    if fingerprint.hostname and fingerprint.domain:
        return f"{SmbDissector.label} en {fingerprint.hostname} ({fingerprint.domain})"
    return f"{SmbDissector.label} en {fingerprint.hostname or fingerprint.domain}"


@register_dissector
class SmbDissector(Dissector):
    label = "SMB"

    def __init__(self, probe: Optional[SmbProbe] = None) -> None:
        self._probe = probe or SmbProbe()

    def applies(self, service) -> bool:
        return is_smb_service(service)

    def probe(self, target, service, rate_limiter):
        port = service.port or 445
        rate_limiter.acquire(target)
        result = self._probe.fetch(target, port)
        if result is None:
            return None
        dialect_revision, security_mode = result

        # El SESSION_SETUP va aparte y sólo si el NEGOTIATE ha ido bien: sin un
        # SMB2 al otro lado no hay a quién preguntarle su nombre.
        rate_limiter.acquire(target)
        identity = self._probe.fetch_identity(target, port)

        fingerprint = fingerprint_smb(dialect_revision, security_mode, identity)
        return DissectorResult(
            fingerprint.product, fingerprint.version, _label_with_identity(fingerprint),
        )
