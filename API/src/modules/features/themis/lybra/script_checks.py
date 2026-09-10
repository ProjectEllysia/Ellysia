"""Checks de tipo ``script`` — el cuarto tipo del runtime.

Un check declarativo compara texto: pide algo y mira si la respuesta contiene
un patrón. Eso cubre el 90 % de lo web, pero deja fuera todo lo que exige
lógica: un protocolo binario, una negociación de varios pasos cuyo resultado
hay que interpretar, o un hecho que ya se dedujo pero que ningún matcher de
texto puede expresar. Para eso está este tipo.

**Un caso concreto, que es el que motiva el módulo.** Los checks "SMB sin
firma" y "SMBv1 habilitado" no se pueden expresar como un check declarativo,
porque el runtime declarativo sólo compara texto decodificado y una respuesta
SMB2 es binaria. Pero el dissector de SMB ya negocia con el servidor y ya lee
su ``SecurityMode``: el hecho está observado, sólo faltaba un vehículo para
convertirlo en un hallazgo. Un plugin de primera parte es ese vehículo.

**Por qué los plugins se inyectan y no se importan.** ``checks.py`` no importa
``fingerprinting`` a propósito — lo dice su propio comentario en ``_TLS_RULES``:
importarlo crearía un ciclo, porque los dissectors importan de ``checks`` sus
predicados de aplicabilidad (``is_smb_service`` y compañía). Este módulo sí
puede importar ambos, y el runtime recibe el registro ya construido por el
mismo mecanismo de inyección con el que ya recibe ``tls_fetch`` y
``network_open``. El runtime sigue sin conocer ningún protocolo concreto.

El reparto es el mismo que ya existe para los dissectors: la clase base
(:class:`~.checks.ScriptPlugin`) y su contexto viven junto al runtime, igual que
``Dissector`` vive en ``dispatch.py``; los plugins concretos viven aquí, igual
que ``SmbDissector`` vive en ``smb.py``.
"""

from __future__ import annotations

import logging
from typing import Dict, Optional

from .checks import (
    ScriptContext,
    ScriptPlugin,
    LDAPS_PORTS,
    is_ldap_service,
    is_dns_service,
    is_mongodb_service,
    is_ntp_service,
    is_rdp_service,
    is_postgres_service,
    is_smb_service,
    is_snmp_service,
    is_telnet_service,
    is_vnc_service,
)
from .engine import Service
from .fingerprinting.smb import SIGNING_REQUIRED_BIT, SmbProbe, fingerprint_smb
from .fingerprinting.ldap import LdapProbe, fingerprint_ldap
from .fingerprinting.mongo import MongoProbe, fingerprint_mongo
from .fingerprinting.postgres import PostgresProbe, fingerprint_postgres
from .fingerprinting.rdp import RdpProbe, fingerprint_rdp
from .fingerprinting.snmp import SnmpProbe
from .fingerprinting.telnet import TelnetProbe
from .fingerprinting.vnc import VncProbe
from .fingerprinting.udp_services import (
    DnsProbe,
    NtpProbe,
    monlist_is_answered,
    parse_dns_version_response,
)

logger = logging.getLogger(__name__)


class SmbSigningNotRequiredPlugin(ScriptPlugin):
    """Detecta un servicio SMB que no exige firma de mensajes.

    Sin firma obligatoria, un atacante en posición de intermediario puede
    manipular el tráfico SMB (la familia de ataques de relay). El dato no se
    infiere: sale del ``SecurityMode`` que el propio servidor devuelve en su
    respuesta NEGOTIATE, así que el hallazgo nace ``confirmed``.

    **La decisión se toma sobre el bit, no sobre la etiqueta.** Este plugin
    llegó a resolverse buscando la subcadena ``"firma no requerida"`` dentro
    del texto legible que produce ``fingerprint_smb``. Eso ataba una decisión
    de seguridad a una cadena de interfaz: traducir esa etiqueta, corregirle
    una tilde o cambiarle el fraseo apagaba el check **en silencio** —seguía
    ejecutándose, seguía devolviendo ``False``, y nadie se enteraba de que
    había dejado de detectar nada—. El dato crudo estaba dos líneas más
    arriba, en la misma tupla.

    Args:
        probe: Sonda inyectable, para que un test use un socket falso — mismo
            patrón que :class:`~.fingerprinting.smb.SmbDissector`.
    """

    plugin_id = "smb-signing-not-required"

    def __init__(self, probe: Optional[SmbProbe] = None) -> None:
        self._probe = probe or SmbProbe()

    def applies(self, service: Service) -> bool:
        return is_smb_service(service)

    def run(self, context: ScriptContext) -> bool:
        context.acquire()
        result = self._probe.fetch(context.target, context.service.port or 445)
        if result is None:
            # Sin negociación no hay evidencia, y sin evidencia no hay hallazgo.
            return False
        dialect_revision, security_mode = result
        if fingerprint_smb(dialect_revision, security_mode).version is None:
            # Respuesta no reconocible: se ignora en vez de asumir lo peor. Un
            # dialecto desconocido no es prueba de que la firma no se exija.
            # Se consulta ``version`` —un campo con tipo— y no el texto del
            # producto: lo que hace falta saber aquí es si la respuesta se
            # entendió, y eso es justo lo que ese campo significa.
            return False
        return not security_mode & SIGNING_REQUIRED_BIT


class SmbV1EnabledPlugin(ScriptPlugin):
    """Detecta un servidor que todavía acepta negociar **SMBv1**.

    Es el hallazgo clásico del protocolo, el que WannaCry convirtió en
    historia: SMB1 no tiene firma obligatoria utilizable, no cifra, y arrastra
    una familia de vulnerabilidades pre-autenticación (EternalBlue y sus
    parientes) que no se han corregido porque el protocolo entero está
    retirado desde 2014. Microsoft lo desactiva por defecto desde Windows 10
    1709; encontrarlo activo significa o bien un sistema viejo o bien alguien
    que lo reactivó a mano por un dispositivo heredado.

    **El NEGOTIATE de SMB2 no puede verlo**, y por eso este check tiene su
    propia sonda: son dos protocolos distintos con dos saludos distintos, así
    que un servidor con SMB1 activo contesta con toda normalidad al SMB2 y no
    dice ni una palabra sobre el otro.

    La evidencia es una aceptación explícita: el servidor contesta un
    ``NEGOTIATE`` de SMB1 con estado correcto y eligiendo un dialecto. El
    silencio, un error o una respuesta de SMB2 **no** cuentan — un servidor
    que no habla SMB1 no tiene por qué contestar de ninguna forma concreta.

    Args:
        probe: Sonda inyectable, para que un test use un socket falso.
    """

    plugin_id = "smbv1-enabled"

    def __init__(self, probe: Optional[SmbProbe] = None) -> None:
        self._probe = probe or SmbProbe()

    def applies(self, service: Service) -> bool:
        return is_smb_service(service)

    def run(self, context: ScriptContext) -> bool:
        context.acquire()
        return self._probe.speaks_smb1(context.target, context.service.port or 445)


class SnmpDefaultCommunityPlugin(ScriptPlugin):
    """Detecta un servicio SNMP que acepta la comunidad por defecto ``public``.

    Comparte la sonda con el dissector SNMP a
    propósito: que ``sysDescr`` conteste a ``public`` ES la evidencia del
    hallazgo, no una comprobación aparte — no tiene sentido mandar el mismo
    datagrama dos veces con dos sondas distintas.

    Args:
        probe: Sonda inyectable, mismo patrón que
            :class:`~.fingerprinting.snmp.SnmpDissector`.
    """

    plugin_id = "snmp-default-community"

    def __init__(self, probe: Optional[SnmpProbe] = None) -> None:
        self._probe = probe or SnmpProbe()

    def applies(self, service: Service) -> bool:
        return is_snmp_service(service)

    def run(self, context: ScriptContext) -> bool:
        context.acquire()
        sysdescr = self._probe.fetch(context.target, context.service.port or 161)
        return sysdescr is not None


class PostgresTrustAuthenticationPlugin(ScriptPlugin):
    """Detecta un PostgreSQL que acepta conexiones de red **sin contraseña**.

    El modo ``trust`` de PostgreSQL no es una autenticación débil: es la
    ausencia completa de autenticación. Un servidor con ``trust`` en su
    ``pg_hba.conf`` para direcciones de red da acceso total a cualquiera que
    alcance el puerto — sin exploit, sin fuerza bruta y sin credenciales.

    La evidencia no se infiere: es el propio servidor contestando
    ``AuthenticationOk`` a un ``StartupMessage`` con un usuario que **no
    existe**. Por eso el hallazgo nace ``confirmed``, y por eso el plugin no
    intenta autenticarse en ningún momento: no manda contraseña ninguna, sólo
    lee la política que el servidor anuncia.

    Comparte sonda con el dissector por el mismo criterio que el de SNMP: el
    dato que responde a la pregunta es el mismo, y mandar dos veces el mismo
    intercambio no lo haría más cierto.

    Args:
        probe: Sonda inyectable, para que un test use un socket falso.
    """

    plugin_id = "postgres-trust-authentication"

    def __init__(self, probe: Optional[PostgresProbe] = None) -> None:
        self._probe = probe or PostgresProbe()

    def applies(self, service: Service) -> bool:
        return is_postgres_service(service)

    def run(self, context: ScriptContext) -> bool:
        context.acquire()
        replies = self._probe.fetch(context.target, context.service.port or 5432)
        if replies is None:
            # Sin intercambio no hay evidencia, y sin evidencia no hay hallazgo.
            return False
        return fingerprint_postgres(*replies).is_unauthenticated


class MongoUnauthenticatedAccessPlugin(ScriptPlugin):
    """Detecta un MongoDB que sirve su catálogo **sin credenciales**.

    Es el hallazgo clásico del producto: durante años las instalaciones por
    defecto escuchaban en todas las interfaces sin autenticación, y de ahí
    salió una de las mayores oleadas de fuga de datos y de ransomware de bases
    de datos que se recuerdan.

    **La evidencia no es que el servidor conteste.** El comando ``hello``
    responde siempre, con ``--auth`` y sin él —es el handshake del protocolo, y
    tiene que hacerlo para que el cliente sepa con quién habla—, así que un
    check construido sobre "ha contestado" marcaría como expuesto todo MongoDB
    alcanzable. La evidencia es que ``listDatabases``, que sí exige permisos,
    devuelva la lista: un servidor cerrado responde ``ok: 0`` con el código 13.

    Args:
        probe: Sonda inyectable, para que un test use un socket falso.
    """

    plugin_id = "mongodb-unauthenticated-access"

    def __init__(self, probe: Optional[MongoProbe] = None) -> None:
        self._probe = probe or MongoProbe()

    def applies(self, service: Service) -> bool:
        return is_mongodb_service(service)

    def run(self, context: ScriptContext) -> bool:
        context.acquire()
        replies = self._probe.fetch(context.target, context.service.port or 27017)
        if replies is None:
            return False
        return fingerprint_mongo(*replies).allows_unauthenticated_access


class LdapAnonymousBindPlugin(ScriptPlugin):
    """Detecta un servidor de directorio que acepta un bind **anónimo**.

    Si el rootDSE contesta sin credenciales, la información del directorio es
    pública: quién sirve qué dominio, qué mecanismos de autenticación admite y,
    en muchos despliegues, bastante más si la consulta se amplía.

    Un bind anónimo no es un intento de adivinar credenciales: es la forma que
    el propio protocolo define para preguntar sin identificarse (RFC 4511
    §4.2), y lo que se observa es si el servidor **la acepta**. No se prueba
    ninguna contraseña.

    Args:
        probe: Sonda inyectable, para que un test use un socket falso.
    """

    plugin_id = "ldap-anonymous-bind"

    def __init__(self, probe: Optional[LdapProbe] = None) -> None:
        self._probe = probe or LdapProbe()

    def applies(self, service: Service) -> bool:
        return is_ldap_service(service)

    def run(self, context: ScriptContext) -> bool:
        context.acquire()
        replies = self._probe.fetch(context.target, context.service.port or 389)
        if replies is None:
            return False
        return fingerprint_ldap(*replies).allows_anonymous_bind


class LdapCleartextWithLdapsPlugin(ScriptPlugin):
    """Detecta un LDAP en claro conviviendo con un LDAPS en el mismo host.

    Éste es el primer check del motor que **no es propiedad de un servicio sino
    de la relación entre dos**. Un 389 abierto no dice gran cosa por sí solo:
    hay despliegues donde es la única opción y el cifrado se resuelve con
    STARTTLS. Pero un 389 en un host que además publica el 636 significa que la
    versión cifrada existe, funciona, y aun así el puerto en claro sigue
    aceptando binds — así que basta con que un cliente esté mal configurado
    para que unas credenciales de directorio viajen legibles por la red.

    No hace ninguna petición: la evidencia son dos puertos que el
    descubrimiento ya encontró (ver ``ScriptContext.sibling_services``).
    """

    plugin_id = "ldap-cleartext-with-ldaps"

    def applies(self, service: Service) -> bool:
        return is_ldap_service(service) and service.port not in LDAPS_PORTS

    def run(self, context: ScriptContext) -> bool:
        return any(
            sibling.port in LDAPS_PORTS
            for sibling in context.sibling_services
        )


class RdpNlaNotRequiredPlugin(ScriptPlugin):
    """Detecta un RDP que **no** exige autenticación a nivel de red.

    NLA obliga a autenticarse antes de que exista la sesión gráfica. Sin él,
    cualquiera que alcance el puerto llega a la pantalla de login — lo que
    habilita la fuerza bruta y toda la familia de vulnerabilidades
    pre-autenticación de la que BlueKeep (CVE-2019-0708) es el ejemplo
    canónico. RDP es, además, el vector de entrada de la mayoría de los
    incidentes de ransomware que empiezan por acceso remoto.

    El dato no se infiere: es el protocolo de seguridad que el propio servidor
    **elige** en la negociación de X.224, así que el hallazgo nace
    ``confirmed``.

    **Un servidor cuyo modo no se ha podido leer no dispara el check.** La
    propiedad que se consulta distingue "no exige NLA" de "no se sabe"
    (``None``), y sólo la primera es un hallazgo: afirmar una configuración
    insegura sin haberla observado sería inventarla.

    Args:
        probe: Sonda inyectable, para que un test use un socket falso.
    """

    plugin_id = "rdp-nla-not-required"

    def __init__(self, probe: Optional[RdpProbe] = None) -> None:
        self._probe = probe or RdpProbe()

    def applies(self, service: Service) -> bool:
        return is_rdp_service(service)

    def run(self, context: ScriptContext) -> bool:
        context.acquire()
        response = self._probe.fetch(context.target, context.service.port or 3389)
        if response is None:
            return False
        return fingerprint_rdp(response).requires_network_level_authentication is False


class DnsOpenResolverPlugin(ScriptPlugin):
    """Detecta un servidor DNS que resuelve nombres para cualquiera.

    Un resolutor abierto no es sólo un problema para su dueño: es un
    **amplificador a disposición de quien lo quiera usar**. Una consulta
    pequeña con la dirección de origen falsificada provoca una respuesta mucho
    mayor dirigida a la víctima, y el host del cliente pasa de tener un
    servicio mal configurado a ser un arma contra terceros. Ésa es una
    conversación distinta, y más incómoda, que "tienes un puerto abierto".

    **La evidencia es la bandera que el servidor enciende él solo.** La
    respuesta a ``version.bind`` trae el bit de "recursión disponible", y con
    eso basta: la alternativa —lanzar una consulta recursiva de verdad por un
    nombre externo— haría que el objetivo mandase tráfico a un tercero para
    responderla, que es exactamente el comportamiento que se está midiendo.
    Comprobarlo no debería practicarlo.

    Args:
        probe: Sonda inyectable, para que un test use un emisor falso.
    """

    plugin_id = "dns-open-resolver"

    def __init__(self, probe: Optional[DnsProbe] = None) -> None:
        self._probe = probe or DnsProbe()

    def applies(self, service: Service) -> bool:
        return is_dns_service(service)

    def run(self, context: ScriptContext) -> bool:
        context.acquire()
        reply = self._probe.fetch(context.target, context.service.port or 53)
        if reply is None:
            return False
        return parse_dns_version_response(reply).offers_recursion


class NtpMonlistPlugin(ScriptPlugin):
    """Detecta un servidor NTP que sigue aceptando ``monlist``.

    ``monlist`` devuelve los últimos seiscientos clientes que han hablado con
    el servidor. Es a la vez un problema de privacidad —el inventario de quién
    usa ese NTP— y el vector de amplificación x500 que llenó internet de
    ataques en 2014: ocho bytes de petición provocan kilobytes de respuesta.

    Preguntarlo no amplifica nada contra nadie: la respuesta viene **a
    nosotros**, no a un tercero. Lo que demuestra es que ese servidor serviría
    para hacerlo.

    Args:
        probe: Sonda inyectable, para que un test use un emisor falso.
    """

    plugin_id = "ntp-monlist-enabled"

    def __init__(self, probe: Optional[NtpProbe] = None) -> None:
        self._probe = probe or NtpProbe()

    def applies(self, service: Service) -> bool:
        return is_ntp_service(service)

    def run(self, context: ScriptContext) -> bool:
        context.acquire()
        return monlist_is_answered(
            self._probe.fetch_monlist(context.target, context.service.port or 123))


class TelnetEnabledPlugin(ScriptPlugin):
    """Detecta un servicio Telnet activo.

    Telnet manda credenciales en claro por diseño: usuario y contraseña viajan
    sin cifrar por la red, legibles para cualquiera que escuche. No hay una
    "mala configuración" que arreglar — el hallazgo es que el protocolo esté en
    uso. Por eso este check no identifica producto ni versión: le basta con
    confirmar que al otro lado hay algo que **habla Telnet**, cosa que un
    servidor delata abriendo su negociación de opciones con el byte IAC (ver
    :class:`~.fingerprinting.telnet.TelnetProbe`).

    Un puerto 23 abierto no basta como evidencia: podría ser cualquier servicio
    mudo en un puerto reutilizado. Lo que dispara es la firma del protocolo, no
    la apertura del puerto.

    Args:
        probe: Sonda inyectable, para que un test use un socket falso.
    """

    plugin_id = "telnet-enabled"

    def __init__(self, probe: Optional[TelnetProbe] = None) -> None:
        self._probe = probe or TelnetProbe()

    def applies(self, service: Service) -> bool:
        return is_telnet_service(service)

    def run(self, context: ScriptContext) -> bool:
        context.acquire()
        return self._probe.speaks_telnet(context.target, context.service.port or 23)


class VncNoAuthenticationPlugin(ScriptPlugin):
    """Detecta un servidor VNC que ofrece acceso **sin autenticación**.

    El protocolo RFB negocia, tras el saludo de versión, qué tipos de seguridad
    admite el servidor. El tipo 1 es ``None`` (RFC 6143 §7.1.2): entrar sin
    contraseña. Un VNC que lo ofrece deja el escritorio del objetivo a
    disposición de cualquiera que alcance el puerto.

    La evidencia es un hecho observado —el servidor **anuncia** ese tipo en su
    lista—, no una inferencia, así que el hallazgo nace ``confirmed``. Y no se
    cruza la línea: se lee la lista de tipos ofrecidos y ahí acaba, sin
    responder a la negociación y sin abrir sesión (ver
    :meth:`~.fingerprinting.vnc.VncProbe.security_types`).

    Args:
        probe: Sonda inyectable, para que un test use un socket falso.
    """

    plugin_id = "vnc-no-authentication"
    _SECURITY_NONE = 1

    def __init__(self, probe: Optional[VncProbe] = None) -> None:
        self._probe = probe or VncProbe()

    def applies(self, service: Service) -> bool:
        return is_vnc_service(service)

    def run(self, context: ScriptContext) -> bool:
        context.acquire()
        types = self._probe.security_types(context.target, context.service.port or 5900)
        if types is None:
            return False
        return self._SECURITY_NONE in types


def default_script_plugins() -> Dict[str, ScriptPlugin]:
    """Construye el registro de plugins de primera parte, indexado por ``plugin_id``.

    Returns:
        Un mapa ``plugin_id -> plugin``, que es lo que ``CheckRuntime`` espera
        recibir por inyección. Añadir un plugin es añadir una entrada aquí.
    """
    plugins = (
        SmbSigningNotRequiredPlugin(),
        SmbV1EnabledPlugin(),
        SnmpDefaultCommunityPlugin(),
        DnsOpenResolverPlugin(),
        NtpMonlistPlugin(),
        PostgresTrustAuthenticationPlugin(),
        MongoUnauthenticatedAccessPlugin(),
        LdapAnonymousBindPlugin(),
        LdapCleartextWithLdapsPlugin(),
        RdpNlaNotRequiredPlugin(),
        TelnetEnabledPlugin(),
        VncNoAuthenticationPlugin(),
    )
    return {plugin.plugin_id: plugin for plugin in plugins}
