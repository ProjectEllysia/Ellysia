"""Checks de tipo ``script`` — el cuarto tipo del runtime (Fase R).

Un check declarativo compara texto: pide algo y mira si la respuesta contiene
un patrón. Eso cubre el 90 % de lo web, pero deja fuera todo lo que exige
lógica: un protocolo binario, una negociación de varios pasos cuyo resultado
hay que interpretar, o un hecho que ya se dedujo pero que ningún matcher de
texto puede expresar. Para eso está este tipo.

**Un caso concreto, que es el que motiva el módulo.** La Fase N dejó anotado que
los checks "SMB sin firma" y "SMBv1 habilitado" *no se pudieron construir*
porque «el runtime declarativo actual solo compara texto decodificado, y una
respuesta SMB2 es binaria». Pero el dissector de SMB ya negocia con el servidor
y ya lee su ``SecurityMode``: el hecho está observado, solo faltaba un vehículo
para convertirlo en un hallazgo. Un plugin de primera parte es ese vehículo, y
llega mucho antes que el camino alternativo (adoptar el esquema ``network`` de
Nuclei con ``type: hex`` y un matcher ``binary``, que depende de la medición de
U4).

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
    is_mongodb_service,
    is_rdp_service,
    is_postgres_service,
    is_smb_service,
    is_snmp_service,
)
from .engine import Service
from .fingerprinting.smb import SIGNING_REQUIRED_BIT, SmbProbe, fingerprint_smb
from .fingerprinting.ldap import LdapProbe, fingerprint_ldap
from .fingerprinting.mongo import MongoProbe, fingerprint_mongo
from .fingerprinting.postgres import PostgresProbe, fingerprint_postgres
from .fingerprinting.rdp import RdpProbe, fingerprint_rdp
from .fingerprinting.snmp import SnmpProbe

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


class SnmpDefaultCommunityPlugin(ScriptPlugin):
    """Detecta un servicio SNMP que acepta la comunidad por defecto ``public``.

    Comparte la sonda con el dissector SNMP (Fase N/Ronda 1, roadmap §6.3) a
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


def default_script_plugins() -> Dict[str, ScriptPlugin]:
    """Construye el registro de plugins de primera parte, indexado por ``plugin_id``.

    Returns:
        Un mapa ``plugin_id -> plugin``, que es lo que ``CheckRuntime`` espera
        recibir por inyección. Añadir un plugin es añadir una entrada aquí.
    """
    plugins = (
        SmbSigningNotRequiredPlugin(),
        SnmpDefaultCommunityPlugin(),
        PostgresTrustAuthenticationPlugin(),
        MongoUnauthenticatedAccessPlugin(),
        LdapAnonymousBindPlugin(),
        LdapCleartextWithLdapsPlugin(),
        RdpNlaNotRequiredPlugin(),
    )
    return {plugin.plugin_id: plugin for plugin in plugins}
