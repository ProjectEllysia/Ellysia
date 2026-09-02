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
    is_postgres_service,
    is_smb_service,
    is_snmp_service,
)
from .engine import Service
from .fingerprinting.smb import SIGNING_REQUIRED_BIT, SmbProbe, fingerprint_smb
from .fingerprinting.postgres import PostgresProbe, fingerprint_postgres
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
    )
    return {plugin.plugin_id: plugin for plugin in plugins}
