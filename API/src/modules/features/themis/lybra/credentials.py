"""El motor de credenciales por defecto.

Es la **única** familia de detección de Lybra que escribe en el objetivo: cada
intento es un login real contra un servicio real — una operación que puede
bloquear cuentas, que genera ruido en el SIEM del objetivo y que exige un
control de tasa y un presupuesto muy distintos a un GET de .git/config — y
por eso vive en su propio módulo, con sus propias guardas, en vez de ser un
``Check`` más del DSL declarativo de :mod:`checks`.

**Las guardas no son opcionales, y son del llamante, no de aquí.** Este
runtime no decide si debe correr: el manager lo invoca sólo bajo la doble
puerta del modo agresivo — objetivo en el registro de autorización *y*
petición explícita del usuario —, exactamente igual que cualquier otro check
``mode: aggressive``. Lo que sí es responsabilidad de este módulo es el
presupuesto de intentos: **por cuenta, no por servicio** — tres contraseñas
distintas contra ``admin`` cuentan tres intentos para ``admin``, sin que
probar además ``root`` en el mismo servicio consuma ese mismo cupo. Es la
cuenta, no el servicio, la que un proveedor bloquea tras demasiados fallos.

**El plaintext nunca sale de este módulo.** Una vez usada para construir la
cabecera ``Authorization``, una contraseña no vuelve a aparecer en ningún
dict que este módulo produzca — ni en el hallazgo, ni en su evidencia, ni en
un log. Sólo el *nombre de usuario* que funcionó se recuerda, porque decir
"la cuenta admin tiene la contraseña de fábrica" es información útil para
quien recibe el informe; decir cuál era la contraseña no lo es, y guardarla
convertiría la base de datos de un cliente en un depósito de las contraseñas
del propio cliente.

Reutiliza deliberadamente piezas de :mod:`checks` en vez de duplicarlas: el
mismo :class:`~.checks.Matcher` decide si una respuesta demuestra que el login
funcionó, el mismo :class:`~.checks.Response` es lo que un matcher evalúa, y
el ``fetch`` inyectado es la misma forma que :class:`~.checks.HttpProbe.fetch`
ya expone (``host, port, method, path, body, headers``) — un intento de
credenciales *es* una petición HTTP con una cabecera ``Authorization``, nada
más.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional

from .checks import HostRateLimiter, Matcher, Response, is_http_service

logger = logging.getLogger(__name__)

# El feed shipped junto al de checks.py, mismo directorio, mismo trato: JSON
# porque estos pares no necesitan comentarios extensos por entrada como el
# feed de checks (una lista de pares usuario/contraseña se explica sola), y
# porque no aspira a compatibilidad con ningún formato externo (a diferencia
# de checks_feed.yaml, que sí la busca con Nuclei).
_BUNDLED_FEED = Path(__file__).parent / "feeds" / "credentials_feed.json"

CREDENTIALS_FEED_VERSION = "lybra-credentials-1"
QOD_CONFIRMED = 99

# Servicios candidatos hoy. Sólo HTTP: es donde vive Tomcat Manager, Jenkins y
# la mayoría de paneles de administración con credenciales de fábrica
# conocidas, y es el único protocolo para el que ``HttpProbe.fetch`` ya sabe
# mandar una cabecera ``Authorization``. Ampliar a FTP/SSH es straight-
# forward por el mismo camino que las familias ``network`` de checks.py —
# inyectar un ``attempt`` en vez de un ``fetch`` HTTP—, pero no hay ninguna
# entrada del feed que lo necesite todavía.
_SERVICE_MATCHERS: Dict[str, Callable] = {
    "http": is_http_service,
}


@dataclass(frozen=True)
class CredentialPair:
    """Un par usuario/contraseña de fábrica a probar.

    Attributes:
        username: El nombre de usuario.
        password: La contraseña. Vive únicamente aquí y en la cabecera HTTP
            que :class:`CredentialRuntime` construye con ella — nunca en un
            hallazgo, en su evidencia, ni en un log.
    """
    username: str
    password: str


@dataclass(frozen=True)
class CredentialEntry:  # pylint: disable=too-many-instance-attributes
    """Un producto con credenciales de fábrica conocidas y cómo probarlas.

    Attributes:
        id: Identificador corto, p. ej. ``"tomcat-manager-default"``.
        version: Versión de la entrada — misma convención que
            :attr:`~.checks.Check.version`: sube cuando cambia qué prueba o
            cómo, no cuando sólo se añade un par a la lista.
        service: Qué servicio reclama esta entrada (``"http"`` hoy — ver
            :data:`_SERVICE_MATCHERS`).
        method: El método HTTP de la sonda.
        path: La ruta a la que se manda cada intento (p. ej.
            ``"/manager/html"`` para Tomcat Manager).
        accounts: Los pares a probar, en orden. El mismo usuario puede
            aparecer varias veces con contraseñas distintas — así es como el
            presupuesto "por cuenta" tiene sentido: agota primero las
            contraseñas de una cuenta antes de pasar a la siguiente.
        matchers: Las condiciones que demuestran que el intento entró — el
            mismo :class:`~.checks.Matcher` que usa el DSL declarativo,
            combinadas con AND. Un ``status: 200`` solo no basta contra un
            servidor que sirve sin autenticar; el feed añade además una
            palabra del cuerpo esperado tras entrar.
        finding: Plantilla de campos del hallazgo (``title`` sobre todo).
        feed_version: Versión del feed de origen, o ``None`` para usar
            :data:`CREDENTIALS_FEED_VERSION`.
    """
    id: str
    version: int
    service: str
    path: str
    accounts: tuple
    matchers: tuple
    method: str = "GET"
    finding: dict = field(default_factory=dict)
    feed_version: Optional[str] = None

    @property
    def check_id(self) -> str:
        """El identificador versionado, p. ej. ``lybra-credentials:tomcat-manager-default@1``."""
        return f"lybra-credentials:{self.id}@{self.version}"


# =========================================================================
# FEED LOADING
# =========================================================================

def load_credentials(path: Optional[str] = None) -> List[CredentialEntry]:
    """Cargar y parsear el feed de credenciales por defecto.

    Args:
        path: Ruta a un feed JSON. Por defecto, el empaquetado con el módulo.

    Returns:
        Las entradas parseadas.
    """
    feed_path = Path(path) if path else _BUNDLED_FEED
    document = json.loads(feed_path.read_text(encoding="utf-8"))
    return [_parse_entry(entry) for entry in document.get("entries", [])]


def _parse_entry(raw: dict) -> CredentialEntry:
    """Construir una :class:`CredentialEntry` desde su representación JSON."""
    return CredentialEntry(
        id=raw["id"],
        version=raw.get("version", 1),
        service=raw.get("service", "http"),
        method=raw.get("method", "GET"),
        path=raw.get("path", "/"),
        accounts=tuple(
            CredentialPair(username=account["username"], password=account["password"])
            for account in raw.get("accounts", [])
        ),
        matchers=tuple(
            Matcher(
                type=matcher["type"],
                part=matcher.get("part", "body"),
                values=tuple(matcher.get("words") or matcher.get("regex") or matcher.get("value") or []),
                negative=matcher.get("negative", False),
            )
            for matcher in raw.get("matchers", [])
        ),
        finding=raw.get("finding", {}),
    )


# =========================================================================
# FEED VALIDATION
# =========================================================================

def validate_credentials(entries: Iterable[CredentialEntry]) -> List[str]:
    """Comprobar que ninguna entrada de credenciales está muerta por construcción.

    Misma filosofía que :func:`~.checks.validate_checks`: un feed que se
    ejecuta y falla en silencio es peor que uno que no carga. Devuelve los
    problemas en vez de lanzar, para poder revisar el feed entero de una vez.

    Args:
        entries: Las entradas ya parseadas.

    Returns:
        Una lista de problemas legibles, vacía si el feed está sano.
    """
    problems: List[str] = []
    seen: set = set()

    for entry in entries:
        name = entry.id or "<sin id>"

        if not entry.id:
            problems.append("Una entrada de credenciales no declara 'id'")
        if (entry.id, entry.version) in seen:
            problems.append(f"Entrada {name!r}: duplicada en (id, version)={(entry.id, entry.version)}")
        seen.add((entry.id, entry.version))

        if entry.service not in _SERVICE_MATCHERS:
            problems.append(
                f"Entrada {name!r}: servicio {entry.service!r} sin predicado "
                f"(disponibles: {', '.join(sorted(_SERVICE_MATCHERS))})"
            )
        if not entry.accounts:
            problems.append(f"Entrada {name!r}: sin ninguna cuenta que probar")
        for position, account in enumerate(entry.accounts):
            if not account.username:
                problems.append(f"Entrada {name!r}, cuenta {position}: sin 'username'")
            if not account.password:
                problems.append(f"Entrada {name!r}, cuenta {position}: sin 'password'")
        if not entry.matchers:
            problems.append(
                f"Entrada {name!r}: sin ningún matcher, así que ningún intento "
                f"se podría distinguir de un fallo de login"
            )

    return problems


# =========================================================================
# RUNTIME
# =========================================================================

def _basic_auth_headers(username: str, password: str) -> Dict[str, str]:
    """Construir la cabecera ``Authorization: Basic`` para un intento.

    El único punto de todo el módulo donde la contraseña en claro se toca:
    entra aquí, sale codificada en la cabecera, y no queda en ninguna otra
    parte —ni en una variable que sobreviva a esta llamada.
    """
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


class CredentialRuntime:
    """Prueba credenciales de fábrica contra los servicios de un host.

    Args:
        entries: Las entradas de credenciales a probar.
        fetch: Un ``(host, port, method, path, body, headers) -> Response |
            None`` — la misma forma que :meth:`~.checks.HttpProbe.fetch`
            expone.
        rate_limiter: Limitador por host opcional, aplicado antes de cada
            intento — cada login real es tráfico hacia el objetivo, y esta es
            la única familia del motor donde ese tráfico además escribe.
        max_attempts_per_account: Tope de contraseñas distintas probadas
            contra una misma cuenta — no contra un mismo servicio. Ver
            el docstring del módulo.
        capture_evidence: Si se adjunta la respuesta que demostró el acceso
            como evidencia — nunca incluye la contraseña, sólo lo que
            el objetivo respondió.
    """

    def __init__(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        entries: Iterable[CredentialEntry],
        fetch: Callable[..., Optional[Response]],
        rate_limiter: Optional[HostRateLimiter] = None,
        max_attempts_per_account: int = 3,
        capture_evidence: bool = False,
    ) -> None:
        self._entries = list(entries)
        self._fetch = fetch
        self._rl = rate_limiter
        self._max_attempts = max(1, int(max_attempts_per_account))
        self._capture_evidence = capture_evidence

    def run(self, host: str, services: Iterable) -> List[dict]:
        """Probar cada entrada aplicable contra cada servicio del host.

        Args:
            host: El objetivo.
            services: Los servicios descubiertos del host.

        Returns:
            Un hallazgo por cada entrada que encontró una cuenta funcionando.
        """
        findings: List[dict] = []
        for service in services:
            for entry in self._entries:
                matches_service = _SERVICE_MATCHERS.get(entry.service)
                if matches_service is None or not matches_service(service):
                    continue
                finding = self._try_entry(host, service, entry)
                if finding is not None:
                    findings.append(finding)
        return findings

    def _try_entry(self, host: str, service, entry: CredentialEntry) -> Optional[dict]:
        """Probar las cuentas de una entrada contra un servicio, hasta el primer éxito.

        Cada intento se registra ocurra lo que ocurra — un informe que dice
        "se probaron credenciales por defecto y ninguna funcionó" es
        información tan válida como un hallazgo, y el silencio no distingue
        eso de "no se llegó a probar".
        """
        attempts_by_username: Dict[str, int] = {}
        for account in entry.accounts:
            used = attempts_by_username.get(account.username, 0)
            if used >= self._max_attempts:
                continue
            attempts_by_username[account.username] = used + 1

            if self._rl is not None:
                self._rl.acquire(host)
            logger.info(
                "Credenciales por defecto %s: intento %s/%s contra %s:%s con la cuenta %r",
                entry.check_id, used + 1, self._max_attempts, host, service.port, account.username,
            )
            response = self._fetch(
                host, service.port, entry.method, entry.path,
                None, _basic_auth_headers(account.username, account.password),
            )
            if response is None:
                continue
            if all(matcher.matches(response) for matcher in entry.matchers):
                return self._finding(entry, service, account, response)
        return None

    def _finding(self, entry: CredentialEntry, service, account: CredentialPair,
                 response: Response) -> dict:
        """Construir el hallazgo de un acceso logrado — sin la contraseña en ningún sitio."""
        finding_template = entry.finding
        finding = {
            "title": finding_template.get(
                "title", f"Credenciales por defecto: {entry.id} ({account.username})"),
            "category": "default_credentials",
            "port": service.port,
            "service": service.name or entry.service,
            "protocol": service.protocol,
            "cve_ids": None,
            "source": "lybra",
            "check_id": entry.check_id,
            "feed_version": entry.feed_version or CREDENTIALS_FEED_VERSION,
            "qod": QOD_CONFIRMED,
            "confirmed": True,
            "state": "open",
        }
        if self._capture_evidence:
            finding["_evidence"] = {
                "kind": "http_response",
                # Sólo lo que el objetivo respondió: la cabecera Authorization
                # que este módulo mandó nunca viaja aquí, así que la
                # contraseña no tiene forma de colarse en la evidencia.
                "payload": {
                    "status": response.status,
                    "headers": dict(response.headers),
                    "body": response.body,
                    "path": entry.path,
                    "username": account.username,
                },
            }
        return finding
