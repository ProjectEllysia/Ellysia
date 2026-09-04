"""Medición formal de precisión de las tres familias de la Fase R (roadmap §10).

El número que la Fase R pide para darse por cerrada es explícito: *"familias de
TLS, cabeceras y paths con precisión ≥ 0,9 medida contra el catálogo de imágenes
etiquetadas"*. Hasta ahora ``test_lybra_oracle_bench.py`` afirmaba
target-a-target ("en este contenedor debe salir este check"), que es una prueba
de regresión, no una medición: no producía ningún agregado, y sobre todo no
tenía **objetivos señuelo** — que son los únicos que pueden generar un falso
positivo y por tanto los únicos que hacen que el denominador signifique algo.

**El método.** Cada entrada del catálogo declara el conjunto **exacto** de
``check_id`` que debe disparar en esas tres familias. Sobre el agregado de todos
los objetivos:

    TP = disparó y estaba declarado      FP = disparó y NO estaba declarado
    FN = estaba declarado y no disparó
    precisión = TP / (TP + FP)           recall = TP / (TP + FN)

La aserción dura es solo sobre la precisión, que es lo que el roadmap fija como
umbral; el recall se mide y se imprime porque un banco con precisión perfecta y
recall ruinoso sería trivial de conseguir (no disparar nunca) y hay que poder
verlo.

**Los señuelos son la mitad del banco a propósito.** ``nginx-endurecido`` manda
la familia entera de cabeceras —la que declare el feed en cada momento, no una
lista fija: se quedó en tres cuando el feed pasó a seis y dejó de ser un control
negativo (#455)— y no debe producir ni un hallazgo de esa familia;
``nginx-decoys`` sirve un 200 en las seis rutas que los checks de ``exposed_path``
piden, pero con un cuerpo que no es lo que el check busca — un ``.git/config``
que no es un config de Git, un ``backup.sql`` que no es un volcado. Un check que
mirase solo el código de estado sacaría aquí seis falsos positivos de golpe.

Un único test y no uno por objetivo: la precisión es una propiedad del agregado,
y partirla en parametrize obligaría a acumular estado entre tests. El desglose
por objetivo se imprime igualmente (y va en el mensaje del fallo).

Requiere Docker, como el resto del paquete ``oracle``. Se salta entero si falta.
"""

from __future__ import annotations

import contextlib
import socket
import time
from dataclasses import dataclass, field
from typing import Iterator, Optional, Set

import pytest

from src.modules.features.themis.lybra.checks import HttpProbe, negotiates_tls

from ._security_headers import always_missing_header_checks
from ._docker_helpers import resolve_docker, docker_run, docker_rm, wait_for_port, port_is_free
from .test_lybra_oracle_bench import _run_self_discovery, _tls_container_cmd

pytestmark = [pytest.mark.oracle, pytest.mark.integration]

_DOCKER = resolve_docker()
pytestmark.append(pytest.mark.skipif(_DOCKER is None, reason="Docker no disponible"))

# Las tres familias que el número de la Fase R nombra. Todo lo demás que emita
# el motor (open_port, fingerprint, outdated_software...) queda fuera del
# cómputo: son otras fases y otros números.
_MEASURED_CATEGORIES = {"exposed_path", "security_header", "tls"}

_PRECISION_THRESHOLD = 0.9

# Un puerto de cada clase, reutilizado en serie: los contenedores se levantan y
# se tiran de uno en uno, así que no hace falta un pool. 8080 y 8443 son los que
# is_http_service()/is_tls_service() (checks.py) reconocen.
_HTTP_PORT = 8080
_TLS_PORT = 8443

# La familia de cabeceras se **deriva del feed**, no se escribe aquí. Estuvo
# escrita a mano, con tres identificadores, y cuando el feed creció (#296) nadie
# la actualizó: los tres checks nuevos —CSP, Referrer-Policy y
# Permissions-Policy— pasaron a contarse como falsos positivos en los diecisiete
# objetivos HTTP del catálogo y tumbaron la precisión de la Fase R a 0,557
# (#455). Ver ``_security_headers.py`` para la derivación y su única excepción.
_HEADERS = always_missing_header_checks()


def _serve(files: dict) -> str:
    """Comando de arranque de nginx que escribe ``files`` en el docroot.

    Los ficheros se crean **dentro** del contenedor, sin bind mount — la misma
    razón que ya documenta la fixture ``git_exposed_port``: evita depender de la
    traducción de rutas WSL↔Docker Desktop.
    """
    parts = []
    for path, body in files.items():
        parts.append(f"mkdir -p /usr/share/nginx/html/$(dirname {path})")
        parts.append(f"printf '%s' '{body}' > /usr/share/nginx/html/{path}")
    parts.append("nginx -g 'daemon off;'")
    return " && ".join(parts)


def _tls_serve(files: dict) -> str:
    """Como :func:`_serve`, pero sirviendo por HTTPS con un certificado propio.

    El certificado se genera dentro del contenedor al arrancar, igual que en
    ``_tls_container_cmd``; lo que cambia es que aquí el docroot lleva ficheros
    en vez de un ``return 200``.
    """
    parts = ["apk add --no-cache openssl >/dev/null 2>&1"]
    parts.append(
        "openssl req -x509 -nodes -days 365 -newkey rsa:2048 "
        "-keyout /etc/nginx/tls.key -out /etc/nginx/tls.crt "
        "-subj /CN=lybra-precision-tls >/dev/null 2>&1"
    )
    for path, body in files.items():
        parts.append(f"mkdir -p /usr/share/nginx/html/$(dirname {path})")
        parts.append(f"printf '%s' '{body}' > /usr/share/nginx/html/{path}")
    parts.append(
        "printf '%s' 'server { listen 443 ssl; ssl_certificate /etc/nginx/tls.crt; "
        "ssl_certificate_key /etc/nginx/tls.key; root /usr/share/nginx/html; }' "
        "> /etc/nginx/conf.d/default.conf"
    )
    parts.append("nginx -g 'daemon off;'")
    return " && ".join(parts)


# El control negativo del catálogo: un nginx que no debe producir ni un
# hallazgo. Manda la familia **entera** de cabeceras, no sólo las tres con
# las que se escribió: en cuanto el feed creció, un «endurecido» al que le
# faltaban tres cabeceras dejó de ser un control negativo y pasó a aportar
# tres falsos positivos él solo (#455).
_HARDENED_CONF = (
    "printf '%s' 'server { listen 80; "
    'add_header Strict-Transport-Security "max-age=31536000" always; '
    "add_header X-Frame-Options DENY always; "
    "add_header X-Content-Type-Options nosniff always; "
    # Los valores van sin comilla simple a propósito: toda la configuración
    # viaja dentro de una cadena de shell entrecomillada con comillas simples,
    # y una sola dentro la cerraría — el contenedor moriría al arrancar y sus
    # tres cabeceras que faltan parecerían un fallo del motor. La misma cautela
    # que ya documenta _redirect_conf(). Qué valor lleve la cabecera da igual:
    # estos checks juzgan que esté, no lo que dice.
    'add_header Content-Security-Policy "default-src https:" always; '
    "add_header Referrer-Policy no-referrer always; "
    'add_header Permissions-Policy "geolocation=(), camera=()" always; '
    'location / { return 200 "ok"; } }\' > /etc/nginx/conf.d/default.conf '
    "&& nginx -g 'daemon off;'"
)

# Rutas que los checks de exposed_path piden, servidas con un 200 y un cuerpo
# que NO es lo que el check busca. Cada una es una oportunidad de falso positivo.
_DECOY_FILES = {
    ".git/config": "no es un repositorio git, solo un fichero con este nombre",
    ".env": "esto no define ninguna variable de entorno",
    "phpinfo.php": "aqui no hay php",
    "wp-config.php": "no hay wordpress en este servidor",
    "id_rsa": "no es una clave",
    "backup.sql": "un fichero de texto cualquiera",
    "server-status": "no es mod_status",
}


# Los siete ficheros que los checks de ``exposed_path`` buscan, con el contenido
# que cada uno pide de verdad. Hasta ahora sólo tres de los siete llegaban a
# dispararse en el banco (git, dotenv y sql): los otros cuatro se medían
# únicamente por su ausencia, que no prueba que sepan reconocer lo que buscan.
_REAL_EXPOSURES = {
    ".git/config": "[core]\n\trepositoryformatversion = 0\n",
    ".env": "SECRET_KEY=abc123\nDB_PASSWORD=hunter2\n",
    "phpinfo.php": "<h1>phpinfo()</h1> PHP Version 8.1.2",
    "wp-config.php": "define(DB_NAME, wordpress); define(DB_PASSWORD, hunter2);",
    "id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n",
    "backup.sql": "-- MySQL dump 10.13\nCREATE TABLE users (id int);\nINSERT INTO users VALUES (1);\n",
    "server-status": "<h1>Apache Server Status for localhost</h1>",
}

_ALL_EXPOSURE_CHECKS = {
    "lybra:git-config-exposure@1",
    "lybra:dotenv-exposure@1",
    "lybra:phpinfo-exposure@1",
    "lybra:wpconfig-source-exposure@1",
    "lybra:ssh-private-key-exposure@1",
    "lybra:sql-backup-exposure@1",
    "lybra:apache-server-status-exposure@1",
}


def _catch_all(body: str, status: int = 200) -> str:
    """nginx que responde lo mismo a **cualquier** ruta.

    El señuelo más duro que existe para la familia ``exposed_path``: sus siete
    checks piden un 200 en una ruta concreta, y aquí todas devuelven 200. Lo
    único que puede salvar al motor de siete falsos positivos de golpe es que
    mire el cuerpo y no el código de estado.
    """
    return (
        "printf '%s' 'server { listen 80; "
        f'location / {{ return {status} "{body}"; }} }}\' > /etc/nginx/conf.d/default.conf '
        "&& nginx -g 'daemon off;'"
    )


# Un WAF delante no devuelve 404 a lo que bloquea: devuelve 200 con su propia
# página. Es el caso realista del catch-all, y el que más se parece a lo que un
# escáner encuentra en un despliegue de producción.
_WAF_BLOCK_PAGE = (
    "<html><head><title>Access Denied</title></head><body>"
    "Request blocked by security policy. Reference ID 8f21ac. "
    "If you believe this is an error, contact your administrator."
    "</body></html>"
)

# Un CDN por delante: cabeceras propias del proveedor, ninguna de seguridad.
_CDN_CONF = (
    "printf '%s' 'server { listen 80; "
    'add_header Server cloudflare always; '
    'add_header CF-RAY 8f21ac0000000000-MAD always; '
    'location / { return 200 "ok"; } }\' > /etc/nginx/conf.d/default.conf '
    "&& nginx -g 'daemon off;'"
)

# Un proxy inverso que reescribe cabeceras y pone **una** de las tres. El caso
# de despliegue real más frecuente, y el que distingue "el motor mira las
# cabeceras" de "el motor da por hecho que no hay ninguna".
_PARTIAL_HEADERS_CONF = (
    "printf '%s' 'server { listen 80; "
    'add_header X-Frame-Options SAMEORIGIN always; '
    'add_header X-Forwarded-Proto https always; '
    'location / { return 200 "ok"; } }\' > /etc/nginx/conf.d/default.conf '
    "&& nginx -g 'daemon off;'"
)

def _redirect_conf() -> str:
    """nginx que redirige la raíz a una página que sí sirve un 200.

    Sin comillas dentro de la configuración a propósito: van embebidas en una
    cadena de shell que a su vez va dentro de una cadena de Python, y la primera
    versión de esto llegaba a nginx con las comillas escapadas, la configuración
    no parseaba y el contenedor moría al arrancar. El síntoma era el peor
    posible — "conexión rechazada" en cada sonda, o sea tres falsos negativos
    que parecían un fallo del motor.
    """
    return (
        "printf '%s' 'server { listen 80; root /usr/share/nginx/html; "
        "location = / { return 301 /index.html; } }' > /etc/nginx/conf.d/default.conf "
        "&& nginx -g 'daemon off;'"
    )


# Autenticación delante: todo responde 401. Ni las rutas expuestas ni las
# cabeceras deben producir nada — el motor no ha llegado a ver ningún recurso.
_BASIC_AUTH_CONF = (
    "printf '%s' 'server { listen 80; "
    'location / { return 401 "authentication required"; } }\' '
    "> /etc/nginx/conf.d/default.conf && nginx -g 'daemon off;'"
)


@dataclass(frozen=True)
class Target:
    """Una imagen etiquetada del catálogo: qué se levanta y qué debe salir."""

    name: str
    image: str
    command: Optional[str]
    expected: Set[str] = field(default_factory=set)
    tls: bool = False

    @property
    def port(self) -> int:
        return _TLS_PORT if self.tls else _HTTP_PORT


# Nada de imágenes nuevas: nginx:alpine y httpd:2.4.49 son las que el banco de
# verdad-por-etiqueta ya usa. Lo que crece aquí es el número de *escenarios*,
# que es donde estaba la falta de escala, no el peso de descarga.
_CATALOGUE = (
    Target(
        name="nginx-vanilla",
        image="nginx:alpine",
        command=None,
        expected=set(_HEADERS),
    ),
    Target(
        name="nginx-git-expuesto",
        image="nginx:alpine",
        command=_serve({".git/config": "[core]\\n\\trepositoryformatversion = 0\\n"}),
        expected=_HEADERS | {"lybra:git-config-exposure@1"},
    ),
    Target(
        name="nginx-dotenv-expuesto",
        image="nginx:alpine",
        command=_serve({".env": "SECRET_KEY=abc123\\nDB_PASSWORD=hunter2\\n"}),
        expected=_HEADERS | {"lybra:dotenv-exposure@1"},
    ),
    Target(
        name="nginx-sql-expuesto",
        image="nginx:alpine",
        command=_serve({
            "backup.sql": "-- MySQL dump 10.13\\nCREATE TABLE users (id int);\\n"
                          "INSERT INTO users VALUES (1);\\n",
        }),
        expected=_HEADERS | {"lybra:sql-backup-exposure@1"},
    ),
    # --- señuelos: aquí no debe disparar nada de exposed_path/security_header ---
    Target(
        name="nginx-endurecido",
        image="nginx:alpine",
        command=_HARDENED_CONF,
        expected=set(),
    ),
    Target(
        name="nginx-senuelos",
        image="nginx:alpine",
        command=_serve(_DECOY_FILES),
        expected=set(_HEADERS),
    ),
    Target(
        name="httpd-2449",
        image="httpd:2.4.49",
        command=None,
        expected=set(_HEADERS),
    ),
    Target(
        name="nginx-todo-expuesto",
        image="nginx:alpine",
        command=_serve(_REAL_EXPOSURES),
        expected=_HEADERS | _ALL_EXPOSURE_CHECKS,
    ),
    Target(
        name="tls-todo-expuesto",
        image="nginx:alpine",
        # Las mismas siete rutas, pero servidas por HTTPS. Hasta ahora ningún
        # check de ``exposed_path`` se ejercitaba nunca sobre TLS, que es como
        # sirve la mayoría de los sitios reales — y es justo el camino donde la
        # detección de esquema por observación (#268) decide si la sonda habla
        # en claro o cifrado.
        command=_tls_serve(_REAL_EXPOSURES),
        expected=_HEADERS | _ALL_EXPOSURE_CHECKS | {"lybra:tls-self-signed-cert@1"},
        tls=True,
    ),
    # --- señuelos duros: un 200 en todas las rutas que los checks piden ---
    Target(
        name="nginx-catch-all",
        image="nginx:alpine",
        command=_catch_all("ok"),
        expected=set(_HEADERS),
    ),
    Target(
        name="nginx-waf",
        image="nginx:alpine",
        command=_catch_all(_WAF_BLOCK_PAGE),
        expected=set(_HEADERS),
    ),
    Target(
        name="nginx-git-vacio",
        image="nginx:alpine",
        command=_serve({".git/config": ""}),
        expected=set(_HEADERS),
    ),
    Target(
        name="nginx-env-documentado",
        image="nginx:alpine",
        # Un .env de ejemplo, con instrucciones en vez de variables: el nombre y
        # el 200 son idénticos a los del caso real, y sólo el anclaje de la
        # expresión regular (mayúscula al principio de línea) los separa.
        command=_serve({".env": "copia este fichero y rellena los valores antes de desplegar"}),
        expected=set(_HEADERS),
    ),
    Target(
        name="nginx-auth-basica",
        image="nginx:alpine",
        command=_BASIC_AUTH_CONF,
        expected=set(),
    ),
    # --- variación de despliegue real ---
    Target(
        name="nginx-tras-cdn",
        image="nginx:alpine",
        command=_CDN_CONF,
        expected=set(_HEADERS),
    ),
    Target(
        name="nginx-cabeceras-parciales",
        image="nginx:alpine",
        command=_PARTIAL_HEADERS_CONF,
        # Manda X-Frame-Options y nada más, así que espera todo el resto de
        # la familia. Se calcula restando en vez de enumerarse, para que crezca
        # sola con el feed.
        expected=_HEADERS - {"lybra:missing-x-frame-options-header@1"},
    ),
    Target(
        name="nginx-redirige",
        image="nginx:alpine",
        # HTTP -> otra ruta. La sonda sigue la redirección, así que lo que se
        # juzga son las cabeceras del destino, no las del 301: el caso realista
        # de un sitio que redirige a su portada.
        command=_redirect_conf(),
        expected=set(_HEADERS),
    ),
    # --- familia tls ---
    Target(
        name="tls-autofirmado",
        image="nginx:alpine",
        command=_tls_container_cmd(days=365, expired=False),
        expected=_HEADERS | {"lybra:tls-self-signed-cert@1"},
        tls=True,
    ),
    Target(
        name="tls-caducado",
        image="nginx:alpine",
        command=_tls_container_cmd(days=30, expired=True),
        expected=_HEADERS | {"lybra:tls-self-signed-cert@1", "lybra:tls-expired-cert@1"},
        tls=True,
    ),
)


def _wait_until_serving(port: int, tls: bool, label: str = "", timeout: float = 180.0) -> None:
    """Esperar a que el servidor conteste **su protocolo**, no a que el puerto acepte.

    El proxy de Docker acepta la conexión TCP en cuanto existe la red del
    contenedor, mucho antes de que nginx haya terminado de arrancar — y estos
    objetivos hacen ``apk add`` y generan un certificado antes de servir nada.
    ``wait_for_port`` da por listo un contenedor que todavía se está instalando.

    Eso no producía un error sino una **medición de menos**, que es peor. El
    motor recorre las familias en orden: la sonda HTTP salía primero, fallaba
    contra un servidor que aún no existía y devolvía ``None`` —ningún check de
    cabeceras podía dispararse—, y cuando un segundo después le tocaba a la
    sonda TLS, nginx ya estaba en pie y el check de certificado sí funcionaba.
    El banco reportaba tres falsos negativos por objetivo TLS y ningún fallo.

    Es la tercera vez que esta carrera muerde en este paquete (#265, L49), y
    siempre con la misma cara: se lee como "el motor no detectó".

    La comprobación es deliberadamente **cruda** —un socket y una línea de
    estado, o un handshake TLS— y no reutiliza ``HttpProbe``: el arnés no puede
    decidir si un objetivo está listo usando la misma pieza que está midiendo.
    Un objetivo que redirige la raíz demostró justo eso, porque ``HttpProbe``
    no le devuelve nada (ver ``test_a_redirecting_root_still_gets_judged``).
    """
    deadline = time.monotonic() + timeout
    last = "sin intentos"
    while time.monotonic() < deadline:
        try:
            if tls:
                if negotiates_tls("127.0.0.1", port, timeout=3.0):
                    return
                last = "el puerto acepta pero todavía no habla TLS"
            else:
                with socket.create_connection(("127.0.0.1", port), timeout=3.0) as sock:
                    sock.sendall(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
                    if sock.recv(16).startswith(b"HTTP/"):
                        return
                last = "responde algo que no es HTTP"
        except OSError as exc:
            last = str(exc)
        time.sleep(1.0)
    raise TimeoutError(f"[{label}] 127.0.0.1:{port} aceptó pero no sirvió su protocolo en {timeout}s ({last})")


@contextlib.contextmanager
def _running(target: Target) -> Iterator[int]:
    """Levanta el contenedor de ``target``, espera a su puerto y lo tira al salir."""
    port = target.port
    if not port_is_free("127.0.0.1", port):
        raise RuntimeError(f"El puerto {port} está ocupado; el banco lo necesita libre")

    name = f"lybra-precision-{target.name}"
    docker_rm(_DOCKER, name)  # restos de una corrida anterior interrumpida
    args = ["run", "-d", "--name", name, "-p", f"{port}:{443 if target.tls else 80}", target.image]
    if target.command:
        args += ["sh", "-c", target.command]
    docker_run(_DOCKER, *args)
    try:
        wait_for_port("127.0.0.1", port)
        _wait_until_serving(port, tls=target.tls, label=target.name)
        yield port
    finally:
        docker_rm(_DOCKER, name)


def _measured_check_ids(findings) -> Set[str]:
    """``check_id`` de los hallazgos **observados** en las tres familias medidas.

    Los de estado ``fixed`` se excluyen, y no es un detalle: los nueve objetivos
    del catálogo comparten IP (127.0.0.1) y por tanto el mismo ``Host``, así que
    ``apply_lifecycle`` (Fase 5) arrastra a cada escaneo un hallazgo fantasma por
    cada uno del escaneo anterior que ya no está, precisamente para dejar
    constancia de la remediación. Contarlos como detecciones convertiría el
    ciclo de vida —que funciona— en seis falsos positivos inventados por el
    banco. ``fixed`` significa literalmente "no observado ahora".
    """
    return {
        f.check_id for f in findings
        if f.category in _MEASURED_CATEGORIES and f.check_id and f.state != "fixed"
    }


def test_fase_r_precision_over_labelled_catalogue(app, admin_user, monkeypatch):
    """El número de la Fase R: precisión ≥ 0,9 sobre el catálogo etiquetado."""
    true_positives = false_positives = false_negatives = 0
    breakdown = []

    for target in _CATALOGUE:
        with _running(target) as port:
            findings = _run_self_discovery(app, admin_user, "127.0.0.1", port, monkeypatch)

        fired = _measured_check_ids(findings)
        hits = fired & target.expected
        spurious = fired - target.expected
        missed = target.expected - fired

        true_positives += len(hits)
        false_positives += len(spurious)
        false_negatives += len(missed)
        breakdown.append(
            f"  {target.name:<22} TP={len(hits)} FP={len(spurious)} FN={len(missed)}"
            + (f"  falsos+: {sorted(spurious)}" if spurious else "")
            + (f"  perdidos: {sorted(missed)}" if missed else "")
        )

    detected = true_positives + false_positives
    assert detected, "el banco no produjo ni un hallazgo: mide la tubería, no el motor"

    precision = true_positives / detected
    recall = true_positives / (true_positives + false_negatives) if true_positives + false_negatives else 0.0

    report = (
        "\n[precisión Fase R] catálogo de "
        f"{len(_CATALOGUE)} objetivos etiquetados, familias {sorted(_MEASURED_CATEGORIES)}\n"
        + "\n".join(breakdown)
        + f"\n  TOTAL  TP={true_positives} FP={false_positives} FN={false_negatives}"
        + f"\n  precisión = {precision:.3f}   (umbral {_PRECISION_THRESHOLD})"
        + f"\n  recall    = {recall:.3f}\n"
    )
    print(report)

    assert precision >= _PRECISION_THRESHOLD, report

    # Y, por encima del umbral del roadmap, un guardarraíl contra la deriva.
    #
    # El 0,9 se fijó cuando el banco tenía 30 detecciones. Con 68 hacen falta
    # más de siete falsos positivos para bajar de ahí, así que una regresión
    # pequeña —un matcher que se relaja, un check nuevo mal escrito— pasaría
    # inadvertida mientras el número sigue "por encima del umbral". Comprobado
    # a mano: relajar tres matchers a propósito produjo falsos positivos y el
    # test seguía en verde.
    #
    # El valor medido es 0 desde que existe el banco, así que cualquier falso
    # positivo es una regresión y no ruido. Un banco que no puede ponerse rojo
    # no protege de nada.
    assert false_positives == 0, report


@pytest.mark.xfail(strict=True, reason=(
    "HttpProbe.fetch devuelve None contra un servidor cuya raíz redirige, así "
    "que ninguno de los tres checks de cabeceras llega a evaluarse. Que el feed "
    "acepte 301 y 302 como estados válidos demuestra que la intención era "
    "justamente juzgarlos. El efecto es un punto ciego grande y silencioso: un "
    "sitio que redirige la raíz —HTTP a HTTPS, / a /login, apex a www— no "
    "recibe ni un hallazgo de esta familia, y el escaneo termina en verde."
))
def test_a_redirecting_root_still_gets_judged(app, admin_user, monkeypatch):
    """El caso de despliegue más común que el catálogo destapó.

    Se prueba aparte y no dentro del agregado porque es un fallo de la **sonda**,
    no de los checks: los tres se evalúan bien en cuanto reciben una respuesta.
    Dentro del cómputo sería un falso negativo más entre otros; aquí es una
    afirmación con nombre que se pondrá en verde el día que se arregle.
    """
    target = next(item for item in _CATALOGUE if item.name == "nginx-redirige")
    with _running(target) as port:
        findings = _run_self_discovery(app, admin_user, "127.0.0.1", port, monkeypatch)
    assert _measured_check_ids(findings) >= _HEADERS
