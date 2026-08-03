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

**Los señuelos son la mitad del banco a propósito.** ``nginx-hardened`` manda
las tres cabeceras y no debe producir ni un hallazgo de esa familia;
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
from dataclasses import dataclass, field
from typing import Iterator, Optional, Set

import pytest

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

_HEADERS = {
    "lybra:missing-hsts-header@1",
    "lybra:missing-x-frame-options-header@1",
    "lybra:missing-x-content-type-options-header@1",
}


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


_HARDENED_CONF = (
    "printf '%s' 'server { listen 80; "
    'add_header Strict-Transport-Security "max-age=31536000" always; '
    "add_header X-Frame-Options DENY always; "
    "add_header X-Content-Type-Options nosniff always; "
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
