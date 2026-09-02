"""APIs de administración expuestas sin autenticar (L17).

Docker en 2375, Elasticsearch en 9200, Kubernetes en 6443: servicios que hablan
HTTP, publican su versión en un JSON sin credenciales, y cuya sola exposición
es el hallazgo más grave que un escáner puede dar. El motor ya escaneaba esos
puertos y hasta los llamaba por su nombre; lo que no hacía era preguntarles
nada.
"""

import json

import pytest

from src.modules.features.themis.lybra.checks import (
    Response,
    is_admin_api_service,
    is_docker_service,
    is_http_service,
    load_checks,
)
from src.modules.features.themis.lybra.engine import Service
from src.modules.features.themis.lybra.fingerprinting import default_dissectors
from src.modules.features.themis.lybra.fingerprinting.http_apis import (
    ADMIN_APIS,
    AdminApiDissector,
    fingerprint_admin_api,
)

pytestmark = pytest.mark.unit


def _json_response(payload, status=200):
    return Response(status, json.dumps(payload), {"content-type": "application/json"})


# ================================================= extracción de versión


def test_docker_version_endpoint():
    body = {"Version": "24.0.7", "ApiVersion": "1.43", "GoVersion": "go1.20.10"}
    result = fingerprint_admin_api(2375, _json_response(body))
    assert (result.product, result.version) == ("Docker", "24.0.7")


def test_elasticsearch_root_endpoint():
    body = {"name": "node-1", "cluster_name": "docker-cluster",
            "version": {"number": "8.11.3", "build_flavor": "default"}}
    result = fingerprint_admin_api(9200, _json_response(body))
    assert (result.product, result.version) == ("Elasticsearch", "8.11.3")


def test_kibana_status_endpoint():
    body = {"name": "kibana", "version": {"number": "8.11.3", "build_number": 12345}}
    result = fingerprint_admin_api(5601, _json_response(body))
    assert (result.product, result.version) == ("Kibana", "8.11.3")


def test_kubernetes_version_endpoint_drops_the_leading_v():
    """Kubernetes publica `v1.28.4`. La `v` sobra para buscar un CPE, y dejarla
    haría que `1.28.4` y `v1.28.4` fueran dos versiones distintas."""
    body = {"major": "1", "minor": "28", "gitVersion": "v1.28.4",
            "platform": "linux/amd64"}
    result = fingerprint_admin_api(6443, _json_response(body))
    assert (result.product, result.version) == ("Kubernetes", "1.28.4")


def test_etcd_version_endpoint():
    body = {"etcdserver": "3.5.9", "etcdcluster": "3.5.0"}
    result = fingerprint_admin_api(2379, _json_response(body))
    assert (result.product, result.version) == ("etcd", "3.5.9")


def test_consul_agent_endpoint():
    body = {"Config": {"Datacenter": "dc1", "Version": "1.17.1"}}
    result = fingerprint_admin_api(8500, _json_response(body))
    assert (result.product, result.version) == ("Consul", "1.17.1")


# ============================================ lo que NO debe identificar


def test_an_authenticated_api_is_not_an_identification():
    """El caso que separa un hallazgo de un servicio bien configurado. Un 401 o
    un 403 significan que el servicio está ahí y pide credenciales — que es
    como debe estar — así que no hay versión observada ni exposición ninguna."""
    for status in (401, 403):
        body = {"message": "missing authentication credentials"}
        assert fingerprint_admin_api(9200, _json_response(body, status)) is None


def test_a_body_that_is_not_json_is_not_guessed():
    assert fingerprint_admin_api(2375, Response(200, "<html>hola</html>", {})) is None


def test_a_json_without_the_expected_field_yields_nothing():
    assert fingerprint_admin_api(9200, _json_response({"name": "node-1"})) is None


def test_a_failed_request_yields_nothing():
    assert fingerprint_admin_api(2375, None) is None


def test_a_port_outside_the_map_yields_nothing():
    assert fingerprint_admin_api(80, _json_response({"Version": "24.0.7"})) is None


# ============================================== selección de dissector


def test_the_admin_ports_are_now_part_of_the_http_family():
    """Sin esto, `is_http_service` rechazaba el 2375 y el 9200, y ni los checks
    de exposición ni los de higiene de certificado los tocaban."""
    for port in ADMIN_APIS:
        assert is_http_service(Service(port, "tcp", ""))


def test_the_admin_api_dissector_is_asked_before_the_generic_http_one():
    """El orden del registro importa desde que los predicados se solapan: el
    motor se queda con el primero que aplique, y si ganara la sonda HTTP
    genérica leería una cabecera `Server` en vez de la versión del JSON."""
    labels = [dissector.label for dissector in default_dissectors()]
    assert labels.index("Admin API") < labels.index("HTTP")


def test_the_dissector_only_claims_the_ports_in_its_map():
    dissector = AdminApiDissector()
    assert dissector.applies(Service(2375, "tcp", ""))
    assert dissector.applies(Service(9200, "tcp", ""))
    assert not dissector.applies(Service(80, "tcp", "http"))
    assert not dissector.applies(Service(8080, "tcp", "http-proxy"))


def test_kubernetes_insecure_8080_is_left_to_the_generic_http_probe():
    """El 8080 es también el puerto HTTP alternativo más común que existe.
    Reclamarlo aquí le quitaría a la sonda genérica un puerto que casi siempre
    es un servidor web corriente."""
    assert not is_admin_api_service(Service(8080, "tcp", ""))


def test_the_dissector_asks_one_path_per_port():
    """Un mapa puerto→API, no seis rutas contra los seis puertos."""
    asked = []

    class _Probe:
        def fetch(self, host, port, method, path):
            asked.append((port, path))
            return _json_response({"Version": "24.0.7"})

    class _NullLimiter:
        def acquire(self, host):
            pass

    result = AdminApiDissector(probe=_Probe()).probe(
        "10.0.0.5", Service(2375, "tcp", "docker"), _NullLimiter())
    assert asked == [(2375, "/version")]
    assert (result.product, result.version) == ("Docker", "24.0.7")


# ================================================ los checks del feed


@pytest.fixture(scope="module")
def feed():
    return {check.id: check for check in load_checks()}


@pytest.mark.parametrize("check_id, service", [
    ("docker-api-unauthenticated", "docker"),
    ("elasticsearch-unauthenticated", "elasticsearch"),
    ("kubernetes-anonymous-api", "kubernetes"),
])
def test_the_exposure_checks_are_critical_safe_and_service_scoped(feed, check_id, service):
    check = feed[check_id]
    assert check.severity == "CRITICAL"
    assert check.mode == "safe"          # todo son GET, lecturas puras
    assert check.service == service      # una petición por producto, no seis
    assert check.category == "exposed_service"


@pytest.mark.parametrize("check_id", [
    "docker-api-unauthenticated",
    "elasticsearch-unauthenticated",
    "kubernetes-anonymous-api",
])
def test_the_exposure_checks_require_a_200_so_a_401_never_fires(feed, check_id):
    """La mitad del check que evita el falso positivo: sin exigir 200, un 401
    con un cuerpo JSON que mencionara el producto dispararía un CRITICAL contra
    un servicio correctamente autenticado."""
    request = feed[check_id].requests[0]
    status_matchers = [m for m in request.matchers if m.type == "status"]
    assert status_matchers, f"{check_id} no exige código de estado"
    assert all(200 in m.values for m in status_matchers)
    assert request.method == "GET"


def test_every_admin_api_has_a_service_predicate():
    """Un check declara su protocolo como cadena y el runtime necesita el
    predicado que decide si un servicio descubierto *es* ese protocolo. El mapa
    se deriva de los nombres de función, así que basta con definirlas."""
    from src.modules.features.themis.lybra.checks import _NETWORK_SERVICE_MATCHERS

    assert {"docker", "elasticsearch", "kibana",
            "kubernetes", "etcd", "consul"} <= set(_NETWORK_SERVICE_MATCHERS)
    assert is_docker_service(Service(2375, "tcp", ""))
