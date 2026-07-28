"""
Tests de integración de la Fase I: el inventario de Hygeia como entrada del
motor Lybra.

Es el primer punto del backend donde dos módulos de ``features/`` se tocan,
así que lo que se verifica aquí no es solo el camino feliz sino el contrato
entre ambos: que el análisis nunca sale a la red, que los escaneos de agente
no contaminan la feed normal de Themis, que el ciclo de vida sigue vivo entre
re-análisis, y que borrar un activo no deja escaneos huérfanos.
"""

from unittest import mock

import pytest

from src.modules.infrastructure import UnitOfWork
from src.modules.features.hygeia import managers as hygeia_managers
from src.modules.features.hygeia.managers import HygeiaAssetManager
from src.modules.features.hygeia.repositories import MonitoredAssetRepository
from src.modules.features.themis.managers import LybraEngineManager
from src.modules.features.themis.model import ScanStatus
from src.modules.features.themis.repositories import KbRepository, ScanRepository

pytestmark = pytest.mark.integration


class _FakeTaskQueue:
    """La TaskQueue real necesita Redis; aquí el cuerpo del escaneo se ejecuta
    a mano (``_run_lybra``), igual que en el resto de tests de Lybra."""

    def submit(self, **kwargs):
        return None


@pytest.fixture(autouse=True)
def _fake_task_queue():
    with mock.patch.object(hygeia_managers.TaskQueue, "get_instance", return_value=_FakeTaskQueue()):
        yield


def _software(name, version, vendor="ACME"):
    return {"name": name, "version": version, "vendor": vendor, "type": "EXE", "source": "registry"}


def _create_asset(app, user, hostname="agent-host", inventory=None):
    """Da de alta un activo y le inyecta un inventario directamente.

    Se escribe en la fila en vez de mandar un heartbeat porque lo que estos
    tests ejercitan es el análisis, no la ingesta (que ya tiene los suyos en
    ``test_hygeia_inventory.py``).
    """
    with app.app_context():
        result = HygeiaAssetManager(user).create_asset(hostname=hostname, os_name="windows", labels={})
        asset_id = result["asset"]["id"]
        if inventory is not None:
            with UnitOfWork() as uow:
                repo = MonitoredAssetRepository(uow)
                asset = repo.get_by_id(asset_id)
                asset.inventory = inventory
                repo.update(asset)
    return asset_id


def _seed_kb_apache_cve(app):
    """CVE-2021-41773 para apache http_server 2.4.49, la misma que usan los
    tests de Lybra — así el matcher tiene algo real que encontrar."""
    with app.app_context():
        with UnitOfWork() as uow:
            KbRepository(uow).upsert_cve(
                {"cve_id": "CVE-2021-41773", "cvss_score": 9.8,
                 "cvss_vector": "CVSS:3.1/AV:N", "severity": "CRITICAL",
                 "description": "Path traversal", "cwe_ids": ["CWE-22"], "source": "nvd"},
                [{"vendor": "apache", "product": "http_server", "exact_version": "2.4.49",
                  "version_start_including": None, "version_start_excluding": None,
                  "version_end_including": None, "version_end_excluding": None}],
            )


def _run_pending_scan(app, scan_id, services):
    """Ejecuta el cuerpo del escaneo que la TaskQueue falsa no encoló."""
    with app.app_context():
        LybraEngineManager()._run_lybra(scan_id, source_scan_id=None, discover_ports=None,
                                       deep=False, services_payload=services)


def _analyze(app, user, asset_id):
    """Lanza el análisis y ejecuta su cuerpo, devolviendo el id del escaneo."""
    with app.app_context():
        result = HygeiaAssetManager(user).analyze_inventory(asset_id)
        scan_id = result["scanId"]
        with UnitOfWork() as uow:
            asset = MonitoredAssetRepository(uow).get_by_id(asset_id)
            inventory = list(asset.inventory or [])
    from src.modules.features.hygeia.services import services_from_inventory
    _run_pending_scan(app, scan_id, services_from_inventory(inventory))
    return scan_id


# ----------------------------------------------------------------- camino feliz

def test_inventory_analysis_produces_confirmed_cve_findings(app, admin_user):
    """El objetivo de toda la fase: paquetes instalados → CVEs, con la
    confianza alta que merece un dato leído del propio host (no un banner)."""
    _seed_kb_apache_cve(app)
    asset_id = _create_asset(app, admin_user, inventory=[
        _software("Apache httpd", "2.4.49"),
        _software("openssl", "1.1.1"),
    ])

    scan_id = _analyze(app, admin_user, asset_id)

    with app.app_context():
        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            scan = repo.get_by_id(scan_id)
            findings = repo.get_findings_by_scan(scan_id)

    assert scan.status == ScanStatus.FINISHED.value
    assert scan.asset_id == asset_id          # marcado como originado en Hygeia
    assert scan.target == "agent-host"

    vulns = [f for f in findings if f.category == "outdated_software"]
    assert len(vulns) == 1
    assert vulns[0].cve_ids == ["CVE-2021-41773"]
    assert vulns[0].qod == 95                  # dato verificado, no hipótesis por banner
    assert vulns[0].confirmed is True

    # Los paquetes sin CVE conocida quedan como inventario informativo, sin puerto.
    packages = [f for f in findings if f.category == "installed_package"]
    assert any("openssl 1.1.1" in f.title for f in packages)
    assert all(f.port is None for f in packages)


def test_analysis_never_touches_the_targets_network(app, admin_user):
    """La garantía que hace viable analizar un host tras NAT: el modo payload
    no hace fingerprinting ni comprobaciones activas, pase lo que pase."""
    def _boom(*_a, **_k):
        raise AssertionError("un análisis de inventario no debe tocar la red del activo")

    asset_id = _create_asset(app, admin_user, inventory=[_software("Apache httpd", "2.4.49")])

    with mock.patch.object(LybraEngineManager, "_fingerprint_services", _boom), \
         mock.patch.object(LybraEngineManager, "_run_active_checks", _boom), \
         mock.patch.object(LybraEngineManager, "_discover_ports", _boom):
        scan_id = _analyze(app, admin_user, asset_id)

    with app.app_context():
        with UnitOfWork() as uow:
            assert ScanRepository(uow).get_by_id(scan_id).status == ScanStatus.FINISHED.value


# ------------------------------------------------------------ separación de feeds

def test_agent_scans_stay_out_of_the_panel_feed(client, app, admin_user, auth_headers):
    """Requisito explícito: un escaneo lanzado desde Hygeia no aparece mezclado
    con los que el usuario lanzó a mano desde el panel de Themis."""
    asset_id = _create_asset(app, admin_user, inventory=[_software("Apache httpd", "2.4.49")])
    agent_scan_id = _analyze(app, admin_user, asset_id)

    # Un escaneo Lybra "de panel" sobre el mismo usuario, por payload directo.
    with app.app_context():
        from src.modules.features.themis.lybra import Service
        panel_scan = LybraEngineManager()._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        panel_scan_id = panel_scan.id
    _run_pending_scan(app, panel_scan_id,
                      [Service(port=None, protocol="", product="curl", version="7.68.0", origin="inventory")])

    headers = auth_headers(admin_user)
    panel = client.get("/themis/results?type=lybra", headers=headers).get_json()
    assert [s["id"] for s in panel["results"]] == [panel_scan_id]

    agent = client.get(f"/themis/results?type=lybra&assetId={asset_id}", headers=headers).get_json()
    assert [s["id"] for s in agent["results"]] == [agent_scan_id]
    assert agent["results"][0]["assetId"] == asset_id


# ------------------------------------------------------------------ ciclo de vida

def test_reanalysis_keeps_history_and_marks_removed_packages_fixed(app, admin_user):
    """La razón por la que "volver a analizar" NO borra el análisis anterior:
    sin el escaneo previo, un paquete desinstalado nunca se marcaría corregido."""
    _seed_kb_apache_cve(app)
    asset_id = _create_asset(app, admin_user, inventory=[
        _software("Apache httpd", "2.4.49"),
        _software("curl", "7.68.0"),
    ])
    first_scan_id = _analyze(app, admin_user, asset_id)

    # El activo se actualiza: Apache ya no está instalado.
    with app.app_context():
        with UnitOfWork() as uow:
            repo = MonitoredAssetRepository(uow)
            asset = repo.get_by_id(asset_id)
            asset.inventory = [_software("curl", "7.68.0")]
            repo.update(asset)

    second_scan_id = _analyze(app, admin_user, asset_id)

    assert second_scan_id != first_scan_id
    with app.app_context():
        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            assert repo.get_by_id(first_scan_id) is not None      # el anterior se conserva
            findings = repo.get_findings_by_scan(second_scan_id)

    fixed = [f for f in findings if f.state == "fixed"]
    assert any(f.cve_ids == ["CVE-2021-41773"] for f in fixed)


# -------------------------------------------------------------------- exposición

def test_inventory_scan_is_scored_as_private_exposure(app, admin_user):
    """Un hostname pelado ('agent-host') no lleva sufijo interno, así que
    `classify_exposure` lo llamaría "public" e inflaría una banda toda la
    prioridad. Un escaneo de inventario no observa la red: va como privado."""
    _seed_kb_apache_cve(app)   # CVSS 9.8 -> CRITICAL si la exposición fuera pública
    asset_id = _create_asset(app, admin_user, inventory=[_software("Apache httpd", "2.4.49")])
    scan_id = _analyze(app, admin_user, asset_id)

    with app.app_context():
        formatted = LybraEngineManager().format_scan(scan_id)

    assert formatted["exposure"] == "private"
    vuln = next(f for f in formatted["findings"] if f["cveIds"] == ["CVE-2021-41773"])
    assert vuln["priority"] == "HIGH"   # topado por ser privado, no CRITICAL


# ----------------------------------------------------------------------- cascada

def test_deleting_an_asset_deletes_its_lybra_scans(app, admin_user):
    """`LybraScan.asset_id` no tiene ForeignKey, así que la limpieza es
    explícita — si se rompe, quedan escaneos apuntando a un activo inexistente."""
    asset_id = _create_asset(app, admin_user, inventory=[_software("Apache httpd", "2.4.49")])
    scan_id = _analyze(app, admin_user, asset_id)

    with app.app_context():
        HygeiaAssetManager(admin_user).delete_asset(asset_id)
        with UnitOfWork() as uow:
            assert ScanRepository(uow).get_by_id(scan_id) is None


# ------------------------------------------------------------------------ guardas

def test_analyze_without_inventory_is_409(client, app, admin_user, auth_headers):
    asset_id = _create_asset(app, admin_user)   # nunca reportó inventario

    resp = client.post(f"/hygeia/assets/{asset_id}/analyze", headers=auth_headers(admin_user))
    assert resp.status_code == 409


def test_analyze_inventory_without_versions_is_409(client, app, admin_user, auth_headers):
    """Sin versión no hay CPE que resolver: el análisis no produciría ni una
    detección, así que se rechaza en vez de crear un escaneo vacío."""
    asset_id = _create_asset(app, admin_user, inventory=[
        {"name": "Some Package", "version": None, "vendor": "ACME"},
    ])

    resp = client.post(f"/hygeia/assets/{asset_id}/analyze", headers=auth_headers(admin_user))
    assert resp.status_code == 409


def test_analyze_another_users_asset_is_404(client, app, make_user, auth_headers):
    """Ambos usuarios tienen permiso para analizar: lo que separa a uno del
    activo del otro es la propiedad, no el rol — si el intruso no tuviera el
    atributo, el 403 llegaría antes y el test no probaría el aislamiento."""
    owner = make_user(role="role_admin")
    intruder = make_user(role="role_admin")
    asset_id = _create_asset(app, owner, inventory=[_software("Apache httpd", "2.4.49")])

    resp = client.post(f"/hygeia/assets/{asset_id}/analyze", headers=auth_headers(intruder))
    assert resp.status_code == 404


def test_analyze_requires_themis_create(client, app, regular_user, auth_headers):
    """La acción crea un escaneo de Themis: quien no puede lanzarlos allí
    tampoco debe poder hacerlo por la puerta de Hygeia."""
    asset_id = _create_asset(app, regular_user, inventory=[_software("Apache httpd", "2.4.49")])

    resp = client.post(f"/hygeia/assets/{asset_id}/analyze", headers=auth_headers(regular_user))
    assert resp.status_code == 403


# ------------------------------------------------------------------------ resumen

def test_analysis_summary_before_and_after(client, app, admin_user, auth_headers):
    _seed_kb_apache_cve(app)
    asset_id = _create_asset(app, admin_user, inventory=[_software("Apache httpd", "2.4.49")])

    before = client.get(f"/hygeia/assets/{asset_id}/analysis", headers=auth_headers(admin_user))
    assert before.status_code == 200
    assert before.get_json()["scanId"] is None

    scan_id = _analyze(app, admin_user, asset_id)

    after = client.get(f"/hygeia/assets/{asset_id}/analysis", headers=auth_headers(admin_user)).get_json()
    assert after["scanId"] == scan_id
    assert after["status"] == ScanStatus.FINISHED.value
    assert after["totalFindings"] >= 1
    assert after["vulnerableCount"] == 1
    assert after["byPriority"].get("HIGH") == 1
