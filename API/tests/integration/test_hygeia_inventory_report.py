"""
Tests del informe PDF del inventario de activos de Hygeia.

Lo que de verdad importa aquí no es que el PDF salga bonito, sino **quién
aparece en él**: el ámbito de organización es la única excepción a la regla de
que una organización comparte plan y factura pero no datos
(``accounts/model.py``), y esa excepción tiene exactamente dos condiciones —
solo el dueño la puede usar, y solo alcanza a los miembros de su organización.

Las garantías de acceso se comprueban sobre el conjunto de activos que resuelve
el manager, no leyendo el PDF: así corren siempre, con o sin librería de
extracción instalada. La lectura del texto del PDF vive aparte y se salta sola
si no hay ``pypdf`` (no está en ``requirements.txt``).
"""

import secrets

import pytest

from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository
from src.modules.shared import utcnow_naive
from src.modules.accounts.model import Organization, OrganizationMember
from src.modules.features.hygeia.exceptions import OrganizationScopeNotAllowedError
from src.modules.features.hygeia.managers import HygeiaReportManager
from src.modules.features.hygeia.model import MonitoredAsset
from src.modules.features.hygeia.repositories import MonitoredAssetRepository
from src.modules.users.repositories import UserRepository

pytestmark = pytest.mark.integration


SOFTWARE = [
    {"name": f"Paquete {index}", "vendor": "ACME S.L.",
     "version": f"1.{index}.0", "architecture": "x64"}
    for index in range(40)
]


def _create_asset(app, user_id: int, hostname: str, with_software: bool = False) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            asset = MonitoredAsset(
                hostname=hostname,
                agent_key_id=secrets.token_hex(8),
                agent_key_hash="dummy",
                heartbeat_interval_sec=15,
                status="online",
                last_seen_at=utcnow_naive(),
                os="linux",
                inventory=SOFTWARE if with_software else None,
                user_id=user_id,
            )
            MonitoredAssetRepository(uow).save(asset)
            return asset.id


def _create_organization(app, owner_id: int, member_ids=(), name="Acme") -> int:
    """Crea la organización y sus filas de pertenencia sin pasar por la
    facturación: aquí se prueba el informe, no el alta de organizaciones."""
    with app.app_context():
        with UnitOfWork() as uow:
            organization = Organization(
                name=name, slug=f"{name.lower()}-{secrets.token_hex(3)}",
                owner_user_id=owner_id,
            )
            uow.session.add(organization)
            uow.session.flush()

            # El dueño es miembro de la suya, igual que en producción.
            uow.session.add(OrganizationMember(
                organization_id=organization.id, user_id=owner_id, member_role="owner",
            ))
            for member_id in member_ids:
                uow.session.add(OrganizationMember(
                    organization_id=organization.id, user_id=member_id, member_role="member",
                ))
            uow.session.flush()
            return organization.id


def _manager_for(user_handle) -> HygeiaReportManager:
    """El manager con el ``User`` real detrás. Debe llamarse dentro de un
    ``app.app_context()``: ``build_repository`` usa la sesión ambiental."""
    user = build_repository(UserRepository).get_by_id(user_handle.id)
    return HygeiaReportManager(user)


# ---------------------------------------------------------------------------
# Ámbito propio
# ---------------------------------------------------------------------------

def test_own_scope_returns_a_pdf(app, client, regular_user, auth_headers):
    _create_asset(app, regular_user.id, "web-01")

    resp = client.post(
        "/hygeia/inventory/report",
        json={"scope": "user"},
        headers=auth_headers(regular_user),
    )

    assert resp.status_code == 200
    assert resp.mimetype == "application/pdf"
    assert resp.data[:5] == b"%PDF-"


def test_a_user_without_assets_still_gets_a_document(client, regular_user, auth_headers):
    """Un inventario vacío es un hecho que se informa, no un error."""
    resp = client.post(
        "/hygeia/inventory/report", json={}, headers=auth_headers(regular_user),
    )

    assert resp.status_code == 200
    assert resp.data[:5] == b"%PDF-"


def test_the_software_annex_makes_the_document_bigger(app, client, regular_user, auth_headers):
    _create_asset(app, regular_user.id, "web-01", with_software=True)
    headers = auth_headers(regular_user)

    without = client.post("/hygeia/inventory/report",
                          json={"includeSoftware": False}, headers=headers)
    with_software = client.post("/hygeia/inventory/report",
                                json={"includeSoftware": True}, headers=headers)

    assert len(with_software.data) > len(without.data)


def test_an_unknown_scope_is_rejected(client, regular_user, auth_headers):
    resp = client.post(
        "/hygeia/inventory/report",
        json={"scope": "everyone"},
        headers=auth_headers(regular_user),
    )

    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Ámbito de organización: quién puede, y hasta dónde llega
# ---------------------------------------------------------------------------

def test_the_owner_gets_the_assets_of_every_member(app, make_user, auth_headers, client):
    owner = make_user()
    member = make_user()
    _create_organization(app, owner.id, [member.id])
    _create_asset(app, owner.id, "owner-host")
    _create_asset(app, member.id, "member-host")

    resp = client.post(
        "/hygeia/inventory/report",
        json={"scope": "organization"},
        headers=auth_headers(owner),
    )
    assert resp.status_code == 200

    # El conjunto exacto se comprueba sobre el manager: el PDF es la
    # presentación, esto es la garantía.
    with app.app_context():
        assets, label, owner_names = _manager_for(owner)._organization_scope()

    assert {asset.hostname for asset in assets} == {"owner-host", "member-host"}
    assert label == "Acme"
    assert set(owner_names) == {owner.id, member.id}


def test_a_member_who_is_not_the_owner_cannot_use_the_organization_scope(
    app, make_user, auth_headers, client,
):
    owner = make_user()
    member = make_user()
    _create_organization(app, owner.id, [member.id])

    resp = client.post(
        "/hygeia/inventory/report",
        json={"scope": "organization"},
        headers=auth_headers(member),
    )

    assert resp.status_code == 403


def test_a_user_without_an_organization_gets_the_same_refusal(
    make_user, auth_headers, client,
):
    """Mismo 403 que un miembro no dueño: distinguirlos diría si la
    organización existe y quién manda en ella."""
    lonely = make_user()

    resp = client.post(
        "/hygeia/inventory/report",
        json={"scope": "organization"},
        headers=auth_headers(lonely),
    )

    assert resp.status_code == 403


def test_assets_outside_the_organization_never_enter_the_report(
    app, make_user, auth_headers,
):
    owner = make_user()
    member = make_user()
    stranger = make_user()
    _create_organization(app, owner.id, [member.id])
    _create_asset(app, member.id, "member-host")
    _create_asset(app, stranger.id, "stranger-host")

    with app.app_context():
        assets, _label, _names = _manager_for(owner)._organization_scope()

    hostnames = {asset.hostname for asset in assets}
    assert "member-host" in hostnames
    assert "stranger-host" not in hostnames


def test_the_organization_scope_raises_the_typed_error(app, make_user):
    lonely = make_user()

    with app.app_context():
        with pytest.raises(OrganizationScopeNotAllowedError):
            _manager_for(lonely).build_inventory_report(
                scope="organization", include_software=False,
            )


# ---------------------------------------------------------------------------
# Contenido del PDF (se salta sin pypdf, que no está en requirements.txt)
# ---------------------------------------------------------------------------

def _pdf_text(data: bytes) -> str:
    pypdf = pytest.importorskip("pypdf")
    import io
    reader = pypdf.PdfReader(io.BytesIO(data))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def test_the_pdf_names_the_assets_it_covers(app, client, regular_user, auth_headers):
    _create_asset(app, regular_user.id, "inventariable-01")

    resp = client.post(
        "/hygeia/inventory/report", json={}, headers=auth_headers(regular_user),
    )
    text = _pdf_text(resp.data)

    assert "inventariable-01" in text
    assert "Mis activos" in text


def test_the_organization_pdf_names_the_organization_and_its_members(
    app, client, make_user, auth_headers,
):
    owner = make_user()
    member = make_user()
    _create_organization(app, owner.id, [member.id], name="Contoso")
    _create_asset(app, member.id, "de-otro-miembro")

    resp = client.post(
        "/hygeia/inventory/report",
        json={"scope": "organization"},
        headers=auth_headers(owner),
    )
    text = _pdf_text(resp.data)

    assert "Contoso" in text
    assert "de-otro-miembro" in text
