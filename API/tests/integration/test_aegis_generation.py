"""Tests del flujo de generación de una píldora de Aegis.

Cubren la invariante que da sentido a los avisos de seguridad: **llegan al
modelo antes de que escriba**. Durante mucho tiempo se traían justo después
de generar, así que no podían influir en una sola frase del contenido y
acababan de apéndice decorativo al final del documento.

Ni el modelo ni las fuentes externas se tocan: ``AegisManager`` acepta
``ai_writer`` y ``alert_fetcher`` inyectados (mismo patrón que ``task_queue``
o que el ``mailer`` de las campañas), así que aquí van dobles que registran
lo que reciben.
"""

from __future__ import annotations

import pytest

from src.modules.features.aegis.managers import AegisManager
from src.modules.features.aegis.services.pills import (
    AegisAlert,
    AegisContent,
    AegisTipData,
    AlertSource,
)

pytestmark = pytest.mark.integration


ADVISORY = AegisAlert(
    title="CVE-2024-1234 — Microsoft Windows",
    description="Remote code execution in the print spooler.",
    url="https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
    source=AlertSource.INCIBE,
    published="2024-03-01",
    severity="crítica",
    brands=["Microsoft"],
)


class _RecordingFetcher:
    """Doble del fetcher que anota cuándo se le llamó y con qué."""

    def __init__(self, calls: list[str]) -> None:
        self._calls = calls
        self.received_products: list[dict] | None = None

    def fetch_alerts(self, products, max_per_product=2):
        self._calls.append("fetch_alerts")
        self.received_products = list(products)
        return [ADVISORY]


class _RecordingWriter:
    """Doble del writer que anota cuándo se le llamó y qué avisos recibió."""

    def __init__(self, calls: list[str]) -> None:
        self._calls = calls
        self.received_advisories = None

    def generate(self, *, topic, resolved_topic_id, topic_title, topic_note,
                 reference, tweaks, advisories=None) -> AegisContent:
        self._calls.append("generate")
        self.received_advisories = advisories
        return AegisContent(
            topic_id     = resolved_topic_id,
            topic_title  = topic_title,
            language     = "es",
            company      = tweaks.get("company", ""),
            generated_at = "2026-08-04T00:00:00",
            subtitle     = "Píldora de prueba",
            intro        = "Introducción.",
            tips         = [AegisTipData(headline="Consejo", body="Cuerpo del consejo.")],
            closing      = "Cierre.",
        )


@pytest.fixture()
def pending_document(app, admin_user):
    """Píldora en 'pending' lista para que el workflow la complete."""
    from src.modules.features.aegis.model import AegisDocument, Topic
    from src.modules.features.aegis.repositories import AegisDocumentRepository
    from src.modules.infrastructure.unit_of_work import UnitOfWork

    with app.app_context():
        with UnitOfWork() as uow:
            topic = Topic(title="Phishing")
            uow.session.add(topic)
            uow.session.flush()

            doc = AegisDocument(
                title="pending_generacion",
                filename="pending_generacion.json",
                status="pending",
                format="json",
                topic_id=topic.id,
                user_id=admin_user.id,
                is_ai_generated=1,
            )
            saved = AegisDocumentRepository(uow).save(doc)
            return saved.id, topic.id


_TWEAKS = {
    "company": "ACME",
    # Sin agentes de Hygeia, el origen es la lista manual del perfil.
    "useHygeiaInventory": False,
    "trackedProducts": [{"vendor": "microsoft", "product": "windows"}],
}


def _run(app, admin_user, doc_id, topic_id, tweaks=None):
    calls: list[str] = []
    fetcher, writer = _RecordingFetcher(calls), _RecordingWriter(calls)

    with app.app_context():
        manager = AegisManager(admin_user, alert_fetcher=fetcher, ai_writer=writer)
        manager._run_generation_workflow(doc_id, topic_id, tweaks or dict(_TWEAKS))
    return calls, fetcher, writer


def test_advisories_reach_the_model_before_it_writes(app, admin_user, pending_document):
    doc_id, topic_id = pending_document
    calls, fetcher, writer = _run(app, admin_user, doc_id, topic_id)

    # El orden es la invariante: traer los avisos DESPUÉS de generar los
    # convierte en decoración, que es exactamente el bug que esto cierra.
    assert calls == ["fetch_alerts", "generate"]

    # Y no basta con el orden: tienen que llegar de verdad al writer.
    assert writer.received_advisories == [ADVISORY]
    assert fetcher.received_products == [{"vendor": "microsoft", "product": "windows"}]


def test_without_hygeia_inventory_falls_back_to_the_manual_list(app, admin_user, pending_document):
    """El interruptor activado no puede romper a quien no tiene agentes: sin
    inventario que resolver, se usa la lista que el usuario eligió."""
    doc_id, topic_id = pending_document
    _, fetcher, _ = _run(app, admin_user, doc_id, topic_id, tweaks={
        "company": "ACME",
        "useHygeiaInventory": True,   # activado, pero no hay activos dados de alta
        "trackedProducts": [{"vendor": "apache", "product": "http_server"}],
    })

    assert fetcher.received_products == [{"vendor": "apache", "product": "http_server"}]


def _asset_with_inventory(app, user, software):
    """Activo de Hygeia con inventario, escrito directo en la fila.

    Mismo atajo que ``test_hygeia_lybra_analysis``: lo que se ejercita aquí es
    de dónde saca Aegis los productos, no la ingesta del heartbeat.
    """
    from src.modules.features.hygeia.managers import HygeiaAssetManager
    from src.modules.features.hygeia.repositories import MonitoredAssetRepository
    from src.modules.infrastructure.unit_of_work import UnitOfWork

    with app.app_context():
        result = HygeiaAssetManager(user).create_asset(
            hostname="agente-aegis", os_name="windows", labels={},
        )
        asset_id = result["asset"]["id"]
        with UnitOfWork() as uow:
            repo = MonitoredAssetRepository(uow)
            asset = repo.get_by_id(asset_id)
            asset.inventory = [
                {"name": name, "version": version, "vendor": "ACME",
                 "type": "EXE", "source": "registry"}
                for name, version in software
            ]
            repo.update(asset)
    return asset_id


def _seed_cpe_index(app, vendor, product):
    """Un CVE del producto + reconstrucción del índice CPE, que es lo que
    permite resolver un nombre de inventario a coordenadas CPE."""
    from src.modules.features.themis.repositories import KbRepository
    from src.modules.infrastructure.unit_of_work import UnitOfWork

    with app.app_context():
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            repo.upsert_cve(
                {"cve_id": f"CVE-2026-9{abs(hash(product)) % 1000:03d}", "cvss_score": 9.8,
                 "cvss_vector": "CVSS:3.1/AV:N", "severity": "CRITICAL",
                 "description": "RCE", "cwe_ids": [], "source": "nvd"},
                [{"vendor": vendor, "product": product, "exact_version": "1.0",
                  "version_start_including": None, "version_start_excluding": None,
                  "version_end_including": None, "version_end_excluding": None}],
            )
            repo.rebuild_cpe_product_index()


def test_hygeia_inventory_becomes_the_tracked_products(app, admin_user, pending_document):
    """El caso que da sentido a la Etapa 5: los productos salen del software
    que los agentes reportan de verdad, no de una lista tecleada a mano."""
    _seed_cpe_index(app, "mozilla", "firefox")
    _asset_with_inventory(app, admin_user, [("Mozilla Firefox", "128.0")])

    doc_id, topic_id = pending_document
    _, fetcher, _ = _run(app, admin_user, doc_id, topic_id, tweaks={
        "company": "ACME",
        "useHygeiaInventory": True,
        # La lista manual dice otra cosa: el inventario manda cuando resuelve.
        "trackedProducts": [{"vendor": "apache", "product": "http_server"}],
    })

    assert fetcher.received_products == [{"vendor": "mozilla", "product": "firefox"}]


def test_disabling_the_switch_ignores_the_inventory(app, admin_user, pending_document):
    """Con agentes dados de alta pero el interruptor apagado, manda la lista
    manual — es la vía de escape que el usuario pidió tener."""
    _seed_cpe_index(app, "mozilla", "firefox")
    _asset_with_inventory(app, admin_user, [("Mozilla Firefox", "128.0")])

    doc_id, topic_id = pending_document
    _, fetcher, _ = _run(app, admin_user, doc_id, topic_id, tweaks={
        "company": "ACME",
        "useHygeiaInventory": False,
        "trackedProducts": [{"vendor": "apache", "product": "http_server"}],
    })

    assert fetcher.received_products == [{"vendor": "apache", "product": "http_server"}]


def test_unresolvable_inventory_falls_back_to_the_manual_list(app, admin_user, pending_document):
    """Un parque entero de software que NVD no indexa no puede dejar la
    píldora sin avisos."""
    _asset_with_inventory(app, admin_user, [("Software Interno De Casa", "1.0")])

    doc_id, topic_id = pending_document
    _, fetcher, _ = _run(app, admin_user, doc_id, topic_id, tweaks={
        "company": "ACME",
        "useHygeiaInventory": True,
        "trackedProducts": [{"vendor": "apache", "product": "http_server"}],
    })

    assert fetcher.received_products == [{"vendor": "apache", "product": "http_server"}]


def test_generation_marks_the_document_done(app, admin_user, pending_document):
    """El workflow completo sigue cerrando bien: sin esto, el test de orden
    podría pasar con una generación rota a medias."""
    from src.modules.features.aegis.repositories import AegisDocumentRepository
    from src.modules.infrastructure.session import get_db_session

    doc_id, topic_id = pending_document
    _run(app, admin_user, doc_id, topic_id)

    with app.app_context():
        doc = AegisDocumentRepository(session=get_db_session()).get_by_id(doc_id)
        assert doc.status == "done"
        assert doc.subtitle == "Píldora de prueba"
        assert [tip.headline for tip in doc.tips] == ["Consejo"]
        assert [alert.title for alert in doc.alerts] == [ADVISORY.title]
