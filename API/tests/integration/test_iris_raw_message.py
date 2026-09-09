"""Tests de integración de la separación raw/resultado de Iris (M09/B19):
``IrisAnalysis.raw_headers`` es ahora una property respaldada por
``IrisRawMessage`` (fila 1:1, cifrada), no una columna.

Cubre lo que un cambio de este tipo puede romper en silencio: que el
contenido de verdad viaja cifrado en la base de datos (no en texto plano),
que borrar el análisis se lleva su raw (cascada), que purgar solo el raw
deja el análisis y sus reglas intactos, y que los contadores del informe de
retención reflejan la tabla real.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

from src.modules.features.iris.model import IrisAnalysis, IrisRawMessage, IrisRuleResult
from src.modules.features.iris.repositories import IrisAnalysisRepository, IrisRuleResultRepository
from src.modules.infrastructure import UnitOfWork
from src.modules.shared._crypto import decrypt_at_rest

pytestmark = pytest.mark.integration


def _save_analysis(app, user_id: int, raw_headers: str = "From: a@b.com\r\nSubject: Hi\r\n") -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            analysis = IrisAnalysis(raw_headers=raw_headers, user_id=user_id, status="finished")
            IrisAnalysisRepository(uow).save(analysis)
            return analysis.id


def test_raw_headers_round_trips_through_the_property(app, regular_user):
    analysis_id = _save_analysis(app, regular_user.id, "From: a@b.com\r\nSubject: Ping\r\n")

    with app.app_context():
        with UnitOfWork() as uow:
            analysis = IrisAnalysisRepository(uow).get_by_id(analysis_id)
            assert analysis.raw_headers == "From: a@b.com\r\nSubject: Ping\r\n"
            assert analysis.raw_message is not None


def test_raw_content_is_encrypted_in_the_database(app, regular_user):
    """El texto plano nunca debe llegar tal cual a la fila -- si esto
    fallara, ``EncryptedText`` habría dejado de cifrar al escribir."""
    plaintext = "From: attacker@evil.tk\r\nSubject: Secreto\r\n"
    analysis_id = _save_analysis(app, regular_user.id, plaintext)

    with app.app_context():
        with UnitOfWork() as uow:
            row = uow.session.execute(
                text('SELECT content FROM "IrisRawMessage" WHERE analysis_id = :id'),
                {"id": analysis_id},
            ).first()
            stored = row[0]
            assert stored != plaintext
            assert decrypt_at_rest(stored, purpose="iris_raw_message") == plaintext


def test_deleting_the_analysis_cascades_to_its_raw_message(app, regular_user):
    analysis_id = _save_analysis(app, regular_user.id)

    with app.app_context():
        with UnitOfWork() as uow:
            repo = IrisAnalysisRepository(uow)
            repo.delete(repo.get_by_id(analysis_id))

        with UnitOfWork() as uow:
            remaining = uow.session.query(IrisRawMessage).filter(
                IrisRawMessage.analysis_id == analysis_id
            ).first()
            assert remaining is None


def test_deleting_the_analysis_cascades_to_its_rule_results(app, regular_user):
    """B17: el criterio de cierre exige que la retención no deje huérfanos
    -- comprobado aquí sobre el borrado normal (no solo el de retención),
    ya que ambos pasan por el mismo cascade del ORM."""
    analysis_id = _save_analysis(app, regular_user.id)
    with app.app_context():
        with UnitOfWork() as uow:
            IrisRuleResultRepository(uow).save(IrisRuleResult(
                analysis_id=analysis_id, rule_name="SPF", score=-10, verdict="fail",
            ))

        with UnitOfWork() as uow:
            repo = IrisAnalysisRepository(uow)
            repo.delete(repo.get_by_id(analysis_id))

        with UnitOfWork() as uow:
            remaining = uow.session.query(IrisRuleResult).filter(
                IrisRuleResult.analysis_id == analysis_id
            ).first()
            assert remaining is None


def test_purging_only_the_raw_message_leaves_the_analysis_and_rules_intact(app, regular_user):
    analysis_id = _save_analysis(app, regular_user.id)
    with app.app_context():
        with UnitOfWork() as uow:
            IrisRuleResultRepository(uow).save(IrisRuleResult(
                analysis_id=analysis_id, rule_name="DKIM", score=-5, verdict="fail",
            ))

        with UnitOfWork() as uow:
            repo = IrisAnalysisRepository(uow)
            analysis = repo.get_by_id(analysis_id)
            analysis.raw_headers = None
            repo.update(analysis)

        with UnitOfWork() as uow:
            reloaded = IrisAnalysisRepository(uow).get_by_id(analysis_id)
            assert reloaded is not None
            assert reloaded.raw_headers is None
            assert reloaded.raw_message is None
            assert len(IrisRuleResultRepository(uow).get_by_analysis(analysis_id)) == 1


def test_count_by_user_and_with_raw_retained(app, regular_user):
    kept_id = _save_analysis(app, regular_user.id)
    purged_id = _save_analysis(app, regular_user.id)
    with app.app_context():
        with UnitOfWork() as uow:
            repo = IrisAnalysisRepository(uow)
            purged = repo.get_by_id(purged_id)
            purged.raw_headers = None
            repo.update(purged)

        with UnitOfWork() as uow:
            repo = IrisAnalysisRepository(uow)
            assert repo.count_by_user(regular_user.id) == 2
            assert repo.count_with_raw_retained_by_user(regular_user.id) == 1
    assert kept_id != purged_id
