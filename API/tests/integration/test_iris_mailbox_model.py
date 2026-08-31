"""Tests de integración del modelo IrisMailboxConnection y su repositorio."""

from __future__ import annotations

import pytest
from sqlalchemy.exc import SQLAlchemyError

from src.modules.features.iris.model import IrisAnalysis, IrisMailboxConnection
from src.modules.features.iris.repositories import (
    IrisAnalysisRepository, IrisMailboxConnectionRepository,
)
from src.modules.infrastructure import UnitOfWork

pytestmark = pytest.mark.integration


def _make_connection(user_id: int, account_email: str = "victim@gmail.com") -> IrisMailboxConnection:
    return IrisMailboxConnection(
        user_id=user_id,
        provider="gmail",
        account_email=account_email,
        scopes="gmail.metadata",
        refresh_token_enc="encrypted-token",
    )


def test_create_and_fetch_connection(app, regular_user):
    with app.app_context():
        with UnitOfWork() as uow:
            repo = IrisMailboxConnectionRepository(uow)
            conn = _make_connection(regular_user.id)
            repo.save(conn)
            conn_id = conn.id

        with UnitOfWork() as uow:
            fetched = IrisMailboxConnectionRepository(uow).get_by_id(conn_id)
            assert fetched is not None
            assert fetched.provider == "gmail"
            assert fetched.status == "active"
            assert fetched.full_message_mode is False


def test_duplicate_user_provider_email_rejected(app, regular_user):
    with app.app_context():
        with UnitOfWork() as uow:
            IrisMailboxConnectionRepository(uow).save(_make_connection(regular_user.id))

        with pytest.raises(SQLAlchemyError):
            with UnitOfWork() as uow:
                IrisMailboxConnectionRepository(uow).save(_make_connection(regular_user.id))


def test_get_by_user_provider_email(app, regular_user):
    with app.app_context():
        with UnitOfWork() as uow:
            IrisMailboxConnectionRepository(uow).save(_make_connection(regular_user.id))

        with UnitOfWork() as uow:
            repo = IrisMailboxConnectionRepository(uow)
            found = repo.get_by_user_provider_email(regular_user.id, "gmail", "victim@gmail.com")
            assert found is not None
            missing = repo.get_by_user_provider_email(regular_user.id, "microsoft", "victim@gmail.com")
            assert missing is None


def test_count_for_user(app, regular_user):
    with app.app_context():
        with UnitOfWork() as uow:
            repo = IrisMailboxConnectionRepository(uow)
            repo.save(_make_connection(regular_user.id, "a@gmail.com"))
            repo.save(_make_connection(regular_user.id, "b@gmail.com"))

        with UnitOfWork() as uow:
            assert IrisMailboxConnectionRepository(uow).count_for_user(regular_user.id) == 2


def test_analysis_source_message_uid_unique_per_connection(app, regular_user):
    with app.app_context():
        with UnitOfWork() as uow:
            conn = _make_connection(regular_user.id)
            IrisMailboxConnectionRepository(uow).save(conn)
            conn_id = conn.id

        with UnitOfWork() as uow:
            IrisAnalysisRepository(uow).save(IrisAnalysis(
                raw_headers="From: a@b.com", user_id=regular_user.id,
                connection_id=conn_id, source_message_uid="msg-1",
            ))

        # Same (connection_id, source_message_uid) again -> rejected (idempotency).
        with pytest.raises(SQLAlchemyError):
            with UnitOfWork() as uow:
                IrisAnalysisRepository(uow).save(IrisAnalysis(
                    raw_headers="From: a@b.com", user_id=regular_user.id,
                    connection_id=conn_id, source_message_uid="msg-1",
                ))

        # Two manual analyses (connection_id/source_message_uid both NULL) never collide.
        with UnitOfWork() as uow:
            repo = IrisAnalysisRepository(uow)
            repo.save(IrisAnalysis(raw_headers="From: a@b.com", user_id=regular_user.id))
            repo.save(IrisAnalysis(raw_headers="From: c@d.com", user_id=regular_user.id))


# --------------------------------------------------------------- B12: cursor opaco

def test_sync_cursor_column_has_no_length_limit():
    """B12: la columna era ``String(255)``, pero el ``@odata.deltaLink`` de
    Microsoft Graph es una URL con un token de estado dentro que la rebasa.

    Esta comprobación mira el **tipo declarado**, no un round-trip, a
    propósito: la suite corre sobre SQLite, que ignora la longitud de un
    ``VARCHAR`` y por tanto guardaría feliz un cursor de 900 caracteres
    incluso con la columna acotada. En PostgreSQL, que es donde corre de
    verdad, ese INSERT falla. El tipo es lo único que distingue las dos cosas
    desde aquí.
    """
    column_type = IrisMailboxConnection.__table__.c.sync_cursor.type

    assert not getattr(column_type, "length", None), (
        "sync_cursor volvió a tener un límite de longitud; un deltaLink de "
        "Graph no cabe y la sincronización incremental se rompe en silencio"
    )


def test_a_long_opaque_cursor_survives_a_round_trip(app, regular_user):
    """Complemento del anterior: el valor vuelve **exactamente** igual.

    Aunque SQLite no valide la longitud, este test protege contra cualquier
    recorte o normalización que alguien introdujera en el camino de guardado —
    el cursor es opaco y un solo carácter de diferencia lo invalida.
    """
    cursor = (
        "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages/delta"
        "?$deltatoken=" + "Ag0AAA" + "Z" * 1200
    )

    with app.app_context():
        with UnitOfWork() as uow:
            repo = IrisMailboxConnectionRepository(uow)
            connection = _make_connection(regular_user.id, "cursor@outlook.com")
            connection.provider = "microsoft"
            connection.sync_cursor = cursor
            repo.save(connection)
            connection_id = connection.id

        with UnitOfWork() as uow:
            fetched = IrisMailboxConnectionRepository(uow).get_by_id(connection_id)
            assert fetched.sync_cursor == cursor
            assert len(fetched.sync_cursor) > 255
