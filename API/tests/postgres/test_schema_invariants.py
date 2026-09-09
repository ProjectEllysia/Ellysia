"""B20: las invariantes del esquema que SQLite no puede comprobar.

Cada test de aquí falla en PostgreSQL y **pasa en SQLite**, que es exactamente
por lo que hacen falta. No repiten cobertura: la añaden donde el motor de la
suite rápida es incapaz de decir la verdad.
"""

from __future__ import annotations

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import DataError, IntegrityError

from src.modules.features.iris.model import (
    IrisAnalysis,
    IrisDocument,
    IrisMailboxConnection,
    IrisRuleResult,
)
from src.modules.users.model import User

pytestmark = pytest.mark.postgres


def _user(pg_session, username: str = "postgres-tester") -> User:
    user = User(
        username=username,
        email=f"{username}@ellysia.test",
        first_name="Postgres",
        last_name="Tester",
        password_hash="x",
        password_salt="",
        role="role_user",
    )
    pg_session.add(user)
    pg_session.commit()
    return user


def _connection(pg_session, user: User, email: str = "buzon@outlook.example") -> IrisMailboxConnection:
    connection = IrisMailboxConnection(
        user_id=user.id, provider="microsoft", account_email=email,
        scopes="Mail.Read", refresh_token="cifrado",
    )
    pg_session.add(connection)
    pg_session.commit()
    return connection


# ---------------------------------------------------------------------------
# Longitud de columna
# ---------------------------------------------------------------------------

def test_a_long_graph_delta_link_fits_in_sync_cursor(pg_session):
    """B12 contra el motor real.

    SQLite ignora la longitud declarada de un ``VARCHAR``, así que con la
    columna en ``String(255)`` el test equivalente de la suite rápida pasaba
    igualmente. Aquí no: si alguien la volviera a estrechar, este INSERT falla.
    """
    user = _user(pg_session, "cursor-largo")
    connection = _connection(pg_session, user, "cursor@outlook.example")

    cursor = (
        "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages/delta"
        "?$deltatoken=" + "Ag0AAA" + "Z" * 1500
    )
    connection.sync_cursor = cursor
    pg_session.commit()
    pg_session.expire_all()

    assert pg_session.get(IrisMailboxConnection, connection.id).sync_cursor == cursor


def test_an_oversized_value_is_rejected_rather_than_truncated(pg_session):
    """La otra cara: PostgreSQL **rechaza** lo que no cabe, no lo recorta.

    Importa dejarlo escrito, porque es la diferencia de comportamiento que hace
    que un desbordamiento se vea en desarrollo (nunca) y en producción (siempre).
    """
    user = _user(pg_session, "estado-largo")
    analysis = IrisAnalysis(raw_headers="From: a@b.com", user_id=user.id,
                            status="x" * 200)  # la columna son 20
    pg_session.add(analysis)

    with pytest.raises((DataError, IntegrityError)):
        pg_session.commit()


# ---------------------------------------------------------------------------
# Unicidad e idempotencia
# ---------------------------------------------------------------------------

def test_the_same_ingested_message_cannot_be_analysed_twice(pg_session, pg_sessions):
    """La idempotencia de la ingesta de buzón, contra una carrera real.

    ``UniqueConstraint(connection_id, source_message_uid)`` es lo que hace que
    un reintento de sincronización sea un no-op en vez de un análisis
    duplicado. Se monta con **dos sesiones independientes** porque con una sola
    el ORM resolvería el conflicto en su propio identity map y el test pasaría
    sin haber llegado a la base de datos.
    """
    user = _user(pg_session, "idempotencia")
    connection = _connection(pg_session, user, "idem@outlook.example")

    first, second = pg_sessions(), pg_sessions()
    first.add(IrisAnalysis(raw_headers="From: a@b.com", user_id=user.id,
                           connection_id=connection.id, source_message_uid="msg-1"))
    first.commit()

    second.add(IrisAnalysis(raw_headers="From: a@b.com", user_id=user.id,
                            connection_id=connection.id, source_message_uid="msg-1"))
    with pytest.raises(IntegrityError):
        second.commit()


def test_manual_submissions_never_collide(pg_session):
    """Y la contrapartida: dos análisis manuales no chocan.

    Ambos tienen ``connection_id`` y ``source_message_uid`` a NULL, y el UNIQUE
    de SQL estándar trata cada NULL como distinto de todos los demás. Es de lo
    que depende que la restricción no rompa el flujo normal de la aplicación.
    """
    user = _user(pg_session, "manuales")

    pg_session.add(IrisAnalysis(raw_headers="From: a@b.com", user_id=user.id))
    pg_session.add(IrisAnalysis(raw_headers="From: c@d.com", user_id=user.id))
    pg_session.commit()  # no debe lanzar

    assert pg_session.query(IrisAnalysis).filter_by(user_id=user.id).count() == 2


# ---------------------------------------------------------------------------
# Claves foráneas
# ---------------------------------------------------------------------------

def test_deleting_a_connection_keeps_its_analyses(pg_session):
    """``ondelete="SET NULL"``: desconectar un buzón no puede borrar el
    historial de análisis que llegaron por él.

    SQLite no aplica claves foráneas salvo que se active explícitamente el
    pragma, así que en la suite rápida esta cláusula no se ejercita nunca.
    """
    user = _user(pg_session, "fk-set-null")
    connection = _connection(pg_session, user, "setnull@outlook.example")

    analysis = IrisAnalysis(raw_headers="From: a@b.com", user_id=user.id,
                            connection_id=connection.id, source_message_uid="msg-9")
    pg_session.add(analysis)
    pg_session.commit()
    analysis_id = analysis.id

    pg_session.delete(connection)
    pg_session.commit()
    pg_session.expire_all()

    survivor = pg_session.get(IrisAnalysis, analysis_id)
    assert survivor is not None
    assert survivor.connection_id is None


def test_deleting_an_analysis_takes_its_documents_with_it(pg_session):
    """``ondelete="CASCADE"``: lo contrario del anterior, y también sin
    cobertura hasta ahora. Un documento huérfano apuntaría a un análisis que ya
    no existe y reventaría al listarlo."""
    user = _user(pg_session, "fk-cascade")
    analysis = IrisAnalysis(raw_headers="From: a@b.com", user_id=user.id, status="finished")
    pg_session.add(analysis)
    pg_session.commit()

    document = IrisDocument(analysis_id=analysis.id, user_id=user.id,
                            document_type="iris", filename="", format="pdf",
                            status="done", verdict="Phishing")
    pg_session.add(document)
    pg_session.commit()
    document_id = document.id

    pg_session.delete(analysis)
    pg_session.commit()
    pg_session.expire_all()

    assert pg_session.get(IrisDocument, document_id) is None


# ---------------------------------------------------------------------------
# JSONB
# ---------------------------------------------------------------------------

def test_the_json_columns_really_are_jsonb(pg_engine):
    """El shim de la suite rápida sustituye ``JSONB`` por ``JSON`` genérico, así
    que el tipo real no se comprueba en ningún otro sitio. Y no es cosmético:
    ``JSON`` no tiene los operadores de contención ni se puede indexar con GIN.
    """
    columns = {column["name"]: str(column["type"])
               for column in sa.inspect(pg_engine).get_columns("IrisAnalysis")}

    assert columns["gate_reasons"] == "JSONB"
    assert columns["failed_rules"] == "JSONB"
    assert columns["ai_summary"] == "JSONB"


def test_jsonb_columns_round_trip_their_structure(pg_session):
    """En la suite rápida estas columnas son ``JSON`` genérico por un shim, así
    que su comportamiento real —tipos, anidamiento, orden de claves— no se
    prueba en ningún sitio."""
    user = _user(pg_session, "jsonb")
    analysis = IrisAnalysis(
        raw_headers="From: a@b.com", user_id=user.id, status="finished",
        gate_reasons=["SPF/DMARC failure", "Análisis degradado"],
        failed_rules=[{"name": "SPF", "family": "auth", "category": "authentication"}],
        ai_summary={"executive_summary": "texto", "recommendations": ["a", "b"],
                     "confidence": "HIGH"},
    )
    pg_session.add(analysis)
    pg_session.commit()
    pg_session.expire_all()

    stored = pg_session.get(IrisAnalysis, analysis.id)
    assert stored.gate_reasons == ["SPF/DMARC failure", "Análisis degradado"]
    assert stored.failed_rules[0]["family"] == "auth"
    assert stored.ai_summary["recommendations"] == ["a", "b"]


def test_jsonb_supports_containment_queries(pg_session):
    """El operador ``@>`` es de JSONB y no existe en SQLite. Se comprueba
    porque es lo que permitiría filtrar informes por su contenido sin traerse
    todas las filas al proceso — y si la columna dejara de ser JSONB, esto es
    lo primero que se rompería."""
    user = _user(pg_session, "jsonb-query")
    pg_session.add(IrisAnalysis(raw_headers="From: a@b.com", user_id=user.id,
                                status="finished", analysis_quality="degraded",
                                failed_rules=[{"name": "SPF", "family": "auth"}]))
    pg_session.add(IrisAnalysis(raw_headers="From: c@d.com", user_id=user.id,
                                status="finished", analysis_quality="complete",
                                failed_rules=None))
    pg_session.commit()

    degraded = pg_session.execute(
        sa.text(
            'SELECT analysis_quality FROM "IrisAnalysis" '
            "WHERE failed_rules @> :probe"
        ).bindparams(sa.bindparam("probe", [{"family": "auth"}], type_=JSONB))
    ).scalars().all()

    assert degraded == ["degraded"]


def test_rule_results_keep_their_execution_order(pg_session):
    """``position`` es un ``SmallInteger`` y el informe se ordena por él. En
    PostgreSQL el tipo tiene rango real (±32767), otra cosa que SQLite ignora."""
    user = _user(pg_session, "orden-reglas")
    analysis = IrisAnalysis(raw_headers="From: a@b.com", user_id=user.id, status="finished")
    pg_session.add(analysis)
    pg_session.commit()

    for position, name in enumerate(["SPF", "DKIM", "DMARC"]):
        pg_session.add(IrisRuleResult(analysis_id=analysis.id, rule_name=name,
                                      category="authentication", score=0,
                                      verdict="pass", position=position))
    pg_session.commit()
    pg_session.expire_all()

    stored = pg_session.get(IrisAnalysis, analysis.id)
    assert [rule.rule_name for rule in stored.rule_results] == ["SPF", "DKIM", "DMARC"]
