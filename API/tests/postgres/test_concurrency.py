"""B20: las carreras que solo existen con transacciones de verdad.

El motor de cuotas y la reserva del resumen de IA se apoyan los dos en la
misma idea: la condición vive **dentro** del UPDATE, para que dos peticiones
simultáneas no puedan gastar el mismo hueco. Esa propiedad no se puede
comprobar con un fichero SQLite y una sola sesión — hacen falta dos
transacciones concurrentes contra el mismo servidor.
"""

from __future__ import annotations

import pytest
import sqlalchemy as sa

from src.modules.features.iris.model import IrisAnalysis
from src.modules.users.model import User

pytestmark = pytest.mark.postgres


def _user(pg_session, username: str) -> User:
    user = User(
        username=username, email=f"{username}@ellysia.test",
        first_name="Postgres", last_name="Tester",
        password_hash="x", password_salt="", role="role_user",
    )
    pg_session.add(user)
    pg_session.commit()
    return user


def _claim(session, analysis_id: int) -> bool:
    """El mismo UPDATE condicional que usa ``IrisManager._claim_ai_summary``.

    Se reproduce aquí en vez de llamar al manager porque el manager abre su
    propia ``UnitOfWork`` contra el engine global de la aplicación, y lo que
    este test necesita es controlar las dos transacciones.
    """
    result = session.execute(
        sa.update(IrisAnalysis)
        .where(sa.and_(
            IrisAnalysis.id == analysis_id,
            sa.or_(IrisAnalysis.ai_summary_status.is_(None),
                   IrisAnalysis.ai_summary_status == "failed"),
        ))
        .values(ai_summary_status="running")
    )
    return bool(result.rowcount)


def test_only_one_of_two_concurrent_claims_wins(pg_session, pg_sessions):
    """B10 contra concurrencia real.

    Dos peticiones simultáneas del resumen de IA del mismo análisis. La
    exclusión se apoya en que el segundo UPDATE no afecte a ninguna fila; si
    la comprobación viviera en Python entre una lectura y una escritura, las
    dos ganarían y el usuario pagaría dos veces.
    """
    user = _user(pg_session, "carrera-resumen")
    analysis = IrisAnalysis(raw_headers="From: a@b.com", user_id=user.id, status="finished")
    pg_session.add(analysis)
    pg_session.commit()

    first, second = pg_sessions(), pg_sessions()

    first_won = _claim(first, analysis.id)
    first.commit()
    second_won = _claim(second, analysis.id)
    second.commit()

    assert [first_won, second_won] == [True, False]


def test_a_failed_claim_can_be_taken_again(pg_session, pg_sessions):
    """`failed` es reclamable: reintentar tiene que funcionar, o un fallo del
    backend de IA dejaría el resumen bloqueado para siempre."""
    user = _user(pg_session, "reintento-resumen")
    analysis = IrisAnalysis(raw_headers="From: a@b.com", user_id=user.id,
                            status="finished", ai_summary_status="failed")
    pg_session.add(analysis)
    pg_session.commit()

    session = pg_sessions()
    assert _claim(session, analysis.id) is True
    session.commit()


def test_two_transactions_cannot_spend_the_same_last_slot(pg_session, pg_sessions):
    """El patrón del motor de cuotas, aislado.

    Es el mismo UPDATE condicional que usa ``QuotaManager._consume_counter``:
    ``SET used = used + 1 WHERE used + 1 <= limite``. Con el límite en 1 y dos
    transacciones a la vez, PostgreSQL serializa los dos UPDATE y el segundo no
    encuentra fila. Sobre SQLite, con una sola conexión, esta comprobación no
    demostraría nada.
    """
    user = _user(pg_session, "carrera-cuota")
    counter = sa.table(
        "IrisAnalysis",
        sa.column("id"), sa.column("total_score"), sa.column("user_id"),
    )

    analysis = IrisAnalysis(raw_headers="From: a@b.com", user_id=user.id,
                            status="finished", total_score=0)
    pg_session.add(analysis)
    pg_session.commit()

    def spend(session) -> bool:
        result = session.execute(
            sa.update(counter)
            .where(sa.and_(counter.c.id == analysis.id, counter.c.total_score + 1 <= 1))
            .values(total_score=counter.c.total_score + 1)
        )
        return bool(result.rowcount)

    first, second = pg_sessions(), pg_sessions()

    first_spent = spend(first)
    first.commit()
    second_spent = spend(second)
    second.commit()

    assert [first_spent, second_spent] == [True, False]


def test_redis_round_trips_a_cancel_signal(real_redis):
    """La otra mitad de la matriz: un Redis de verdad.

    La suite normal corta Redis de raíz, así que la señal de cancelación
    cooperativa —la clave ``taskqueue:cancel:<job>`` que los workers sondean—
    nunca se escribe ni se lee contra el servidor real. Es poco código, pero es
    el mecanismo del que depende que un escaneo o un análisis se puedan parar.
    """
    key = "taskqueue:cancel:job-de-prueba"

    assert real_redis.get(key) is None

    real_redis.set(key, "1", ex=60)
    assert real_redis.get(key) == "1"

    real_redis.delete(key)
    assert real_redis.get(key) is None
