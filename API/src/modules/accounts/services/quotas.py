"""
Motor de cuotas: cuenta lo consumido y corta cuando el plan se acaba.

Dos naturalezas, dos formas de contar:

- **Consumo** (``month`` / ``day``): hay contador en ``UsageCounter``. Sube y no
  baja, y se reinicia solo al cambiar de periodo — no hay ningún proceso que
  ponga contadores a cero.
- **Existencias** (``stock``): no hay contador. Se cuenta la tabla real. Un
  contador de existencias se desincroniza en el primer borrado, y la base de
  datos ya sabe la respuesta.

**Dónde se llama.** ``consume()`` va en la costura del *manager*, nunca solo en
el endpoint HTTP. Es la lección que dejó el arreglo SSRF de los escáneres: el
flujo programado (``scheduling.py`` llamando a ``run_scan()`` directamente) y
las reejecuciones del worker RQ no pasan por el endpoint, y se saltarían
cualquier comprobación que viva solo allí.

**Sin devolución.** Si la tarea falla después de consumir, la cuota se gastó.
Es fallo cerrado y es lo aburrido. El gancho para un ``release()`` simétrico es
obvio, pero no se escribe hasta que duela de verdad.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date
from typing import Optional

from sqlalchemy import and_, insert, update
from sqlalchemy.exc import IntegrityError

from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository, get_db_session

from ..exceptions import EmailNotVerifiedError, PlanFeatureDisabledError, QuotaExceededError
from ..model import UsageCounter
from .entitlements import Entitlement, resolve_entitlement
from .limits import (
    STOCK_COUNTERS,
    LimitKey,
    LimitPeriod,
    next_period_start,
    period_start_for,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class QuotaState:
    """Foto del consumo de una clave, para enseñarla sin modificar nada."""

    key: LimitKey
    limit: Optional[int]
    used: int
    period: LimitPeriod
    source: str
    plan_code: str
    resets_at: Optional[date]

    @property
    def is_unlimited(self) -> bool:
        return self.limit is None

    @property
    def exceeded(self) -> bool:
        """Por encima del tope.

        Pasa sin haber hecho nada malo: al bajar de plan, al caducar una
        suscripción o al salir de una organización, unas existencias que eran
        legales dejan de serlo. Nunca se borra nada — la clave entra en modo
        solo lectura hasta volver por debajo.
        """
        return self.limit is not None and self.used > self.limit

    @property
    def remaining(self) -> Optional[int]:
        return None if self.limit is None else max(self.limit - self.used, 0)


class QuotaManager:
    """Comprueba y consume cuota. La única puerta a ``UsageCounter``."""

    # -------------------------------------------------------------- lectura

    def state(self, user_id: int, key: LimitKey) -> QuotaState:
        """Consumo actual sin tocar nada. Es lo que alimenta la vista "Mi plan"."""
        entitlement = resolve_entitlement(user_id, key)
        return QuotaState(
            key=key,
            limit=entitlement.limit,
            used=self._current_usage(entitlement),
            period=entitlement.period,
            source=entitlement.source,
            plan_code=entitlement.plan_code,
            resets_at=next_period_start(entitlement.period),
        )

    # -------------------------------------------------------------- escritura

    def consume(self, user_id: int, key: LimitKey, amount: int = 1) -> None:
        """Apunta ``amount`` usos de ``key``, o corta.

        Raises:
            EmailNotVerifiedError: la cuenta no ha confirmado su correo (403).
            PlanFeatureDisabledError: el plan no incluye la característica (402).
            QuotaExceededError: incluida, pero sin cupo (402).
        """
        self._assert_email_verified(user_id)

        entitlement = resolve_entitlement(user_id, key)

        if entitlement.is_disabled:
            logger.info(
                f"Corte por plan | user={user_id} key={key.db_name} "
                f"plan={entitlement.plan_code} motivo=no_incluido"
            )
            raise PlanFeatureDisabledError(key.db_name, entitlement.plan_code)

        if entitlement.period is LimitPeriod.TIER:
            raise NotImplementedError(
                f"'{key.db_name}' es una clave de nivel: no se consume. Su tope se "
                f"lee con resolve_entitlement(...).limit y se respeta al aplicarlo."
            )

        if entitlement.period is LimitPeriod.STOCK:
            self._consume_stock(entitlement, amount)
        else:
            self._consume_counter(entitlement, amount)

    def consume_many(self, user_id: int, keys: list[LimitKey], amount: int = 1) -> None:
        """Consume varias claves como una única operación: todas o ninguna.

        Encadenar ``consume()`` a pelo dos veces deja un cobro a medias si la
        segunda llamada falla -- el caso real es ``generate_ai_summary()``,
        que cobraba ``IRIS_AI_SUMMARIES`` y luego ``AI_REQUESTS``: si la
        segunda no tenía cupo, la primera se quedaba cobrada por un trabajo
        que nunca se encolaba. Aquí, si cualquier clave falla (sin cupo,
        plan que no la incluye), las que ya se cobraron en esta llamada se
        reembolsan antes de relanzar -- el balance neto siempre es "cobrado
        todo" o "cobrado nada", nunca un punto intermedio.

        El orden de ``keys`` importa: si más de una fallaría, la excepción
        que ve el llamante es la de la primera en agotarse, no una elegida al
        azar por el orden de iteración interno.
        """
        consumed: list[LimitKey] = []
        try:
            for key in keys:
                self.consume(user_id, key, amount)
                consumed.append(key)
        except Exception:
            for key in reversed(consumed):
                self.refund(user_id, key, amount)
            raise

    def refund(self, user_id: int, key: LimitKey, amount: int = 1) -> None:
        """Devuelve ``amount`` usos ya apuntados de ``key``.

        Existe porque ``consume()`` ocurre **antes** que el trabajo que se está
        pagando, y tiene que ser así: cobrar después dejaría la puerta abierta
        a lanzar N trabajos concurrentes con cupo para uno. El precio de ese
        orden es que un trabajo que nunca llega a hacerse —el encolado lo
        rechaza, el worker revienta— deja al usuario pagando por nada.

        No es lo contrario exacto de ``consume()`` y no debe usarse como tal:
        no resucita una fila de periodo que ya no existe (si el mes cambió
        entre el cobro y el reembolso, el cargo pertenece al periodo anterior
        y ya no se puede deshacer ahí), ni baja de cero. Nunca lanza: un
        reembolso fallido no puede tumbar el camino de error que lo invocó, y
        cobrar de más una vez es preferible a perder el error original.

        Las claves de nivel (TIER) y de existencias (STOCK) no llevan
        contador que devolver — su "consumo" es la tabla real — así que
        reembolsarlas es un no-op.
        """
        try:
            entitlement = resolve_entitlement(user_id, key)
            if entitlement.period in (LimitPeriod.TIER, LimitPeriod.STOCK):
                return
            if entitlement.is_unlimited:
                return

            period_start = period_start_for(entitlement.period)
            with UnitOfWork() as uow:
                # Igual que el cobro: la resta va dentro del UPDATE, con el
                # suelo en la condición, para no leer-decidir-escribir.
                uow.session.execute(
                    update(UsageCounter)
                    .where(and_(
                        UsageCounter.holder_kind == entitlement.holder_kind,
                        UsageCounter.holder_id == entitlement.holder_id,
                        UsageCounter.limit_key == entitlement.key.db_name,
                        UsageCounter.period_start == period_start,
                        UsageCounter.used >= amount,
                    ))
                    .values(used=UsageCounter.used - amount)
                )
        except Exception as exc:
            logger.warning(
                "No se pudo reembolsar cuota | user=%s key=%s: %s",
                user_id, key.db_name, exc,
            )

    # ------------------------------------------------------------- internos

    @staticmethod
    def _assert_email_verified(user_id: int) -> None:
        """Sin correo confirmado no se consume nada que cueste dinero.

        Una comprobación, en el único sitio por el que pasan todas las acciones
        medidas — el mismo motivo por el que ``consume()`` vive en la costura
        del manager. Poner el guard en cada endpoint sería recordarlo catorce
        veces y olvidarlo en la quince.

        La cuenta sin verificar **entra y navega**: puede mirar sus datos, su
        plan y la documentación. Lo que no puede es gastar dinero nuestro, que
        es lo que evita que el plan gratuito sea un grifo abierto a cuentas
        desechables.

        Import diferido: ``users`` acaba importando ``features``, y ``features``
        importa este módulo. Al nivel de módulo sería un ciclo.
        """
        from src.modules.users.model import User

        user = get_db_session().get(User, user_id)
        if user is not None and user.email_verified_at is None:
            logger.info(f"Corte por correo sin verificar | user={user_id}")
            raise EmailNotVerifiedError()

    def _consume_stock(self, entitlement: Entitlement, amount: int) -> None:
        """Existencias: cuenta la tabla real y compara.

        No hay nada que escribir — la fila que se está a punto de crear es el
        contador. Por eso la comprobación es ``actual + amount > limite`` y no
        ``>=``.
        """
        if entitlement.is_unlimited:
            return

        used = self._count_stock(entitlement)
        if used + amount > entitlement.limit:
            logger.info(
                f"Corte por plan | user={entitlement.holder_id} key={entitlement.key.db_name} "
                f"plan={entitlement.plan_code} usado={used}/{entitlement.limit} tipo=stock"
            )
            raise QuotaExceededError(
                limit_key=entitlement.key.db_name,
                value=entitlement.limit,
                used=used,
                period=entitlement.period.value,
                plan_code=entitlement.plan_code,
            )

    def _consume_counter(self, entitlement: Entitlement, amount: int) -> None:
        """Consumo: incremento condicional, con la condición dentro del UPDATE.

        La atomicidad vive entera en ese ``WHERE``: si dos peticiones simultáneas
        intentan gastar el último hueco, la base de datos serializa los dos
        UPDATE y el segundo no afecta a ninguna fila. Nada de leer, decidir en
        Python y escribir — ese patrón regala cuota bajo concurrencia.
        """
        period_start = period_start_for(entitlement.period)

        with UnitOfWork() as uow:
            session = uow.session
            self._ensure_counter_row(session, entitlement, period_start)

            conditions = [
                UsageCounter.holder_kind == entitlement.holder_kind,
                UsageCounter.holder_id == entitlement.holder_id,
                UsageCounter.limit_key == entitlement.key.db_name,
                UsageCounter.period_start == period_start,
            ]
            if not entitlement.is_unlimited:
                conditions.append(UsageCounter.used + amount <= entitlement.limit)

            result = session.execute(
                update(UsageCounter)
                .where(and_(*conditions))
                .values(used=UsageCounter.used + amount)
            )

            if result.rowcount:
                return

            # Ninguna fila afectada: o se agotó el cupo, o se perdió la carrera
            # contra otra petición que gastó el hueco. Las dos cosas significan
            # lo mismo de cara al usuario.
            used = self._read_counter(session, entitlement, period_start)

        logger.info(
            f"Corte por plan | user={entitlement.holder_id} key={entitlement.key.db_name} "
            f"plan={entitlement.plan_code} usado={used}/{entitlement.limit} "
            f"periodo={entitlement.period.value}"
        )
        raise QuotaExceededError(
            limit_key=entitlement.key.db_name,
            value=entitlement.limit,
            used=used,
            period=entitlement.period.value,
            plan_code=entitlement.plan_code,
            resets_at=next_period_start(entitlement.period),
        )

    @staticmethod
    def _ensure_counter_row(session, entitlement: Entitlement, period_start: date) -> None:
        """Crea la fila del periodo con ``used = 0`` si no existía.

        El INSERT va dentro de un SAVEPOINT (``begin_nested``): si otra petición
        crea la misma fila entre el comprobar y el insertar, el conflicto de
        clave primaria se queda dentro del punto de guardado y no aborta la
        transacción de fuera — que es lo que pasaría en Postgres con un
        ``IntegrityError`` suelto. Después manda el UPDATE condicional, que es
        la única autoridad sobre si cabe o no.
        """
        try:
            with session.begin_nested():
                session.execute(
                    insert(UsageCounter).values(
                        holder_kind=entitlement.holder_kind,
                        holder_id=entitlement.holder_id,
                        limit_key=entitlement.key.db_name,
                        period_start=period_start,
                        used=0,
                    )
                )
        except IntegrityError:
            pass  # ya existía: seguimos al UPDATE.

    def _current_usage(self, entitlement: Entitlement) -> int:
        # Un nivel no se gasta: lo consumido es siempre 0 y lo que importa es
        # el tope. Así "Mi plan" puede pintarlo sin caso especial.
        if entitlement.period is LimitPeriod.TIER:
            return 0

        if entitlement.period is LimitPeriod.STOCK:
            return self._count_stock(entitlement)

        return self._read_counter(
            get_db_session(), entitlement, period_start_for(entitlement.period)
        )

    @staticmethod
    def _read_counter(session, entitlement: Entitlement, period_start: date) -> int:
        row = session.get(
            UsageCounter,
            (
                entitlement.holder_kind,
                entitlement.holder_id,
                entitlement.key.db_name,
                period_start,
            ),
        )
        return row.used if row is not None else 0

    @staticmethod
    def _count_stock(entitlement: Entitlement) -> int:
        counter = STOCK_COUNTERS.get(entitlement.key)
        if counter is None:
            raise NotImplementedError(
                f"La clave de existencias '{entitlement.key.db_name}' no tiene contador "
                f"registrado en STOCK_COUNTERS. Anyadelo antes de exigirla."
            )

        return counter(get_db_session(), QuotaManager._holder_user_ids(entitlement))

    @staticmethod
    def _holder_user_ids(entitlement: Entitlement) -> list[int]:
        """Usuarios cuyas existencias suman para este titular.

        Cuando paga la organización, la bolsa es común: cuenta lo que tienen
        entre todos sus miembros. Cuando paga el usuario, es solo él.
        """
        if entitlement.holder_kind != "org":
            return [entitlement.holder_id]

        from ..repositories import OrganizationMemberRepository

        return build_repository(OrganizationMemberRepository).user_ids_of(entitlement.holder_id)
