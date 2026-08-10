"""Vigencia de una suscripción: la aritmética que sustituye al cron nocturno.

``is_effective`` es la única función que decide si una suscripción concede
derechos, y se llama en cada lectura. Por eso no hay ningún proceso de
degradación que pueda dejar de correr un fin de semana y regalar un plan de
pago sin que nadie se entere — pero por eso mismo un fallo aquí se nota en toda
la plataforma a la vez.
"""

from datetime import datetime, timedelta

import pytest

from src.modules.accounts.model import Subscription
from src.modules.accounts.services.limits import PERIODS, LimitKey, LimitPeriod
from src.modules.accounts.services.entitlements import is_effective

pytestmark = pytest.mark.unit


NOW = datetime(2026, 8, 6, 12, 0, 0)
LATER = NOW + timedelta(days=10)
EARLIER = NOW - timedelta(days=10)


def _subscription(**kwargs) -> Subscription:
    """Suscripción suelta, sin sesión: is_effective no toca base de datos."""
    defaults = {
        "status": "active",
        "current_period_end": None,
        "grace_until": None,
    }
    return Subscription(**{**defaults, **kwargs})


# --------------------------------------------------------------------- básicos

def test_no_subscription_is_not_effective():
    """No tener fila no es tener derechos de pago: es tener los del plan por
    defecto, y de eso se encarga resolve_effective_plan."""
    assert is_effective(None, NOW) is False


def test_active_without_period_end_never_expires():
    """El plan por defecto no caduca: sin fecha de fin no hay nada que vencer."""
    assert is_effective(_subscription(current_period_end=None), NOW) is True


def test_active_within_period_is_effective():
    assert is_effective(_subscription(current_period_end=LATER), NOW) is True


def test_active_after_period_end_is_not_effective():
    """La caducidad es aritmética de fechas en el momento de leer, no el
    resultado de que un job haya corrido."""
    assert is_effective(_subscription(current_period_end=EARLIER), NOW) is False


def test_trialing_behaves_exactly_like_active():
    """Un trial concede lo mismo que un plan pagado; lo único que cambia es lo
    que dice la interfaz y a qué operación llama su final."""
    for period_end, expected in ((LATER, True), (EARLIER, False)):
        assert is_effective(
            _subscription(status="trialing", current_period_end=period_end), NOW
        ) is expected


# -------------------------------------------------------------------- past_due

def test_past_due_within_grace_is_still_effective():
    """Un impago no corta al instante. Una tarjeta caducada es mucho más
    frecuente que un moroso, y cortarle la monitorización a alguien porque su
    banco rechazó un cargo el martes es un error caro."""
    assert is_effective(
        _subscription(status="past_due", grace_until=LATER), NOW
    ) is True


def test_past_due_after_grace_is_not_effective():
    assert is_effective(
        _subscription(status="past_due", grace_until=EARLIER), NOW
    ) is False


def test_past_due_without_grace_is_not_effective():
    """Sin ventana de cortesía no hay cortesía: fallo cerrado."""
    assert is_effective(
        _subscription(status="past_due", grace_until=None), NOW
    ) is False


# -------------------------------------------------------------------- canceled

def test_canceled_before_period_end_keeps_the_plan():
    """Cancelar NO corta; corta caducar.

    Una baja significa "no se renueva", y hasta el final del periodo el cliente
    sigue disfrutando lo que ya pagó. Confundir las dos cosas es quitarle lo
    pagado el día que pulsa "darme de baja".
    """
    assert is_effective(
        _subscription(status="canceled", current_period_end=LATER), NOW
    ) is True


def test_canceled_after_period_end_is_not_effective():
    assert is_effective(
        _subscription(status="canceled", current_period_end=EARLIER), NOW
    ) is False


def test_canceled_without_period_end_is_not_effective():
    """Baja inmediata (devolución, contracargo): sin periodo abierto, se acabó."""
    assert is_effective(
        _subscription(status="canceled", current_period_end=None), NOW
    ) is False


def test_unknown_status_is_not_effective():
    """Fallo cerrado ante un estado que no reconocemos — por ejemplo, uno que
    escribiera una pasarela futura sin que nadie lo mapeara aquí."""
    assert is_effective(_subscription(status="paused"), NOW) is False


# ------------------------------------------------------------ catálogo de claves

def test_limit_key_values_are_unique():
    """El valor del enum es lo que se guarda en PlanLimit y UsageCounter: un
    duplicado haría que dos características compartieran contador."""
    values = [key.value for key in LimitKey]
    assert len(values) == len(set(values))


def test_every_limit_key_declares_a_period():
    """Una clave sin periodo no se puede contar ni topar."""
    assert set(PERIODS) == set(LimitKey)
    assert all(isinstance(period, LimitPeriod) for period in PERIODS.values())
