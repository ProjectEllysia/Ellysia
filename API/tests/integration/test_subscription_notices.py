"""Avisos por correo de caducidad e impago.

Lo que importa de este job es lo que NO hace: no degrada, no cancela y no toca
ninguna fila. Si no corre, se pierde un correo — no se regala un plan de pago ni
se le corta a nadie antes de tiempo. Hay un test dedicado a eso.
"""

from datetime import timedelta
from unittest import mock

import pytest

from src.modules.accounts.managers import SubscriptionManager
from src.modules.accounts.services.notices import send_subscription_notices
from src.modules.shared import utcnow_naive

pytestmark = pytest.mark.integration


NOW = utcnow_naive()


@pytest.fixture()
def sent_emails():
    mailer = mock.Mock()
    with mock.patch("src.modules.accounts.services.notices.build_mailer",
                    return_value=mailer):
        yield mailer.send.call_args_list


def test_warns_about_a_plan_ending_soon(app, seeded_plans, regular_user, sent_emails):
    with app.app_context():
        SubscriptionManager().activate(
            regular_user.id, "gold", period_end=NOW + timedelta(days=2),
        )
        sent = send_subscription_notices()

    assert sent["expiring"] == 1
    assert "termina" in sent_emails[0].args[0].subject.lower()


def test_says_nothing_about_a_plan_that_ends_far_away(
    app, seeded_plans, regular_user, sent_emails
):
    """Avisar con un mes de antelación es ruido; el aviso llega cuando sirve."""
    with app.app_context():
        SubscriptionManager().activate(
            regular_user.id, "gold", period_end=NOW + timedelta(days=30),
        )
        sent = send_subscription_notices()

    assert sent["expiring"] == 0
    assert sent_emails == []


def test_says_nothing_about_a_plan_that_already_ended(
    app, seeded_plans, regular_user, sent_emails
):
    """Ya caducó: el aviso llega tarde y solo molesta."""
    with app.app_context():
        SubscriptionManager().activate(
            regular_user.id, "gold", period_end=NOW - timedelta(days=1),
        )
        sent = send_subscription_notices()

    assert sent["expiring"] == 0


def test_warns_about_an_unpaid_subscription_still_in_grace(
    app, seeded_plans, regular_user, sent_emails
):
    with app.app_context():
        manager = SubscriptionManager()
        manager.activate(regular_user.id, "gold", period_end=NOW - timedelta(days=1))
        manager.mark_past_due(regular_user.id, grace_until=NOW + timedelta(days=5))
        sent = send_subscription_notices()

    assert sent["past_due"] == 1
    assert "pago" in sent_emails[0].args[0].subject.lower()


def test_only_the_holder_is_warned(app, seeded_plans, make_user, make_subscription, sent_emails):
    """Los miembros de una organización cuyo dueño no ha pagado no reciben nada.

    Verán en la interfaz que ciertas funciones ya no están, pero "tu jefe no ha
    pagado" no es un mensaje nuestro que dar.
    """
    from src.modules.accounts.model import Organization, OrganizationMember
    from src.modules.infrastructure import unit_of_work

    owner, member = make_user(), make_user()
    with app.app_context():
        SubscriptionManager().activate(
            owner.id, "gold", organization_enabled=True,
            period_end=NOW + timedelta(days=2),
        )
        with unit_of_work.UnitOfWork() as uow:
            organization = Organization(name="Acme", slug="acme", owner_user_id=owner.id)
            uow.session.add(organization)
            uow.session.flush()
            uow.session.add_all([
                OrganizationMember(organization_id=organization.id, user_id=owner.id,
                                   member_role="owner"),
                OrganizationMember(organization_id=organization.id, user_id=member.id,
                                   member_role="member"),
            ])
            uow.session.flush()

        send_subscription_notices()

    recipients = [call.args[0].to for call in sent_emails]
    assert recipients == [f"user{owner.id}@ellysia.test"]


def test_the_job_never_changes_a_subscription(app, seeded_plans, regular_user, sent_emails):
    """La red de seguridad de todo el diseño: la vigencia se calcula al leer, y
    este job solo lee. Si algún día degradase, el día que no corra habría gente
    con un plan de pago gratis y nadie se enteraría.
    """
    from src.modules.accounts.repositories import SubscriptionRepository
    from src.modules.infrastructure import unit_of_work

    with app.app_context():
        SubscriptionManager().activate(
            regular_user.id, "gold", period_end=NOW + timedelta(days=1),
        )
        with unit_of_work.UnitOfWork() as uow:
            before = SubscriptionRepository(uow).get_by_user(regular_user.id).to_dict()

        send_subscription_notices()

        with unit_of_work.UnitOfWork() as uow:
            after = SubscriptionRepository(uow).get_by_user(regular_user.id).to_dict()

    assert before == after


def test_a_broken_relay_does_not_stop_the_rest(app, seeded_plans, make_user):
    """Que no salga un correo no debe impedir que salgan los demás."""
    first, second = make_user(), make_user()
    with app.app_context():
        manager = SubscriptionManager()
        for user in (first, second):
            manager.activate(user.id, "gold", period_end=NOW + timedelta(days=1))

        with mock.patch("src.modules.accounts.services.notices.build_mailer",
                        side_effect=RuntimeError("relay caido")):
            sent = send_subscription_notices()

    assert sent == {"expiring": 0, "past_due": 0}
