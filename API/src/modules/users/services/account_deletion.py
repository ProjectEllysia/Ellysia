"""
Borrado de una cuenta y de todo lo que cuelga de ella.

**Por qué existe este fichero.** Veintiséis claves ajenas apuntan a ``User`` y
solo dos tienen ``ON DELETE CASCADE``. De las demás, unas cuantas cuelgan de una
``relationship`` con ``cascade="all, delete-orphan"`` y se van solas al borrar
por el ORM; otras diez no cuelgan de nada, así que un ``DELETE FROM "User"``
falla en Postgres con una violación de clave ajena.

Y no se notaría en los tests: la suite corre sobre SQLite, que **no** aplica
claves ajenas salvo que se active un PRAGMA que el proyecto no activa. Un
barrido incompleto pasaría verde aquí y daría un 500 en producción. Por eso el
barrido es explícito y hay un test que recorre el grafo real de claves ajenas
en vez de fiarse del borrado.

**Por qué una lista y no un registro.** Se puede leer de arriba abajo y saber
exactamente qué se destruye. Un registro donde cada módulo se apunta solo queda
más desacoplado y obliga a ir a cinco ficheros para responder "¿qué borra este
botón?" — que es justo la pregunta que hay que poder responder rápido.
"""

import logging
from typing import Callable

from src.modules.infrastructure import UnitOfWork

logger = logging.getLogger(__name__)


# =========================================================================
# PURGAS POR MÓDULO
# =========================================================================
#
# Cada una borra lo que su módulo guarda de un usuario. Los imports van
# diferidos dentro de cada función: estas dependencias apuntan "hacia abajo"
# (users -> features) y al nivel de módulo cerrarían un ciclo.


def _purge_themis(uow: UnitOfWork, user_id: int) -> dict[str, int]:
    """Escaneos programados, carpetas, objetivos autorizados y traceroutes.

    Los ``Scan`` no van aquí: cuelgan de ``User.scans`` con
    ``cascade="all, delete-orphan"`` y se los lleva el ORM.
    """
    from src.modules.features.themis.model import (
        AuthorizedTarget,
        ProgramedScan,
        ScanFolder,
        Traceroute,
    )

    return _delete_by_user(uow, user_id, [ProgramedScan, ScanFolder, AuthorizedTarget, Traceroute])


def _purge_aegis(uow: UnitOfWork, user_id: int) -> dict[str, int]:
    """Perfil de organización, listas de distribución y campañas.

    Los destinatarios y las respuestas cuelgan de la lista y de la campaña por
    clave ajena; se borran con ellas.
    """
    from src.modules.features.aegis.model import (
        AegisOrgProfile,
        Campaign,
        CampaignAnswer,
        CampaignRecipient,
        DistributionList,
        Recipient,
    )

    counts: dict[str, int] = {}
    session = uow.session

    campaign_ids = [row[0] for row in session.query(Campaign.id).filter(Campaign.user_id == user_id)]
    list_ids = [
        row[0] for row in session.query(DistributionList.id)
        .filter(DistributionList.user_id == user_id)
    ]

    if campaign_ids:
        # Las respuestas cuelgan del destinatario de la campaña, no de la
        # campaña: hay que bajar dos niveles antes de borrar hacia arriba.
        recipient_ids = [
            row[0] for row in session.query(CampaignRecipient.id)
            .filter(CampaignRecipient.campaign_id.in_(campaign_ids))
        ]
        if recipient_ids:
            counts["CampaignAnswer"] = session.query(CampaignAnswer).filter(
                CampaignAnswer.campaign_recipient_id.in_(recipient_ids)
            ).delete(synchronize_session=False)
        counts["CampaignRecipient"] = session.query(CampaignRecipient).filter(
            CampaignRecipient.campaign_id.in_(campaign_ids)
        ).delete(synchronize_session=False)
    if list_ids:
        counts["Recipient"] = session.query(Recipient).filter(
            Recipient.list_id.in_(list_ids)
        ).delete(synchronize_session=False)

    counts.update(_delete_by_user(uow, user_id, [Campaign, DistributionList, AegisOrgProfile]))
    return counts


def _purge_iris(uow: UnitOfWork, user_id: int) -> dict[str, int]:
    """Buzones conectados. Los análisis cuelgan de ``User.analyses``."""
    from src.modules.features.iris.model import IrisMailboxConnection

    return _delete_by_user(uow, user_id, [IrisMailboxConnection])


def _purge_hygeia(uow: UnitOfWork, user_id: int) -> dict[str, int]:
    """Activos monitorizados, con sus muestras y anomalías."""
    from src.modules.features.hygeia.model import Anomaly, AssetSnapshot, MonitoredAsset

    session = uow.session
    asset_ids = [
        row[0] for row in session.query(MonitoredAsset.id)
        .filter(MonitoredAsset.user_id == user_id)
    ]

    counts: dict[str, int] = {}
    if asset_ids:
        counts["Anomaly"] = session.query(Anomaly).filter(
            Anomaly.asset_id.in_(asset_ids)
        ).delete(synchronize_session=False)
        counts["AssetSnapshot"] = session.query(AssetSnapshot).filter(
            AssetSnapshot.asset_id.in_(asset_ids)
        ).delete(synchronize_session=False)

    counts.update(_delete_by_user(uow, user_id, [MonitoredAsset]))
    return counts


def _purge_accounts(uow: UnitOfWork, user_id: int) -> dict[str, int]:
    """Suscripción, pertenencia y rastro en invitaciones.

    La **organización de la que es dueño se disuelve entera**: sus miembros se
    quedan sin ella. Es lo que hay que avisarle antes de pulsar el botón, y por
    eso ``preview_deletion`` lo cuenta.

    Las referencias de "quién invitó" o "quién asignó el plan" se ponen a NULL
    en vez de borrar la fila: son rastro histórico de otra persona, no datos de
    quien se va.
    """
    from src.modules.accounts.model import (
        Organization,
        OrganizationInvitation,
        OrganizationMember,
        Subscription,
    )

    session = uow.session
    counts: dict[str, int] = {}

    owned = session.query(Organization).filter(Organization.owner_user_id == user_id).one_or_none()
    if owned is not None:
        counts["OrganizationInvitation"] = session.query(OrganizationInvitation).filter(
            OrganizationInvitation.organization_id == owned.id
        ).delete(synchronize_session=False)
        counts["OrganizationMember"] = session.query(OrganizationMember).filter(
            OrganizationMember.organization_id == owned.id
        ).delete(synchronize_session=False)
        session.delete(owned)
        counts["Organization"] = 1

    # Invitaciones que emitió o que crearon su cuenta, en organizaciones ajenas.
    session.query(OrganizationInvitation).filter(
        OrganizationInvitation.created_user_id == user_id
    ).update({"created_user_id": None}, synchronize_session=False)
    session.query(OrganizationInvitation).filter(
        OrganizationInvitation.invited_by_user_id == user_id
    ).delete(synchronize_session=False)

    session.query(OrganizationMember).filter(
        OrganizationMember.invited_by_user_id == user_id
    ).update({"invited_by_user_id": None}, synchronize_session=False)
    session.query(Subscription).filter(
        Subscription.assigned_by_user_id == user_id
    ).update({"assigned_by_user_id": None}, synchronize_session=False)

    counts.update(_delete_by_user(uow, user_id, [OrganizationMember, Subscription]))
    return counts


def _purge_users(uow: UnitOfWork, user_id: int) -> dict[str, int]:
    """Desafíos MFA a medias.

    El resto de lo que guarda ``users`` (tokens, atributos, credencial TOTP y
    códigos de recuperación) cuelga de una ``relationship`` con cascada.
    """
    from src.modules.users.model import MFAChallenge

    return _delete_by_user(uow, user_id, [MFAChallenge])


#: Orden de barrido. Se ejecuta antes de borrar la fila de ``User``.
PURGES: list[tuple[str, Callable[[UnitOfWork, int], dict[str, int]]]] = [
    ("themis",   _purge_themis),
    ("aegis",    _purge_aegis),
    ("iris",     _purge_iris),
    ("hygeia",   _purge_hygeia),
    ("accounts", _purge_accounts),
    ("users",    _purge_users),
]


def _delete_by_user(uow: UnitOfWork, user_id: int, models: list) -> dict[str, int]:
    """Borra de cada modelo las filas cuyo ``user_id`` sea el dado."""
    counts = {}
    for model in models:
        counts[model.__tablename__] = (
            uow.session.query(model)
            .filter(model.user_id == user_id)
            .delete(synchronize_session=False)
        )
    return counts


def purge_user_data(uow: UnitOfWork, user_id: int) -> dict[str, int]:
    """Ejecuta todas las purgas y devuelve cuántas filas cayó cada tabla."""
    counts: dict[str, int] = {}
    for module_name, purge in PURGES:
        module_counts = purge(uow, user_id)
        counts.update({key: value for key, value in module_counts.items() if value})
        logger.debug(f"Purga de {module_name} para el usuario {user_id}: {module_counts}")
    uow.session.flush()
    return counts
