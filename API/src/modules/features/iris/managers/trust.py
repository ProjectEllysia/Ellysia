"""
IrisTrustPolicyManager — excepciones de confianza por usuario.

Permite a un usuario reducir un falso positivo recurrente sin tocar la
configuración global: declara un remitente o un dominio de confianza, con
motivo y caducidad. Las excepciones **no se borran**: revocar una la marca con
``revoked_at`` y la deja en el listado, para que la auditoría conserve qué
excepciones existieron, hasta cuándo y por qué. Cada análisis al que se aplica
guarda además su propio rastro (``IrisAnalysis.trust_applied``).

Qué hace una excepción al analizar un mensaje lo decide
``services/trust.py``; este manager solo gestiona su ciclo de vida.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from src.modules.infrastructure import UnitOfWork, build_repository
from src.modules.shared import assert_owned, isoformat_utc, utcnow_naive

from ..exceptions import IrisInvalidInputError, IrisTrustedSenderNotFoundError
from ..model import IrisTrustedSender, TrustKind
from ..repositories import IrisTrustedSenderRepository
from ..services.trust import (
    DEFAULT_TRUST_EXPIRY_DAYS,
    MAX_TRUST_EXPIRY_DAYS,
    MAX_TRUST_REASON_LENGTH,
    TrustEntry,
    normalize_trust_value,
)


def _status_of(entry: IrisTrustedSender, now: datetime) -> str:
    """Estado de una excepción en un instante dado.

    Args:
        entry: Fila ``IrisTrustedSender``.
        now: Instante de referencia (UTC naive).

    Returns:
        str: ``revoked`` si se revocó (aunque además haya caducado),
            ``expired`` si pasó su caducidad, o ``active``.
    """
    if entry.revoked_at is not None:
        return "revoked"
    if entry.expires_at <= now:
        return "expired"
    return "active"


class IrisTrustPolicyManager:
    """Alta, consulta y revocación de las excepciones de confianza de un usuario."""

    @staticmethod
    def entry_to_dict(entry: IrisTrustedSender, now: Optional[datetime] = None) -> Dict[str, Any]:
        """Serializa una excepción con las claves camelCase de la API.

        Args:
            entry: Fila ``IrisTrustedSender``.
            now: Instante con el que calcular ``status``. Por defecto ``None``:
                el actual.

        Returns:
            dict: ``trustedSenderId``, ``kind``, ``value``, ``reason``,
                ``status`` (``active``, ``expired`` o ``revoked``),
                ``createdAt``, ``expiresAt`` y ``revokedAt``.
        """
        return {
            "trustedSenderId": entry.id,
            "kind": entry.kind,
            "value": entry.value,
            "reason": entry.reason,
            "status": _status_of(entry, now or utcnow_naive()),
            "createdAt": isoformat_utc(entry.created_at),
            "expiresAt": isoformat_utc(entry.expires_at),
            "revokedAt": isoformat_utc(entry.revoked_at),
        }

    def create_entry(self, user_id: int, kind: str, value: str, reason: str,
                     expires_in_days: Optional[int] = None) -> Dict[str, Any]:
        """Crea una excepción de confianza para un usuario.

        Args:
            user_id: Usuario al que se aplica; también es quien la crea.
            kind: ``sender`` (una dirección exacta) o ``domain`` (el dominio
                del ``From`` y sus subdominios).
            value: Dirección o dominio; se normaliza con
                ``services/trust.normalize_trust_value``.
            reason: Por qué se confía en él. Obligatorio: sin motivo, la
                auditoría no sirve para nada. Se recorta a
                ``MAX_TRUST_REASON_LENGTH`` caracteres.
            expires_in_days: Días hasta que caduca, entre 1 y
                ``MAX_TRUST_EXPIRY_DAYS``. Por defecto ``None``:
                ``DEFAULT_TRUST_EXPIRY_DAYS``.

        Returns:
            dict: La excepción creada (ver ``entry_to_dict``).

        Raises:
            IrisInvalidInputError: Si el tipo, el valor, el motivo o la
                caducidad no son válidos, o si ya hay una excepción activa
                para el mismo valor.
        """
        if kind not in {member.value for member in TrustKind}:
            raise IrisInvalidInputError(f"Tipo de excepción desconocido: {kind!r}.")
        try:
            normalized = normalize_trust_value(kind, value)
        except ValueError as e:
            raise IrisInvalidInputError(str(e), user_message=str(e)) from e
        cleaned_reason = (reason or "").strip()[:MAX_TRUST_REASON_LENGTH]
        if not cleaned_reason:
            raise IrisInvalidInputError("La excepción necesita un motivo.",
                                        user_message="La excepción necesita un motivo.")
        days = DEFAULT_TRUST_EXPIRY_DAYS if expires_in_days is None else expires_in_days
        if not 1 <= days <= MAX_TRUST_EXPIRY_DAYS:
            message = f"La caducidad debe estar entre 1 y {MAX_TRUST_EXPIRY_DAYS} días."
            raise IrisInvalidInputError(message, user_message=message)

        now = utcnow_naive()
        with UnitOfWork() as uow:
            repo = IrisTrustedSenderRepository(uow)
            if repo.has_active(user_id, kind, normalized, now):
                message = f"Ya tienes una excepción activa para {normalized}."
                raise IrisInvalidInputError(message, user_message=message)
            entry = repo.save(IrisTrustedSender(
                user_id=user_id, kind=kind, value=normalized, reason=cleaned_reason,
                created_at=now, expires_at=now + timedelta(days=days),
            ))
            return self.entry_to_dict(entry, now)

    def list_entries(self, user_id: int, include_inactive: bool = False) -> List[Dict[str, Any]]:
        """Excepciones de un usuario, de la más reciente a la más antigua.

        Args:
            user_id: Dueño de las excepciones.
            include_inactive: Si ``True``, incluye también las caducadas y las
                revocadas: es la vista de auditoría. Por defecto ``False``.

        Returns:
            List[dict]: Las excepciones (ver ``entry_to_dict``).
        """
        now = utcnow_naive()
        entries = build_repository(IrisTrustedSenderRepository).get_by_user(user_id)
        serialized = [self.entry_to_dict(entry, now) for entry in entries]
        if include_inactive:
            return serialized
        return [entry for entry in serialized if entry["status"] == "active"]

    def revoke_entry(self, entry_id: int, user_id: int) -> Dict[str, Any]:
        """Revoca una excepción sin borrarla.

        Revocar dos veces no es un error: la segunda vez devuelve la excepción
        tal como quedó, con su fecha de revocación original.

        Args:
            entry_id: Excepción a revocar; debe ser del usuario.
            user_id: Usuario que revoca.

        Returns:
            dict: La excepción ya revocada (ver ``entry_to_dict``).

        Raises:
            IrisTrustedSenderNotFoundError: Si no existe o no es suya.
        """
        with UnitOfWork() as uow:
            entry = assert_owned(IrisTrustedSenderRepository, entry_id, user_id,
                                 IrisTrustedSenderNotFoundError, uow=uow)
            if entry.revoked_at is None:
                entry.revoked_at = utcnow_naive()
                IrisTrustedSenderRepository(uow).update(entry)
            return self.entry_to_dict(entry)

    @staticmethod
    def get_active_entries(user_id: int) -> List[TrustEntry]:
        """Excepciones que el motor de análisis debe tener en cuenta ahora.

        Args:
            user_id: Dueño del análisis.

        Returns:
            List[TrustEntry]: Las no revocadas y no caducadas; lista vacía si
                no tiene ninguna.
        """
        rows = build_repository(IrisTrustedSenderRepository).get_active_for_user(user_id, utcnow_naive())
        return [TrustEntry(id=row.id, kind=row.kind, value=row.value, reason=row.reason) for row in rows]
