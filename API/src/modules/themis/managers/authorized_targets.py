"""AuthorizedTargetManager — registro de objetivos autorizados (roadmap §6).

Antes de que Lybra ejecute cualquier operación que toque la red del objetivo
(autodescubrimiento propio, fingerprinting propio, comprobaciones activas del
runtime), el objetivo debe estar en este registro por usuario. Es un gate
legal, no de red o de privilegios: complementa, no sustituye, el rechazo de
IPs privadas que ya hace ``ScanManager.validate_ip``.
"""

import ipaddress
import logging

from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import read_repo
from ..repositories import AuthorizedTargetRepository
from ..model import AuthorizedTarget
from ..exceptions import (
    AuthorizedTargetNotFoundError,
    DuplicateAuthorizedTargetError,
    IPValidationError,
)

logger = logging.getLogger(__name__)


class AuthorizedTargetManager:
    """CRUD y comprobación de pertenencia para el registro de objetivos autorizados."""

    @staticmethod
    def _normalize(target: str) -> str:
        """Valida ``target`` como IP o CIDR y devuelve su forma canónica."""
        try:
            return str(ipaddress.ip_network(target.strip(), strict=False))
        except ValueError as exc:
            raise IPValidationError(
                message=f"'{target}' no es una IP ni un CIDR válido",
                ip_spec=target,
            ) from exc

    def add(self, user_id: int, target: str, label: str | None = None) -> AuthorizedTarget:
        """Añade un objetivo al registro del usuario. Rechaza duplicados."""
        normalized = self._normalize(target)
        with UnitOfWork() as uow:
            repo = AuthorizedTargetRepository(uow)
            if repo.get_by_target_and_user(normalized, user_id):
                raise DuplicateAuthorizedTargetError(normalized)
            entry = AuthorizedTarget(user_id=user_id, target=normalized, label=label or None)
            repo.save(entry)
        logger.info(f"Objetivo autorizado '{normalized}' añadido por usuario {user_id}")
        return entry

    def list(self, user_id: int) -> list[AuthorizedTarget]:
        """Lista el registro completo del usuario."""
        return read_repo(AuthorizedTargetRepository).get_by_user(user_id)

    def remove(self, target_id: int, user_id: int) -> None:
        """Elimina una entrada del registro, verificando propiedad."""
        with UnitOfWork() as uow:
            repo = AuthorizedTargetRepository(uow)
            entry = repo.get_by_id_and_user(target_id, user_id)
            if entry is None:
                raise AuthorizedTargetNotFoundError(target_id)
            repo.delete(entry)
        logger.info(f"Objetivo autorizado {target_id} eliminado por usuario {user_id}")

    @staticmethod
    def is_authorized(user_id: int, target: str) -> bool:
        """True si ``target`` (una IP) cae dentro de alguna entrada autorizada del usuario."""
        try:
            ip = ipaddress.ip_address(target.strip())
        except ValueError:
            return False
        entries = read_repo(AuthorizedTargetRepository).get_by_user(user_id)
        return any(ip in ipaddress.ip_network(entry.target, strict=False) for entry in entries)
