"""
Repositories for the Acheron encrypted vault module.

Provides typed data access for Vault, Storable (polymorphic), Account, and CreditCard.

Classes:
    VaultRepository: Repository for Vault entities.
    StorableRepository: Repository for Storable entities.
    AccountRepository: Repository for Account entities.
    CreditCardRepository: Repository for CreditCard entities.

Usage:
    with UnitOfWork() as uow:
        vault_repo = VaultRepository(uow)
        storable_repo = StorableRepository(uow)

        vault = vault_repo.get_by_user(user_id=1)
        storables = storable_repo.get_by_vault(vault.id)
"""

from __future__ import annotations

from typing import List, Optional

from sqlalchemy.orm import Session

from src.modules.features.acheron.model import Account, CreditCard, Storable, Vault
from src.modules.infrastructure import BaseRepository, UnitOfWork


class VaultRepository(BaseRepository[Vault]):
    """
    Repository for the Vault entity (encrypted vault for secrets).

    Attributes:
        _model:  Vault (inherited from BaseRepository).
        _uow:    Active Unit of Work (inherited from BaseRepository).

    Example:
    >>> with UnitOfWork() as uow:
    ...     repo = VaultRepository(uow)
    ...     vault = repo.get_by_user(user_id=1)
    """

    def __init__(self, uow: UnitOfWork | None = None, session: Session | None = None) -> None:
        super().__init__(Vault, uow=uow, session=session)

    # =========================================================================
    # DOMAIN QUERIES
    # =========================================================================

    def get_by_user(self, user_id: int) -> Optional[Vault]:
        """
        Retrieve the vault for a user.

        Args:
            user_id: Primary key of the user.

        Returns:
            Vault instance, or None if not found.
        """
        return (
            self._session.query(Vault)
            .filter(Vault.user_id == user_id)
            .one_or_none()
        )

    def get_all_by_user(self, user_id: int) -> List[Vault]:
        """
        Retrieve all vaults for a user.

        Args:
            user_id: Primary key of the user.

        Returns:
            List of Vault instances.
        """
        return (
            self._session.query(Vault)
            .filter(Vault.user_id == user_id)
            .all()
        )

    # =========================================================================
    # CREATE / UPDATE
    # =========================================================================

    def save_with_storables(
        self,
        vault: Vault,
        accounts_data: List[dict] | None = None,
        creditcards_data: List[dict] | None = None,
    ) -> Vault:
        """
        Save a vault and optionally create storables in the same transaction.

        Args:
            vault: Vault instance to save.
            accounts_data: Optional list of account dictionaries.
            creditcards_data: Optional list of credit card dictionaries.

        Returns:
            Saved Vault instance.
        """
        self._session.add(vault)
        self._session.flush()

        if accounts_data:
            for acc_data in accounts_data:
                self._session.add(Account(
                    vault=vault,
                    internal_id=acc_data.get("id"),
                    title=acc_data.get("title"),
                    created_at=acc_data.get("created_at"),
                    updated_at=acc_data.get("updated_at"),
                    username=acc_data.get("username", ""),
                    domain=acc_data.get("domain", ""),
                    password=acc_data.get("password", ""),
                ))

        if creditcards_data:
            for cc_data in creditcards_data:
                self._session.add(CreditCard(
                    vault=vault,
                    internal_id=cc_data.get("id"),
                    title=cc_data.get("title"),
                    created_at=cc_data.get("created_at"),
                    updated_at=cc_data.get("updated_at"),
                    cardholder_name=cc_data.get("cardholder_name", ""),
                    card_number=cc_data.get("card_number", ""),
                    expiration_date=cc_data.get("expiration_date", ""),
                    postal_code=cc_data.get("postal_code", ""),
                    cvv=cc_data.get("cvv", ""),
                ))

        self._session.flush()
        self._session.refresh(vault)
        return vault

    def delete_with_storables(self, vault: Vault) -> None:
        """
        Delete a vault and all its storables.

        Args:
            vault: Vault instance to delete.
        """
        for st in list(vault.storables):
            self._session.delete(st)
        self._session.flush()
        self._session.delete(vault)


class StorableRepository(BaseRepository[Storable]):
    """
    Repository for the Storable entity (polymorphic base for secrets).

    Attributes:
        _model:  Storable (inherited from BaseRepository).
        _uow:    Active Unit of Work (inherited from BaseRepository).

    Example:
    >>> with UnitOfWork() as uow:
    ...     repo = StorableRepository(uow)
    ...     storables = repo.get_by_vault(vault_id=1)
    """

    def __init__(self, uow: UnitOfWork | None = None, session: Session | None = None) -> None:
        super().__init__(Storable, uow=uow, session=session)

    # =========================================================================
    # DOMAIN QUERIES
    # =========================================================================

    def get_by_vault(self, vault_id: int) -> List[Storable]:
        """
        Retrieve all storables for a vault.

        Args:
            vault_id: Primary key of the vault.

        Returns:
            List of Storable instances.
        """
        return (
            self._session.query(Storable)
            .filter(Storable.vault_id == vault_id)
            .all()
        )

    def get_by_internal_id(self, vault_id: int, internal_id: str) -> Optional[Storable]:
        """
        Retrieve a storable by its internal ID within a vault.

        Args:
            vault_id: Primary key of the vault.
            internal_id: Internal identifier within the vault.

        Returns:
            Storable instance, or None if not found.
        """
        return (
            self._session.query(Storable)
            .filter(
                Storable.vault_id == vault_id,
                Storable.internal_id == internal_id,
            )
            .one_or_none()
        )

    def get_by_user(self, user_id: int, limit: int = 100) -> List[Storable]:
        """
        Retrieve all storables for a user's vaults.

        Args:
            user_id: Primary key of the user.
            limit: Maximum number of results (default: 100).

        Returns:
            List of Storable instances.
        """
        return (
            self._session.query(Storable)
            .join(Vault)
            .filter(Vault.user_id == user_id)
            .limit(limit)
            .all()
        )

    def get_by_vault_and_type(self, vault_id: int, storable_type: str) -> List[Storable]:
        """
        Retrieve all storables of a specific type for a vault.

        Args:
            vault_id: Primary key of the vault.
            storable_type: Type discriminator ('account' or 'creditcard').

        Returns:
            List of Storable instances.
        """
        return (
            self._session.query(Storable)
            .filter(
                Storable.vault_id == vault_id,
                Storable.type == storable_type,
            )
            .all()
        )
