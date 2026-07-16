import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.exc import IntegrityError
from typing import Literal

from .model import Storable, Vault

from src.modules.users import User
from src.modules.infrastructure.unit_of_work import UnitOfWork
from src.modules.infrastructure.session import build_repository
from src.modules.shared import utcnow_naive

from .repositories import (
    VaultRepository,
    StorableRepository,
)
from .storable_specs import STORABLE_SPECS, SPEC_BY_MODEL, JSON_TO_ATTR

logger = logging.getLogger(__name__)

StorableKind = Literal[
    "account",
    "creditcard",
    "securenote",
    "identity",
    "bankaccount",
    "wifi",
    "license",
]


class VaultManager:
    """
    Gestor de almacenes (Vaults) y elementos almacenables (Storables).

    Toda la persistencia se realiza a través de los repositorios
    usando UnitOfWork. El manager no gestiona sesiones directamente.
    """

    def __init__(self, user: User) -> None:
        self.active_user = user

    @staticmethod
    def _parse_dt(value: Optional[str]) -> datetime:
        if not value:
            return utcnow_naive()
        try:
            dt = datetime.fromisoformat(value)
            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        except Exception as e:
            logger.warning("Failed to parse datetime value %r, defaulting to utcnow", value, exc_info=True)
            return utcnow_naive()

    def _ensure_vault_ownership(self, vault: Vault) -> None:
        if vault.user_id != self.active_user.id:
            raise PermissionError(
                f"El usuario {self.active_user.id} no es dueño del vault {vault.id}"
            )

    def get_vault_by_id(self, vault_id: int) -> Optional[Vault]:
        repo = build_repository(VaultRepository)
        vault = repo.get_by_id(vault_id)
        if vault is None:
            logger.warning(f"Vault {vault_id} no encontrado")
            return None
        self._ensure_vault_ownership(vault)
        return vault

    def get_vault_for_user(self, is_recovery: bool = False) -> Optional[Vault]:
        repo = build_repository(VaultRepository)
        vault = repo.get_by_user(self.active_user.id)
        return vault

    def upsert_vault_from_json(
        self,
        data: Dict[str, Any],
        is_recovery: bool = False,
    ) -> Tuple[Vault, bool]:
        try:
            algorithm = data.get("algorithm", {}) or {}

            with UnitOfWork() as uow:
                vault_repo = VaultRepository(uow)

                existing_vault = vault_repo.get_by_user(self.active_user.id)
                created = existing_vault is None

                if existing_vault is None:
                    vault = Vault(
                        user_id=self.active_user.id,
                        checker=data["checker"],
                        vault_key=data["vaultKey"],
                        transformation=algorithm.get("transformation", ""),
                        kdf=algorithm.get("kdf", ""),
                        kdf_iterations=int(algorithm.get("kdfIterations", 0)),
                        kdf_memory=int(algorithm.get("kdfMemoryKiB", 0)),
                        kdf_parallelism=int(algorithm.get("kdfParallelism", 1)),
                        salt=algorithm.get("salt", ""),
                    )
                    vault_repo.save(vault)
                    vault_id = vault.id
                else:
                    self._ensure_vault_ownership(existing_vault)
                    existing_vault.checker = data["checker"]
                    existing_vault.vault_key = data["vaultKey"]
                    existing_vault.transformation = algorithm.get("transformation", "")
                    existing_vault.kdf = algorithm.get("kdf", "")
                    existing_vault.kdf_iterations = int(algorithm.get("kdfIterations", 0))
                    existing_vault.kdf_memory = int(algorithm.get("kdfMemoryKiB", 0))
                    existing_vault.kdf_parallelism = int(algorithm.get("kdfParallelism", 1))
                    existing_vault.salt = algorithm.get("salt", "")

                    for st in list(existing_vault.storables):
                        uow.session.delete(st)
                    uow.session.flush()

                    vault_id = existing_vault.id

                vault = vault_repo.get_by_id(vault_id)
                if not vault:
                    raise ValueError(f"Vault {vault_id} no encontrado tras creación")

                for spec in STORABLE_SPECS.values():
                    for item in data.get(spec.json_list_key, []) or []:
                        uow.session.add(spec.model(
                            vault=vault,
                            internal_id=item.get("id"),
                            title=item.get("title"),
                            created_at=self._parse_dt(item.get("createdAt")),
                            updated_at=self._parse_dt(item.get("updatedAt")),
                            **{attr: item.get(json_key, "") for attr, json_key in spec.fields},
                        ))

            logger.info(
                f"Vault {vault.id} {'creado' if created else 'actualizado'} "
                f"para user {self.active_user.id} (is_recovery={is_recovery})"
            )
            return vault, created

        except IntegrityError as ie:
            logger.error(f"Error de integridad en upsert de vault: {ie}", exc_info=True)
            raise
        except Exception as e:
            logger.error(
                f"Error en upsert de vault desde JSON: {e}", exc_info=True
            )
            raise

    def upsert_vault_from_json_string(
        self,
        data: str,
        is_recovery: bool = False
    ):
        self.upsert_vault_from_json(
            json.loads(data),
            is_recovery
        )

    def update_vault_metadata(self, data: Dict[str, Any]) -> Optional[Vault]:
        """Refresca SOLO los metadatos cripto del vault tras un cambio de
        contraseña maestra: ``checker``, ``vault_key`` y los parámetros de
        ``algorithm``.

        A diferencia de :meth:`upsert_vault_from_json`, **no toca los storables**:
        como la ``vaultKey`` que los cifra no cambia, su ciphertext permanece
        válido y no debe borrarse/recrearse.

        Devuelve el vault actualizado, o ``None`` si el usuario no tiene vault.
        """
        algorithm = data.get("algorithm", {}) or {}

        with UnitOfWork() as uow:
            vault_repo = VaultRepository(uow)
            vault = vault_repo.get_by_user(self.active_user.id)
            if vault is None:
                return None

            self._ensure_vault_ownership(vault)

            vault.checker = data["checker"]
            vault.vault_key = data["vaultKey"]
            vault.transformation = algorithm.get("transformation", "")
            vault.kdf = algorithm.get("kdf", "")
            vault.kdf_iterations = int(algorithm.get("kdfIterations", 0))
            vault.kdf_memory = int(algorithm.get("kdfMemoryKiB", 0))
            vault.kdf_parallelism = int(algorithm.get("kdfParallelism", 1))
            vault.salt = algorithm.get("salt", "")
            # Señal para que otros clientes detecten el cambio de contraseña maestra.
            vault.metadata_version = (vault.metadata_version or 1) + 1

        logger.info(
            f"Metadatos del vault {vault.id} refrescados (cambio de contraseña, "
            f"v{vault.metadata_version}) para user {self.active_user.id}"
        )
        return vault

    def export_vault_to_json(self, vault_id: int) -> Dict[str, Any]:
        repo = build_repository(VaultRepository)
        vault = repo.get_by_id(vault_id)
        if vault is None:
            raise ValueError(f"Vault {vault_id} no encontrado")
        self._ensure_vault_ownership(vault)

        algorithm = {
            "transformation": vault.transformation,
            "kdf": vault.kdf,
            "kdfIterations": str(vault.kdf_iterations),
            "kdfMemoryKiB": str(vault.kdf_memory),
            "kdfParallelism": str(vault.kdf_parallelism),
            "salt": vault.salt,
        }

        by_list_key: Dict[str, List[Dict[str, Any]]] = {
            spec.json_list_key: [] for spec in STORABLE_SPECS.values()
        }

        for st in vault.storables:
            spec = SPEC_BY_MODEL.get(type(st))
            if spec is None:
                continue
            by_list_key[spec.json_list_key].append({
                "id": st.internal_id,
                "title": st.title,
                "createdAt": st.created_at.strftime('%Y-%m-%dT%H:%M:%S.%fZ') if st.created_at else None,
                "updatedAt": st.updated_at.strftime('%Y-%m-%dT%H:%M:%S.%fZ') if st.updated_at else None,
                "allowedUsers": [],
                **{json_key: getattr(st, attr) for attr, json_key in spec.fields},
            })

        return {
            "checker": vault.checker,
            "vaultKey": vault.vault_key,
            "metadataVersion": vault.metadata_version,
            "algorithm": algorithm,
            **by_list_key,
        }

    def find_storables(
            self,
            *,
            vault_id: Optional[int] = None,
            limit: Optional[int] = None,
            **filters: Any,
        ) -> List[Storable]:
        repo = build_repository(StorableRepository)

        if vault_id is not None:
            vault = self.get_vault_by_id(vault_id)
            if vault is None:
                return []
            storables = repo.get_by_vault(vault_id)
        else:
            storables = repo.get_by_user(self.active_user.id, limit or 100)

        result = storables
        for field, value in filters.items():
            if not hasattr(Storable, field):
                raise ValueError(f"Campo inválido para Storable: {field}")
            result = [s for s in result if getattr(s, field, None) == value]

        return result

    def get_storable_by(self, **filters: Any) -> Optional[Storable]:
        results = self.find_storables(limit=2, **filters)
        if not results:
            return None
        if len(results) > 1:
            raise ValueError(
                f"Más de un Storable coincide con los filtros: {filters!r}"
            )
        return results[0]

    def get_storable(self, storable_id: int) -> Optional[Storable]:
        return self.get_storable_by(id=storable_id)

    def list_storables(self, vault_id: int) -> List[Storable]:
        vault = self.get_vault_by_id(vault_id)
        if vault is None:
            return []
        return list(vault.storables)

    def add_storable_to_vault(
        self,
        vault_id: int,
        kind: StorableKind,
        *,
        internal_id: Optional[str] = None,
        title: Optional[str] = None,
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
        **payload: Any,
    ) -> Storable:
        vault = self.get_vault_by_id(vault_id)
        if vault is None:
            raise ValueError(f"Vault {vault_id} no encontrado")

        spec = STORABLE_SPECS.get(kind)
        if spec is None:
            raise ValueError(f"Tipo de storable no soportado: {kind}")

        created_at = created_at or utcnow_naive()
        updated_at = updated_at or created_at

        st = spec.model(
            vault=vault,
            internal_id=internal_id,
            title=title,
            created_at=created_at,
            updated_at=updated_at,
            **{attr: payload.get(attr, "") for attr, _ in spec.fields},
        )

        try:
            with UnitOfWork() as uow:
                repo = StorableRepository(uow)
                repo.save(st)
            logger.info(f"Storable {st.id} creado en vault {vault_id}")
            return st
        except IntegrityError as ie:
            logger.error(f"Error de integridad añadiendo storable: {ie}", exc_info=True)
            raise
        except Exception as e:
            logger.error(f"Error añadiendo storable: {e}", exc_info=True)
            raise

    def update_storable(
        self,
        storable_id: int,
        *,
        title: Optional[str] = None,
        internal_id: Optional[str] = None,
        **fields: Any,
    ) -> Storable:
        """Actualiza los campos presentes (no ``None``) de un storable.

        ``fields`` acepta cualquier atributo propio del tipo concreto de
        ``st`` (p. ej. ``username``/``domain``/``password`` para un
        ``Account``); campos que no pertenecen a ese tipo se ignoran, igual
        que antes cuando el parámetro no aplicaba al ``isinstance`` activo.
        """
        with UnitOfWork() as uow:
            repo = StorableRepository(uow)
            st = repo.get_by_id(storable_id)
            if st is None:
                raise ValueError(f"Storable {storable_id} no encontrado")

            try:
                changed = False
                if title is not None:
                    st.title = title
                    changed = True
                if internal_id is not None:
                    st.internal_id = internal_id
                    changed = True

                spec = SPEC_BY_MODEL.get(type(st))
                if spec is not None:
                    for attr, _ in spec.fields:
                        value = fields.get(attr)
                        if value is not None:
                            setattr(st, attr, value)
                            changed = True

                if changed:
                    st.updated_at = utcnow_naive()
                    repo.update(st)
                    logger.info(f"Storable {st.id} actualizado correctamente")
                else:
                    logger.info(f"Storable {st.id}: sin cambios")

                return st

            except IntegrityError as ie:
                logger.error(f"Error de integridad actualizando storable {storable_id}: {ie}", exc_info=True)
                raise
            except Exception as e:
                logger.error(
                    f"Error actualizando storable {storable_id}: {e}", exc_info=True
                )
                raise

    def bulk_update_storables(
        self,
        operations: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        vault_cache: Dict[bool, Optional[Vault]] = {}
        field_map = JSON_TO_ATTR

        for op in operations:
            internal_id = op.get("internalId")
            is_recovery = bool(op.get("isRecovery", False))

            if not internal_id:
                results.append({
                    "internalId": None,
                    "isRecovery": is_recovery,
                    "status": "error",
                    "error": "Missing internalId",
                })
                continue

            changes = op.get("changes") or {}
            if not isinstance(changes, dict) or not changes:
                results.append({
                    "internalId": internal_id,
                    "isRecovery": is_recovery,
                    "status": "skipped",
                    "error": "No changes provided",
                })
                continue

            try:
                if is_recovery not in vault_cache:
                    vault_cache[is_recovery] = self.get_vault_for_user(
                        is_recovery=is_recovery
                    )

                vault = vault_cache[is_recovery]
                if not vault:
                    results.append({
                        "internalId": internal_id,
                        "isRecovery": is_recovery,
                        "status": "vault_not_found",
                    })
                    continue

                st = self.get_storable_by(
                    vault_id=vault.id,
                    internal_id=internal_id,
                )
                if not st:
                    results.append({
                        "internalId": internal_id,
                        "isRecovery": is_recovery,
                        "status": "not_found",
                    })
                    continue

                update_kwargs: Dict[str, Any] = {}
                for json_field, value in changes.items():
                    if json_field not in field_map:
                        continue
                    update_kwargs[field_map[json_field]] = value

                if not update_kwargs:
                    results.append({
                        "internalId": internal_id,
                        "isRecovery": is_recovery,
                        "status": "skipped",
                        "error": "No valid fields to update",
                    })
                    continue

                self.update_storable(st.id, **update_kwargs)
                results.append({
                    "internalId": internal_id,
                    "isRecovery": is_recovery,
                    "status": "updated",
                })

            except Exception as e:
                logger.error(
                    f"Error aplicando cambios al storable {internal_id} "
                    f"(is_recovery={is_recovery}): {e}",
                    exc_info=True,
                )
                results.append({
                    "internalId": internal_id,
                    "isRecovery": is_recovery,
                    "status": "error",
                    "error": str(e),
                })

        return results

    def delete_storable(self, storable_id: int) -> bool:
        st = self.get_storable(storable_id)
        if st is None:
            return False

        try:
            with UnitOfWork() as uow:
                repo = StorableRepository(uow)
                repo.delete(st)
            logger.info(f"Storable {storable_id} eliminado")
            return True
        except Exception as e:
            logger.error(f"Error eliminando storable {storable_id}: {e}", exc_info=True)
            raise
