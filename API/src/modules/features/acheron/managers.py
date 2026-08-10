import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.exc import IntegrityError
from typing import Literal

from .exceptions import VaultRevisionMismatchError
from .model import Storable, Vault

from src.modules.accounts import LimitKey, QuotaManager
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

    @staticmethod
    def _bump_revision(vault: Vault) -> int:
        """Único punto de incremento de ``Vault.revision``.

        Toda mutación del contenido del vault —upsert completo, rotación de la
        maestra y alta/edición/baja de storables— pasa por aquí. Tenerlo en un
        solo sitio es lo que evita que un endpoint nuevo se olvide de marcar el
        cambio y deje a los demás clientes con un snapshot que creen fresco.

        No confundir con ``metadata_version``: esa solo señala el cambio de
        contraseña maestra (y de ella depende la invalidación del secreto
        biométrico del móvil), así que no se reutiliza como token de
        concurrencia.
        """
        vault.revision = (vault.revision or 1) + 1
        return vault.revision

    @staticmethod
    def _require_revision(vault: Vault, expected: Optional[int]) -> None:
        """Rechaza una escritura basada en una revisión obsoleta del vault.

        ``expected is None`` significa que el cliente no mandó ``If-Match``: se
        acepta por compatibilidad con las apps ya desplegadas. La única
        excepción es el upsert completo (destructivo), donde la capa de
        endpoints exige la cabecera antes de llegar aquí.

        La comprobación y la escritura viven en la misma transacción de
        petición, pero sin bloqueo de fila: dos peticiones simultáneas con la
        misma revisión base podrían pasar ambas. Cubre el caso real —un
        snapshot obsoleto de minutos— no una carrera de milisegundos.
        """
        if expected is None:
            return
        current = vault.revision or 1
        if current != expected:
            raise VaultRevisionMismatchError(current=current, provided=expected)

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
        expected_revision: Optional[int] = None,
    ) -> Tuple[Vault, bool]:
        """Crea el vault, o lo **reemplaza entero** borrando sus storables.

        ``expected_revision`` es la revisión que el cliente cree tener: si no
        coincide con la del servidor se lanza ``VaultRevisionMismatchError``
        **antes** de tocar nada, así que el vault queda intacto.
        """
        try:
            algorithm = data.get("algorithm", {}) or {}

            with UnitOfWork() as uow:
                vault_repo = VaultRepository(uow)

                existing_vault = vault_repo.get_by_user(self.active_user.id)
                created = existing_vault is None

                if created:
                    # Solo al crearla: reemplazar una bóveda existente no es
                    # una bóveda nueva.
                    #
                    # OJO: Vault.user_id es UNIQUE, así que hoy nadie puede
                    # tener más de una y este tope funciona en la práctica como
                    # una puerta — 0 es "tu plan no incluye Acheron" y
                    # cualquier valor >= 1 es "sí". Los 3/10/ilimitado que
                    # promete la tabla de precios necesitan que la bóveda deje
                    # de ser única por usuario.
                    QuotaManager().consume(self.active_user.id, LimitKey.ACHERON_VAULTS)

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
                    # Antes de cualquier mutación: si la revisión no cuadra, el
                    # 409 sale de aquí con la sesión todavía limpia.
                    self._require_revision(existing_vault, expected_revision)
                    self._bump_revision(existing_vault)

                    existing_vault.checker = data["checker"]
                    existing_vault.vault_key = data["vaultKey"]
                    existing_vault.transformation = algorithm.get("transformation", "")
                    existing_vault.kdf = algorithm.get("kdf", "")
                    existing_vault.kdf_iterations = int(algorithm.get("kdfIterations", 0))
                    existing_vault.kdf_memory = int(algorithm.get("kdfMemoryKiB", 0))
                    existing_vault.kdf_parallelism = int(algorithm.get("kdfParallelism", 1))
                    existing_vault.salt = algorithm.get("salt", "")

                    for storable in list(existing_vault.storables):
                        uow.session.delete(storable)
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

    def update_vault_metadata(
        self,
        data: Dict[str, Any],
        expected_revision: Optional[int] = None,
    ) -> Optional[Vault]:
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
            self._require_revision(vault, expected_revision)

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
            self._bump_revision(vault)

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

        for storable in vault.storables:
            spec = SPEC_BY_MODEL.get(type(storable))
            if spec is None:
                continue
            by_list_key[spec.json_list_key].append({
                "id": storable.internal_id,
                "title": storable.title,
                "createdAt": storable.created_at.strftime('%Y-%m-%dT%H:%M:%S.%fZ') if storable.created_at else None,
                "updatedAt": storable.updated_at.strftime('%Y-%m-%dT%H:%M:%S.%fZ') if storable.updated_at else None,
                "allowedUsers": [],
                **{json_key: getattr(storable, attr) for attr, json_key in spec.fields},
            })

        return {
            "checker": vault.checker,
            "vaultKey": vault.vault_key,
            "metadataVersion": vault.metadata_version,
            "revision": vault.revision or 1,
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
            result = [storable for storable in result if getattr(storable, field, None) == value]

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
        expected_revision: Optional[int] = None,
        **payload: Any,
    ) -> Storable:
        vault = self.get_vault_by_id(vault_id)
        if vault is None:
            raise ValueError(f"Vault {vault_id} no encontrado")

        # Son existencias, contadas sobre la tabla real a través de la bóveda:
        # borrar un secreto devuelve el hueco. Va antes de tocar la sesión, por
        # el mismo motivo que la comprobación de revisión de abajo.
        QuotaManager().consume(self.active_user.id, LimitKey.ACHERON_ITEMS)

        # Antes de construir el storable: instanciarlo con vault=... ya lo mete
        # en la sesión por cascada, y el teardown de la petición lo commitearía
        # aunque después lanzáramos el 409.
        self._require_revision(vault, expected_revision)

        spec = STORABLE_SPECS.get(kind)
        if spec is None:
            raise ValueError(f"Tipo de storable no soportado: {kind}")

        created_at = created_at or utcnow_naive()
        updated_at = updated_at or created_at

        storable = spec.model(
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
                repo.save(storable)
                self._bump_revision(vault)
            logger.info(f"Storable {storable.id} creado en vault {vault_id}")
            return storable
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
            storable = repo.get_by_id(storable_id)
            if storable is None:
                raise ValueError(f"Storable {storable_id} no encontrado")

            try:
                changed = False
                if title is not None:
                    storable.title = title
                    changed = True
                if internal_id is not None:
                    storable.internal_id = internal_id
                    changed = True

                spec = SPEC_BY_MODEL.get(type(storable))
                if spec is not None:
                    for attr, _ in spec.fields:
                        value = fields.get(attr)
                        if value is not None:
                            setattr(storable, attr, value)
                            changed = True

                if changed:
                    storable.updated_at = utcnow_naive()
                    self._bump_revision(storable.vault)
                    repo.update(storable)
                    logger.info(f"Storable {storable.id} actualizado correctamente")
                else:
                    logger.info(f"Storable {storable.id}: sin cambios")

                return storable

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
        expected_revision: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        vault_cache: Dict[bool, Optional[Vault]] = {}
        field_map = JSON_TO_ATTR

        # La revisión se valida una sola vez y fuera del bucle: dentro, el
        # try/except por operación convertiría el 409 en un resultado de error
        # con HTTP 200 y el lote se aplicaría igualmente.
        if expected_revision is not None:
            current_vault = self.get_vault_for_user()
            if current_vault is not None:
                self._require_revision(current_vault, expected_revision)

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

                storable = self.get_storable_by(
                    vault_id=vault.id,
                    internal_id=internal_id,
                )
                if not storable:
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

                self.update_storable(storable.id, **update_kwargs)
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

    def delete_storable(
        self,
        storable_id: int,
        expected_revision: Optional[int] = None,
    ) -> bool:
        storable = self.get_storable(storable_id)
        if storable is None:
            return False

        vault = storable.vault
        self._require_revision(vault, expected_revision)

        try:
            with UnitOfWork() as uow:
                repo = StorableRepository(uow)
                repo.delete(storable)
                self._bump_revision(vault)
            logger.info(f"Storable {storable_id} eliminado")
            return True
        except Exception as e:
            logger.error(f"Error eliminando storable {storable_id}: {e}", exc_info=True)
            raise
