"""Gestión de las carpetas usadas para organizar escaneos."""

import logging
import re
import src.modules.system.config_reading as CR
from src.modules.infrastructure import UnitOfWork
from ..repositories import (
    ScanRepository,
    ScanFolderRepository,
)
from ..model import (
    Scan,
    ScanFolder,
)
from ..exceptions import (
    ScanNotFoundError,
    FolderNotFoundError,
    FolderNameInvalidError,
    ScanAlreadyInFolderError,
)

from .scan import ScanManager


logger = logging.getLogger(__name__)


class ScanFolderManager:
    """
    Manager for scan folder lifecycle.

    Handles creation, renaming, deletion and scan assignment. A scan can belong
    to at most one folder; deleting a folder leaves its scans unassigned.
    """

    _FOLDER_NAME_RE = re.compile(r"^[a-zA-Z0-9\s_-]+$")

    @staticmethod
    def _validate_name(name: str) -> str:
        """Strip and validate a folder name, raising FolderNameInvalidError if invalid."""
        stripped = (name or "").strip()
        if not stripped or not ScanFolderManager._FOLDER_NAME_RE.match(stripped):
            raise FolderNameInvalidError(name)
        return stripped

    @staticmethod
    def _assert_scan_ownership(scan: Scan, user_id: int) -> None:
        """Raise ScanNotFoundError if the scan does not belong to the user."""
        if scan is None or scan.user_id != user_id:
            raise ScanNotFoundError(scan.id if scan else 0)

    @staticmethod
    def _assert_folder_ownership(folder: ScanFolder, user_id: int) -> None:
        """Raise FolderNotFoundError if the folder does not belong to the user."""
        if folder is None or folder.user_id != user_id:
            raise FolderNotFoundError(folder.id if folder else 0)

    def create_folder(self, user_id: int, name: str) -> ScanFolder:
        """Create and persist a new folder for the user."""
        validated_name = self._validate_name(name)
        with UnitOfWork() as uow:
            folder = ScanFolder(user_id=user_id, name=validated_name)
            ScanFolderRepository(uow).save(folder)
        logger.info(f"Carpeta '{validated_name}' creada para usuario {user_id}")
        return folder

    def rename_folder(self, folder_id: int, user_id: int, name: str) -> ScanFolder:
        """Rename an existing folder owned by the user."""
        validated_name = self._validate_name(name)
        with UnitOfWork() as uow:
            repo = ScanFolderRepository(uow)
            folder = repo.get_by_id_and_user(folder_id, user_id)
            self._assert_folder_ownership(folder, user_id)
            folder.name = validated_name  # type: ignore
            repo.update(folder)
        logger.info(f"Carpeta {folder_id} renombrada a '{validated_name}'")
        return folder

    def delete_folder(self, folder_id: int, user_id: int) -> None:
        """Delete a folder and unassign its scans (folder_id -> NULL)."""
        with UnitOfWork() as uow:
            folder_repo = ScanFolderRepository(uow)
            folder = folder_repo.get_by_id_and_user(folder_id, user_id)
            self._assert_folder_ownership(folder, user_id)

            scan_repo = ScanRepository(uow)
            for scan in scan_repo.get_by_folder(folder_id, user_id):
                scan_repo.unset_folder(scan)

            folder_repo.delete(folder)
        logger.info(f"Carpeta {folder_id} eliminada por usuario {user_id}")

    def move_scan_to_folder(self, scan_id: int, folder_id: int, user_id: int) -> Scan:
        """Move a scan into a folder, replacing any previous folder assignment."""
        with UnitOfWork() as uow:
            scan_repo = ScanRepository(uow)
            scan = scan_repo.get_by_id(scan_id)
            self._assert_scan_ownership(scan, user_id)

            folder_repo = ScanFolderRepository(uow)
            folder = folder_repo.get_by_id_and_user(folder_id, user_id)
            self._assert_folder_ownership(folder, user_id)

            if scan.folder_id == folder_id:
                raise ScanAlreadyInFolderError(scan_id, folder_id)

            scan_repo.set_folder(scan, folder)
        logger.info(f"Escaneo {scan_id} movido a carpeta {folder_id}")
        return scan

    def add_scans_to_folder(self, scan_ids: list[int], folder_id: int, user_id: int) -> list[Scan]:
        """Add multiple scans to a folder at once."""
        with UnitOfWork() as uow:
            scan_repo = ScanRepository(uow)
            folder_repo = ScanFolderRepository(uow)

            folder = folder_repo.get_by_id_and_user(folder_id, user_id)
            self._assert_folder_ownership(folder, user_id)

            added = []
            for scan_id in scan_ids:
                scan = scan_repo.get_by_id(scan_id)
                self._assert_scan_ownership(scan, user_id)
                if scan.folder_id == folder_id:
                    continue
                scan_repo.set_folder(scan, folder)
                added.append(scan)

        logger.info(f"{len(added)} escaneos añadidos a carpeta {folder_id}")
        return added

    def remove_scan_from_folder(self, scan_id: int, user_id: int) -> Scan:
        """Remove a scan from its current folder."""
        with UnitOfWork() as uow:
            scan_repo = ScanRepository(uow)
            scan = scan_repo.get_by_id(scan_id)
            self._assert_scan_ownership(scan, user_id)

            if scan.folder_id is None:
                return scan

            scan_repo.unset_folder(scan)
        logger.info(f"Escaneo {scan_id} sacado de su carpeta")
        return scan

    def get_folders_with_scans(self, user_id: int) -> dict:
        """
        Return all user folders with their scans plus an unfoldered group.

        Returns:
            Dict with keys ``folders`` (list) and ``unfoldered`` (dict).
        """
        default_name = CR.themis_folders().default_folder_name

        with UnitOfWork() as uow:
            folder_repo = ScanFolderRepository(uow)
            scan_repo = ScanRepository(uow)

            folders = folder_repo.get_by_user(user_id)
            result_folders = []
            for folder in folders:
                scans = scan_repo.get_by_folder(folder.id, user_id)
                result_folders.append({
                    "id": folder.id,
                    "name": folder.name,
                    "createdAt": folder.created_at,
                    "updatedAt": folder.updated_at,
                    "scanCount": len(scans),
                    "scans": [self._format_scan(scan) for scan in scans],
                })

            unfoldered_scans = scan_repo.get_unfoldered_by_user(user_id)
            unfoldered = {
                "id": None,
                "name": default_name,
                "scanCount": len(unfoldered_scans),
                "scans": [self._format_scan(scan) for scan in unfoldered_scans],
            }

        return {
            "folders": result_folders,
            "unfoldered": unfoldered,
        }

    @staticmethod
    def _format_scan(scan: Scan) -> dict:
        """Format a scan using the appropriate type manager."""
        manager = ScanManager.resolve_manager(scan.id)
        return manager.format_scan(scan.id)

