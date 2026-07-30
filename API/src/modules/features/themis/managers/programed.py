"""ProgramedScanManager — extraido de themis/managers.py (Fase 3 del refactor de estructura)."""

import logging
from datetime import datetime
from typing import List
from src.modules.infrastructure import UnitOfWork
from src.modules.shared import assert_owned
from ..repositories import ProgramedScanRepository
from ..model import (
    ProgramedScan,
    ScanType,
)
from ..services import ThemisScheduler
from ..exceptions import (
    InvalidProgramedTaskArgumentError,
    ProgramedScanNotFoundError,
)


logger = logging.getLogger(__name__)


class ProgramedScanManager():

    _REQUIRED_ARGS: dict[ScanType, List[str]] = {
        ScanType.NMAP:      ["target_host", "target_ports"],
        ScanType.NIKTO:     ["target_domain"],
        ScanType.OPENVAS:   ["target"],
        ScanType.LYBRA:     ["target"],
        ScanType.NUCLEI:    ["target"],
    }

    @classmethod
    def register(
        cls,
        user_id: int,
        scan_type: ScanType,
        arguments: dict[str, str],
        schedule_type: str,
        schedule_config: dict
    ):
        cls._assert_valid_arguments(
            scan_type=scan_type,
            arguments=arguments
        )
        cls._assert_valid_scheduling_config(
            schedule_type=schedule_type,
            schedule_config=schedule_config
        )
        next_run = ThemisScheduler.calculate_next_run(
            schedule_type=schedule_type,
            schedule_config=schedule_config,
        )
        with UnitOfWork() as uow:
            repo = ProgramedScanRepository(uow)
            ps = repo.create(
                user_id=user_id,
                scan_type=scan_type,
                arguments=arguments,
                schedule_type=schedule_type,
                schedule_config=schedule_config,
                next_run_at=next_run,
            )

        ThemisScheduler.schedule(
            ps_id=ps.id,
            scan_type=ps.scan_type,
            user_id=ps.user_id,
            schedule_type=schedule_type,
            schedule_config=schedule_config,
        )
        return ps

    @classmethod
    def _assert_valid_arguments(cls, scan_type: ScanType, arguments: dict[str, str]):
        # .get(), not [] — a ScanType the endpoint's own enum-wide validation
        # accepts but that has no entry here (e.g. a new tool not yet wired
        # into scheduling) must fail as a clean 400, not an uncaught KeyError.
        required_list = cls._REQUIRED_ARGS.get(scan_type)
        if required_list is None:
            raise InvalidProgramedTaskArgumentError(
                scan_type, f"escaneos programados no soportan el tipo '{scan_type}'"
            )

        for field in required_list:
            if arguments.get(field) is None:
                raise InvalidProgramedTaskArgumentError(scan_type, field)

    @classmethod
    def _assert_valid_scheduling_config(
        cls,
        schedule_type: str,
        schedule_config: dict
    ):
        if schedule_type == "interval":
            every = schedule_config.get("every")
            if not isinstance(every, (int, float)) or every <= 0:
                raise InvalidProgramedTaskArgumentError(
                    schedule_type, f"interval every must be > 0, got: {every}"
                )
            unit = schedule_config.get("unit")
            if unit not in ("minutes", "hours", "days"):
                raise InvalidProgramedTaskArgumentError(
                    schedule_type, f"invalid interval unit: {unit}"
                )

        elif schedule_type == "cron":
            cron_expr = schedule_config.get("cron")
            if not cron_expr:
                raise InvalidProgramedTaskArgumentError(
                    schedule_type, "missing cron expression"
                )
            try:
                from croniter import croniter as _ci
                _ci(cron_expr, datetime.now())
            except Exception:
                raise InvalidProgramedTaskArgumentError(
                    schedule_type, f"invalid cron expression: {cron_expr}"
                )

        else:
            raise InvalidProgramedTaskArgumentError(
                schedule_type, f"unknown schedule_type: {schedule_type}"
            )

    @classmethod
    def assert_ownership(cls, ps_id: int, user_id: int) -> ProgramedScan:
        return assert_owned(ProgramedScanRepository, ps_id, user_id, ProgramedScanNotFoundError)

    @classmethod
    def get_scans_for_user(cls, user_id: int) -> List[ProgramedScan]:
        with UnitOfWork() as uow:
            repo = ProgramedScanRepository(uow)
            programed_scans = repo.get_by_user(user_id)

        return programed_scans

    @classmethod
    def revoke(cls, ps_id: int, user_id: int) -> None:
        ThemisScheduler.unschedule(ps_id)
        with UnitOfWork() as uow:
            repo = ProgramedScanRepository(uow)
            ps = repo.get_by_id(ps_id)
            if ps is None:
                raise ProgramedScanNotFoundError(ps_id)
            if ps.user_id != user_id: # type: ignore
                raise ProgramedScanNotFoundError(ps_id)
            ps.is_active = False # type: ignore
            repo.update(ps)

    @classmethod
    def delete(cls, ps_id: int, user_id: int) -> None:
        ThemisScheduler.unschedule(ps_id)
        with UnitOfWork() as uow:
            repo = ProgramedScanRepository(uow)
            ps = repo.get_by_id(ps_id)
            if ps is None:
                raise ProgramedScanNotFoundError(ps_id)
            if ps.user_id != user_id: # type: ignore
                raise ProgramedScanNotFoundError(ps_id)
            repo.delete(ps)

