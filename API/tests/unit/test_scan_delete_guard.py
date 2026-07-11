"""Regression test: a scan whose cancellation fails must not be deleted.

Cancellation is cooperative (ScanManager.cancel_scan / TaskQueue.cancel only
signal the worker, they never kill the OS-level subprocess directly). If a
delete path ignores that signal's success/failure and deletes the scan row
regardless, a still-running nmap/nikto/openvas process is orphaned: invisible
to the app forever, since its Scan row and TaskQueue mapping are gone. See
endpoints.delete_scan and ScanManager.bulk_delete_scans for the guard.
"""

from unittest.mock import MagicMock, patch

import pytest

from src.modules.themis.managers.scan import ScanManager

pytestmark = pytest.mark.unit


def _mock_manager(scan_status: str, cancel_result: bool):
    mgr = MagicMock()
    mgr.get_scan_by_id.return_value = MagicMock(status=scan_status)
    mgr.cancel_scan.return_value = cancel_result
    return mgr


def test_bulk_delete_skips_deletion_when_cancel_fails():
    mgr = _mock_manager(scan_status="running", cancel_result=False)
    with patch.object(ScanManager, "resolve_manager", return_value=mgr), \
         patch.object(ScanManager, "assert_scan_ownership"):
        result = ScanManager.bulk_delete_scans([1], user_id=1)

    assert result["deletedCount"] == 0
    assert result["failedCount"] == 1
    assert result["results"][0]["status"] == "error"
    mgr.cancel_scan.assert_called_once_with(1, 1)
    mgr.delete_scan.assert_not_called()


def test_bulk_delete_proceeds_when_cancel_succeeds():
    mgr = _mock_manager(scan_status="running", cancel_result=True)
    with patch.object(ScanManager, "resolve_manager", return_value=mgr), \
         patch.object(ScanManager, "assert_scan_ownership"):
        result = ScanManager.bulk_delete_scans([1], user_id=1)

    assert result["deletedCount"] == 1
    assert result["failedCount"] == 0
    mgr.delete_scan.assert_called_once_with(1)


def test_bulk_delete_skips_cancel_for_already_finished_scan():
    mgr = _mock_manager(scan_status="finished", cancel_result=False)
    with patch.object(ScanManager, "resolve_manager", return_value=mgr), \
         patch.object(ScanManager, "assert_scan_ownership"):
        result = ScanManager.bulk_delete_scans([1], user_id=1)

    assert result["deletedCount"] == 1
    mgr.cancel_scan.assert_not_called()
    mgr.delete_scan.assert_called_once_with(1)
