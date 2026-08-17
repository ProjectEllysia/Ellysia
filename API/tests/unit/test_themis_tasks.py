import subprocess
from unittest.mock import patch

import pytest

from src.modules.features.themis.services.tasks import _Task
from src.modules.system.taskqueue import TaskStatus


class _FailingTask(_Task):
    def _build_command(self):
        return ["nikto"]


class _FailedProcess:
    returncode = 1

    def poll(self):
        return self.returncode

    def communicate(self, timeout=None):
        return "Can't locate Net/SSLeay.pm in @INC", None


def test_scan_logs_output_when_process_fails_immediately(caplog):
    task = _FailingTask("example.com")

    with patch.object(subprocess, "Popen", return_value=_FailedProcess()):
        with pytest.raises(RuntimeError, match="código 1"):
            task.scan()

    assert task.status == TaskStatus.FAILED
    assert "Net/SSLeay.pm" in caplog.text
