"""Unit tests for NucleiResultProcessor (JSONL parsing, roadmap Fase U1)."""

import json

import pytest

from src.modules.features.themis.services.processors import NucleiResultProcessor

pytestmark = pytest.mark.unit


def _write_jsonl(tmp_path, lines):
    path = tmp_path / "nuclei_scan.jsonl"
    path.write_text("\n".join(lines), encoding="utf-8")
    return str(path)


def test_parses_one_result_per_line(tmp_path):
    lines = [
        json.dumps({"template-id": "a", "info": {"name": "A"}}),
        json.dumps({"template-id": "b", "info": {"name": "B"}}),
    ]
    path = _write_jsonl(tmp_path, lines)

    results = NucleiResultProcessor().process(path)

    assert len(results) == 2
    assert results[0]["template-id"] == "a"
    assert results[1]["template-id"] == "b"


def test_corrupt_line_is_skipped_not_fatal(tmp_path):
    lines = [
        json.dumps({"template-id": "a", "info": {"name": "A"}}),
        "{not valid json",
        json.dumps({"template-id": "c", "info": {"name": "C"}}),
    ]
    path = _write_jsonl(tmp_path, lines)

    results = NucleiResultProcessor().process(path)

    assert len(results) == 2
    assert [r["template-id"] for r in results] == ["a", "c"]


def test_blank_lines_ignored(tmp_path):
    lines = [
        json.dumps({"template-id": "a"}),
        "",
        "   ",
        json.dumps({"template-id": "b"}),
    ]
    path = _write_jsonl(tmp_path, lines)

    results = NucleiResultProcessor().process(path)

    assert len(results) == 2


def test_missing_file_returns_empty_list(tmp_path):
    missing = str(tmp_path / "does_not_exist.jsonl")
    assert NucleiResultProcessor().process(missing) == []


def test_empty_list_input_passes_through_unchanged():
    """NucleiScanTask._process_results returns [] directly (no file at all)
    when the scan found nothing — the processor must accept that as-is."""
    assert NucleiResultProcessor().process([]) == []


def test_list_input_returned_as_list_copy():
    raw = [{"template-id": "a"}]
    result = NucleiResultProcessor().process(raw)
    assert result == raw
    assert result is not raw
