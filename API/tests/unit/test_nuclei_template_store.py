"""Unit tests for the single Nuclei template store.

Pure: every test builds a fake template tree under ``tmp_path``, so nothing
here needs a real ``nuclei`` install or its multi-thousand-file feed. What is
being verified is the *mechanics* — which files count as templates, and
tolerance to a malformed one — not the content of any real template, which can
only be checked on a machine that has the feed installed.

Resolving *where* the tree lives is not this module's job (it belongs to
``config_reading.NucleiConfig.templates_dir``), so those tests live in
``test_config_reading.py``.
"""

import pytest

from src.modules.features.themis.services.nuclei_templates import NucleiTemplateStore

pytestmark = pytest.mark.unit


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


_MINIMAL_TEMPLATE = """
id: git-config
info:
  name: Git config exposure
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
"""


# ------------------------------------------------------------------ iteration

def test_iterates_yaml_templates_only(tmp_path):
    _write(tmp_path / "http" / "git-config.yaml", _MINIMAL_TEMPLATE)
    _write(tmp_path / "network" / "redis.yml", _MINIMAL_TEMPLATE)
    _write(tmp_path / "README.md", "not a template")
    _write(tmp_path / "TEMPLATES-STATS.json", "{}")

    names = [p.name for p in NucleiTemplateStore(tmp_path).iter_template_paths()]

    assert sorted(names) == ["git-config.yaml", "redis.yml"]


def test_skips_metadata_and_workflow_directories(tmp_path):
    _write(tmp_path / "http" / "real.yaml", _MINIMAL_TEMPLATE)
    _write(tmp_path / ".git" / "config.yaml", _MINIMAL_TEMPLATE)
    _write(tmp_path / "workflows" / "wordpress.yaml", _MINIMAL_TEMPLATE)

    names = [p.name for p in NucleiTemplateStore(tmp_path).iter_template_paths()]

    assert names == ["real.yaml"]


def test_iteration_is_stable_across_runs(tmp_path):
    for name in ("c.yaml", "a.yaml", "b.yaml"):
        _write(tmp_path / name, _MINIMAL_TEMPLATE)

    store = NucleiTemplateStore(tmp_path)
    first = [p.name for p in store.iter_template_paths()]
    second = [p.name for p in store.iter_template_paths()]

    assert first == second == ["a.yaml", "b.yaml", "c.yaml"]


def test_unavailable_store_iterates_empty_instead_of_raising(tmp_path):
    store = NucleiTemplateStore(tmp_path / "missing")
    assert store.is_available is False
    assert list(store.iter_template_paths()) == []


# -------------------------------------------------------------------- loading

def test_loads_a_template_into_a_dict(tmp_path):
    path = _write(tmp_path / "git-config.yaml", _MINIMAL_TEMPLATE)
    document = NucleiTemplateStore(tmp_path).load_template(path)

    assert document["id"] == "git-config"
    assert document["info"]["severity"] == "high"


def test_malformed_template_is_skipped_not_raised(tmp_path):
    """The upstream tree has thousands of files and changes daily: one bad
    document must cost itself, never the whole iteration."""
    _write(tmp_path / "good.yaml", _MINIMAL_TEMPLATE)
    _write(tmp_path / "broken.yaml", "id: [unclosed\n  bad: : :")
    _write(tmp_path / "scalar.yaml", "just a string, not a mapping")

    loaded = list(NucleiTemplateStore(tmp_path).iter_templates())

    assert [path.name for path, _doc in loaded] == ["good.yaml"]
