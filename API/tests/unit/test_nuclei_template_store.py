"""Unit tests for the single Nuclei template store (roadmap Fases U4/R).

Pure: every test builds a fake template tree under ``tmp_path``, so nothing
here needs a real ``nuclei`` install or its multi-thousand-file feed. What is
being verified is the *mechanics* — path resolution order, which files count as
templates, and tolerance to a malformed one — not the content of any real
template, which can only be checked on a machine that has the feed installed.
"""

import pytest

from src.modules.features.themis.services.nuclei_templates import (
    NucleiTemplateStore,
    resolve_templates_dir,
)

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


# ------------------------------------------------------------- path resolution

def test_configured_directory_wins(tmp_path, monkeypatch):
    configured = tmp_path / "configured"
    configured.mkdir()
    monkeypatch.setattr(
        "src.modules.features.themis.services.nuclei_templates.CR.get_nuclei_templates_dir",
        lambda: str(configured),
    )
    assert resolve_templates_dir() == configured


def test_environment_variable_used_when_config_is_empty(tmp_path, monkeypatch):
    from_env = tmp_path / "from-env"
    from_env.mkdir()
    monkeypatch.setattr(
        "src.modules.features.themis.services.nuclei_templates.CR.get_nuclei_templates_dir",
        lambda: "",
    )
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(from_env))
    assert resolve_templates_dir() == from_env


def test_falls_back_to_nuclei_default_location(tmp_path, monkeypatch):
    """The Docker image's real case: nothing configured, templates under $HOME."""
    default_location = tmp_path / ".local" / "nuclei-templates"
    default_location.mkdir(parents=True)
    monkeypatch.setattr(
        "src.modules.features.themis.services.nuclei_templates.CR.get_nuclei_templates_dir",
        lambda: "",
    )
    monkeypatch.delenv("NUCLEI_TEMPLATES_DIR", raising=False)
    monkeypatch.setattr("pathlib.Path.home", classmethod(lambda cls: tmp_path))

    assert resolve_templates_dir() == default_location


def test_returns_none_when_nothing_resolves(tmp_path, monkeypatch):
    """A missing tree is reported as such, never as an invented path."""
    monkeypatch.setattr(
        "src.modules.features.themis.services.nuclei_templates.CR.get_nuclei_templates_dir",
        lambda: "",
    )
    monkeypatch.delenv("NUCLEI_TEMPLATES_DIR", raising=False)
    monkeypatch.setattr("pathlib.Path.home", classmethod(lambda cls: tmp_path / "empty"))

    assert resolve_templates_dir() is None


def test_configured_but_missing_directory_falls_through(tmp_path, monkeypatch):
    """A deployment typo must not silently yield a working-looking store."""
    monkeypatch.setattr(
        "src.modules.features.themis.services.nuclei_templates.CR.get_nuclei_templates_dir",
        lambda: str(tmp_path / "does-not-exist"),
    )
    monkeypatch.delenv("NUCLEI_TEMPLATES_DIR", raising=False)
    monkeypatch.setattr("pathlib.Path.home", classmethod(lambda cls: tmp_path / "empty"))

    assert resolve_templates_dir() is None


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
