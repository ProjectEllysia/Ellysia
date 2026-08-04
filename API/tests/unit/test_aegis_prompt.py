"""Tests del prompt de Aegis.

Existen por un modo de fallo silencioso y caro: ``_build_user_prompt`` aplica
sus sustituciones con ``str.replace``, y un ``replace`` de un placeholder que
la plantilla no declara **no falla, no avisa y no deja rastro**. Durante mucho
tiempo ``userTemplate`` consumía 4 de las 16 sustituciones ofrecidas, así que
el modelo nunca vio la empresa, el tono, el idioma, el foco, el número de
consejos pedido, el material de referencia cargado de disco (hasta 150k
caracteres), los recursos verificados en la web ni los avisos de seguridad —
mientras la UI seguía ofreciendo todos esos controles al usuario.

``test_every_replacement_is_consumed`` es la red que impide que vuelva a
pasar. Si alguien añade una clave a ``_build_replacements`` sin declarar su
placeholder en SecOpsConfig.json (o al revés), cae aquí y no en producción.
"""

import re

import pytest

import src.modules.system.config_reading as CR
from src.modules.features.aegis.services.pills import AegisAIWriter

pytestmark = pytest.mark.unit

PLACEHOLDER_RE = re.compile(r"{{(\w+)}}")


def _template() -> str:
    return CR.aegis_config().prompts.get("userTemplate", "")


def _placeholders_in_template() -> set[str]:
    return set(PLACEHOLDER_RE.findall(_template()))


def _replacements(**overrides) -> dict[str, str]:
    """Las sustituciones reales, sin construir un AIGenerator.

    ``_build_replacements`` es estático justamente para esto: instanciar
    ``AegisAIWriter`` llamaría a ``build_generator('aegis')``, que exige
    credenciales de un proveedor de IA que un test unitario no debe necesitar.
    """
    kwargs = {
        "topic":              None,
        "topic_id":           7,
        "reference":          "material interno de referencia",
        "tweaks":             {"company": "ACME", "sector": "banca"},
        "verified_resources": "https://ejemplo.es/guia",
        "advisories":         None,
    }
    kwargs.update(overrides)
    return AegisAIWriter._build_replacements(**kwargs)


class TestPlaceholderContract:
    def test_every_replacement_is_consumed(self):
        """Ninguna sustitución puede quedarse sin su hueco en la plantilla."""
        missing = sorted(set(_replacements()) - _placeholders_in_template())
        assert not missing, (
            "userTemplate de SecOpsConfig.json no declara estos placeholders, "
            f"así que su valor se pierde en silencio: {missing}"
        )

    def test_every_placeholder_has_a_replacement(self):
        """Y ningún hueco de la plantilla puede quedarse sin rellenar: un
        '{{foo}}' huérfano llegaría literal al modelo."""
        orphans = sorted(_placeholders_in_template() - set(_replacements()))
        assert not orphans, (
            f"userTemplate usa placeholders que nadie sustituye: {orphans}"
        )

    def test_rendered_prompt_has_no_leftover_placeholders(self):
        """Comprobación de extremo a extremo sobre la plantilla real."""
        writer = AegisAIWriter.__new__(AegisAIWriter)  # sin __init__: no hace falta el generador
        prompt = writer._build_user_prompt(
            None, 7, "referencia interna", {"company": "ACME"}, "recursos", None,
        )
        assert "{{" not in prompt


class TestPromptContent:
    def test_context_the_model_used_to_never_see_is_present(self):
        """Regresión de los inputs que se descartaban: empresa, tono, idioma,
        foco, nº de consejos y el material de referencia leído de disco."""
        writer = AegisAIWriter.__new__(AegisAIWriter)
        prompt = writer._build_user_prompt(
            None, 7,
            "CONTENIDO-DE-REFERENCIA-INTERNA",
            {
                "company": "ACME Seguros", "sector": "seguros", "tone": "cercano",
                "language": "es", "topicFocus": "phishing por SMS",
                "mentionContact": "seguridad@acme.test",
            },
            "RECURSOS-VERIFICADOS",
            None,
        )
        for fragment in (
            "ACME Seguros", "seguros", "cercano", "ES", "phishing por SMS",
            "seguridad@acme.test", "CONTENIDO-DE-REFERENCIA-INTERNA", "RECURSOS-VERIFICADOS",
        ):
            assert fragment in prompt, fragment

    def test_long_reference_is_truncated(self):
        """El stack de referencias puede traer 150k caracteres (3 ficheros de
        50k) y no puede entrar entero en la ventana del modelo."""
        from src.modules.features.aegis.services.pills import MAX_PROMPT_REFERENCE_CHARS

        rendered = _replacements(reference="x" * 200_000)["reference"]
        assert len(rendered) == MAX_PROMPT_REFERENCE_CHARS


class TestAdvisoryFormatting:
    def test_no_advisories_says_so_instead_of_leaving_a_hole(self):
        assert "No hay avisos" in AegisAIWriter._format_advisories([])
        assert "No hay avisos" in AegisAIWriter._format_advisories(None)

    def test_advisories_render_severity_title_and_summary(self):
        from src.modules.features.aegis.services.pills import AegisAlert, AlertSource

        block = AegisAIWriter._format_advisories([
            AegisAlert(
                title="CVE-2024-1234 — Microsoft Windows",
                description="Remote code execution in the print spooler.",
                url="https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
                source=AlertSource.INCIBE,
                published="2024-03-01",
                severity="crítica",
                brands=["Microsoft"],
            ),
        ])
        assert "CVE-2024-1234" in block
        assert "CRÍTICA" in block
        assert "2024-03-01" in block
        assert "print spooler" in block

    def test_advisory_list_is_capped(self):
        from src.modules.features.aegis.services.pills import (
            AegisAlert, AlertSource, MAX_PROMPT_ADVISORIES,
        )

        many = [
            AegisAlert(
                title=f"CVE-2024-{i:04d}", description="d",
                url=f"https://nvd.nist.gov/vuln/detail/CVE-2024-{i:04d}",
                source=AlertSource.INCIBE, published="2024-01-01",
                severity="alta", brands=[],
            )
            for i in range(MAX_PROMPT_ADVISORIES + 8)
        ]
        block = AegisAIWriter._format_advisories(many)
        entries = [line for line in block.splitlines() if line.startswith("- [")]
        assert len(entries) == MAX_PROMPT_ADVISORIES
