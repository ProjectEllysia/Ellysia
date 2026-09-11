"""Taxonomía estable de los hallazgos de Iris: rule_id, severidad y MITRE ATT&CK.

Cubre el criterio de cierre: un hallazgo se identifica por un id estable que
no depende del nombre visible (que se puede traducir o corregir), lleva una
severidad separada del score y, cuando encaja, sus técnicas ATT&CK; y el PDF lo
enseña.

``EXPECTED_RULE_IDS`` congela los ids a propósito: son un contrato con quien
exporte o agrupe hallazgos, así que cambiar uno tiene que ser una decisión
explícita, no un efecto secundario de renombrar una regla.
"""

from __future__ import annotations

import re

import pytest
from reportlab.lib.styles import getSampleStyleSheet

from src.modules.features.iris.managers.analysis import _rule_to_dict
from src.modules.features.iris.model import IrisRuleResult
from src.modules.features.iris.services.quality import assess_quality
from src.modules.features.iris.services.registry import RuleRegistry, RuleResult, RuleSeverity
from src.modules.features.iris.services.reports import IrisPDFCreator, IrisReportTheme, PALETTE
from src.modules.features.iris.services.rules import iris_rules

pytestmark = pytest.mark.unit

EXPECTED_RULE_IDS = frozenset({
    "iris.attachment.external_image_tracking", "iris.attachment.image_only_email",
    "iris.attachment.suspicious_attachments",
    "iris.auth.spf", "iris.auth.dkim", "iris.auth.dmarc", "iris.auth.domain_alignment",
    "iris.auth.arc_chain", "iris.auth.auth_results_provenance",
    "iris.content.alarming_keywords", "iris.content.body_content", "iris.content.bec_wire_transfer",
    "iris.content.generic_greeting", "iris.content.url_in_subject", "iris.content.unicode_evasion",
    "iris.content.encoded_word_abuse", "iris.content.toad_callback", "iris.content.list_unsubscribe",
    "iris.content.image_text_phishing",
    "iris.links.body_links", "iris.links.qr_code_links", "iris.links.compromised_legitimate_domain",
    "iris.links.external_login_link",
    "iris.received.date_header_anomaly", "iris.received.received_chain",
    "iris.received.temporal_inconsistency", "iris.received.path_anomaly",
    "iris.received.origin_helo_coherence",
    "iris.recipient.undisclosed_recipients",
    "iris.reply_path.reply_to_mismatch", "iris.reply_path.reply_to_free_provider",
    "iris.reply_path.return_path_mismatch", "iris.reply_path.triangulation",
    "iris.identity.from_header", "iris.identity.display_name_spoofing",
    "iris.identity.display_name_email_mismatch", "iris.identity.lookalike_sender_domain",
    "iris.identity.subdomain_impersonation", "iris.identity.misspelled_brand_names",
    "iris.identity.suspicious_tld", "iris.identity.recipient_domain_lookalike",
    "iris.identity.display_name_foreign_address",
    "iris.thread.fake_reply_chain", "iris.thread.self_referencing_in_reply_to",
    "iris.thread.message_id", "iris.thread.message_id_domain",
    "iris.thread.message_id_received_correlation",
})


# ------------------------------------------------------------------ catálogo

def test_every_rule_has_a_frozen_stable_id():
    ids = [rule_def["rule_id"] for rule_def in iris_rules.get_rules()]

    assert len(ids) == len(set(ids)), "hay rule_id repetidos"
    assert set(ids) == EXPECTED_RULE_IDS


def test_every_rule_has_a_severity_and_well_formed_techniques():
    severities = {member.value for member in RuleSeverity}
    for rule_def in iris_rules.get_rules():
        assert rule_def["severity"] in severities, rule_def["name"]
        for technique in rule_def["mitre_techniques"]:
            assert re.match(r"^T\d{4}(\.\d{3})?$", technique), (rule_def["name"], technique)


def test_attack_techniques_are_only_declared_where_they_fit():
    """Adjunto -> T1566.001, enlace -> T1566.002, y la mayoría sin técnica:
    una heurística de cabeceras no es una técnica de ATT&CK."""
    by_id = {rule_def["rule_id"]: rule_def for rule_def in iris_rules.get_rules()}

    assert by_id["iris.attachment.suspicious_attachments"]["mitre_techniques"] == ("T1566.001",)
    assert by_id["iris.links.body_links"]["mitre_techniques"] == ("T1566.002",)
    assert by_id["iris.auth.spf"]["mitre_techniques"] == ()
    without = sum(1 for rule_def in by_id.values() if not rule_def["mitre_techniques"])
    assert without > len(by_id) / 2


# ---------------------------------------------------------------- registro

def _register(**overrides):
    fields = dict(name="Prueba", evidence_headers=("from",), rule_id="iris.test.prueba", severity="low")
    fields.update(overrides)
    registry = RuleRegistry()
    registry.register(**fields)(lambda headers: RuleResult(score=0, verdict="pass"))
    return registry


@pytest.mark.parametrize("overrides", [
    {"rule_id": ""},
    {"rule_id": "Prueba"},
    {"rule_id": "iris.Test.prueba"},
    {"severity": ""},
    {"severity": "extreme"},
    {"mitre_techniques": ("phishing",)},
    {"mitre_techniques": ("T1566.2",)},
])
def test_the_registry_rejects_an_incomplete_or_malformed_taxonomy(overrides):
    with pytest.raises(ValueError):
        _register(**overrides)


def test_the_registry_rejects_a_duplicate_id():
    registry = _register()

    with pytest.raises(ValueError):
        registry.register(name="Otra", evidence_headers=("from",), rule_id="iris.test.prueba", severity="low")


def test_the_registry_keeps_the_taxonomy_with_the_rule():
    rule_def = _register(mitre_techniques=["T1566.002"]).get_rules()[0]

    assert (rule_def["rule_id"], rule_def["severity"], rule_def["mitre_techniques"]) == (
        "iris.test.prueba", "low", ("T1566.002",))


# ------------------------------------------------------------ serialización

def test_a_finding_is_serialized_with_its_stable_reference():
    row = IrisRuleResult(rule_name="Enlaces del cuerpo", rule_id="iris.links.body_links", severity="high",
                         mitre_techniques=["T1566.002"], category="content_analysis", score=-20.0,
                         verdict="fail")

    serialized = _rule_to_dict(row)

    assert serialized["ruleId"] == "iris.links.body_links"
    assert serialized["ruleName"] == "Enlaces del cuerpo"
    assert serialized["severity"] == "high"
    assert serialized["mitreTechniques"] == ["T1566.002"]


def test_a_finding_from_before_the_taxonomy_still_serializes():
    row = IrisRuleResult(rule_name="SPF", category="authentication", score=0.0, verdict="pass")

    serialized = _rule_to_dict(row)

    assert serialized["ruleId"] is None
    assert serialized["mitreTechniques"] == []


def test_a_rule_that_could_not_run_is_reported_with_its_id():
    rules_defs = [rule_def for rule_def in iris_rules.get_rules() if rule_def["rule_id"] == "iris.auth.dmarc"]

    quality = assess_quality(rules_defs, [RuleResult(score=0, verdict="error")])

    assert quality.failed_rules[0]["ruleId"] == "iris.auth.dmarc"


# ------------------------------------------------------------------- PDF

def test_the_pdf_shows_the_stable_id_and_the_attack_technique(tmp_path, monkeypatch):
    import src.modules.features.iris.services.reports as reports_mod
    monkeypatch.setattr(reports_mod.CR, "get_directory_of", lambda *_args, **_kwargs: str(tmp_path))
    report = {
        "analysisId": 1, "status": "finished", "verdict": "Phishing", "totalScore": 20,
        "rules": [{
            "ruleId": "iris.links.body_links", "ruleName": "Body Links", "category": "content_analysis",
            "score": -20, "verdict": "fail", "details": {}, "mitreTechniques": ["T1566.002"],
            "recommendation": "No hagas clic.", "evidence": [],
        }],
    }
    elements: list = []

    IrisPDFCreator(report=report).append_rules(elements, IrisReportTheme(getSampleStyleSheet(), PALETTE))

    texts = " ".join(getattr(element, "text", "") for element in elements)
    table_cells = " ".join(
        cell.text for element in elements if hasattr(element, "_cellvalues")
        for row in element._cellvalues for cell in row if hasattr(cell, "text")
    )
    assert "iris.links.body_links" in table_cells
    assert "iris.links.body_links" in texts and "T1566.002" in texts
