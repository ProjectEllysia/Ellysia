"""Public Suffix List y confusables IDN: menos falsos positivos, los mismos homógrafos.

Cubre el criterio de cierre: ``co.uk``, TLDs nuevos, punycode, cirílico y
dominios multilingües no producen regresiones en remitentes legítimos, y los
homógrafos de marca y la mezcla de alfabetos se siguen detectando.

Los dominios internacionalizados se escriben en Unicode y se convierten con
el codec ``idna`` de la biblioteca estándar, para que el test diga qué
dominio es sin tener que descifrar el punycode a mano.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from email.utils import format_datetime

import pytest

from src.modules.features.iris.managers import IrisManager
from src.modules.features.iris.services.idn import IdnVerdict, assess_domain, skeleton
from src.modules.features.iris.services.parsers import parse_raw_message
from src.modules.features.iris.services.rules import iris_rules
from src.modules.features.iris.services.rules.sender_identity_rules import (
    check_lookalike_domain,
    check_subdomain_impersonation,
)
from src.modules.features.iris.services.text import (
    analyze_url,
    normalize_homoglyphs,
    public_suffix,
    registrable_domain,
    registrable_label,
)
from src.modules.features.iris.services.wordlists import canonical_brands

pytestmark = pytest.mark.unit


def _puny(domain: str) -> str:
    return domain.encode("idna").decode("ascii")


# --------------------------------------------------------- dominio registrable

@pytest.mark.parametrize("host, expected", [
    ("a.b.example.co.uk", "example.co.uk"),
    ("mail.paypal.com", "paypal.com"),
    ("shop.example.com.br", "example.com.br"),
    # Antes gob.es no era un sufijo conocido: todo el sector público español
    # contaba como una sola organización, «gob.es».
    ("mail.hacienda.gob.es", "hacienda.gob.es"),
    ("login.example.ac.jp", "example.ac.jp"),
    ("news.example.app", "example.app"),
    ("email.mango", "email.mango"),
    ("Mail.Example.COM.", "example.com"),
    ("localhost", "localhost"),
    ("192.168.1.10", "192.168.1.10"),
])
def test_registrable_domain_follows_the_public_suffix_list(host, expected):
    assert registrable_domain(host) == expected


def test_registrable_label_and_public_suffix():
    assert registrable_label("mail.hacienda.gob.es") == "hacienda"
    assert public_suffix("mail.hacienda.gob.es") == "gob.es"
    assert registrable_domain(_puny("correo.пример.рф")) == _puny("пример.рф")
    assert registrable_domain(None) is None


# --------------------------------------------------------------- IDN y esqueleto

def test_the_visual_skeleton_reads_like_a_human():
    assert skeleton("pаypаl") == "paypal"          # а cirílicas
    assert skeleton("gööglé") == "google"          # tildes latinas
    assert skeleton("ｇｏｏｇｌｅ") == "google"      # anchura completa
    assert skeleton("münchen") == "munchen"
    assert normalize_homoglyphs("PаYPа1") == "paypal"


@pytest.mark.parametrize("domain, verdict", [
    ("example.com", IdnVerdict.ASCII),
    (_puny("münchen.de"), IdnVerdict.VALID_IDN),
    (_puny("пример.рф"), IdnVerdict.VALID_IDN),
    (_puny("日本語.jp"), IdnVerdict.VALID_IDN),
    (_puny("ひらがなカタカナ漢字.jp"), IdnVerdict.VALID_IDN),
    (_puny("ελληνικά.gr"), IdnVerdict.VALID_IDN),
    ("xn--pypal-4ve.com", IdnVerdict.BRAND_HOMOGRAPH),   # pаypal
    (_puny("gооgle.com"), IdnVerdict.BRAND_HOMOGRAPH),   # о cirílicas
    (_puny("gööglé.com"), IdnVerdict.BRAND_HOMOGRAPH),   # latín con tildes
    (_puny("bаnco.com"), IdnVerdict.MIXED_SCRIPT),        # latín + cirílico, sin marca
    (_puny("pаypal.ejemplo.com"), IdnVerdict.BRAND_HOMOGRAPH),
])
def test_an_idn_is_only_suspicious_when_it_imitates_or_mixes(domain, verdict):
    assert assess_domain(domain, canonical_brands()).verdict == verdict


# ------------------------------------------------------------ reglas afectadas

@pytest.mark.parametrize("domain", [
    _puny("münchen.de"), _puny("пример.рф"), _puny("日本語.jp"), _puny("correos-españa.es"),
])
def test_a_legitimate_international_sender_is_not_a_lookalike(domain):
    assert check_lookalike_domain({"from": f"info@{domain}"}).verdict == "pass"
    assert check_subdomain_impersonation({"from": f"info@{domain}"}).verdict != "fail"


def test_a_homograph_of_a_brand_is_still_flagged():
    result = check_lookalike_domain({"from": f"seguridad@{_puny('gооgle.com')}"})

    assert result.verdict == "fail"
    assert result.details["type"] == "idn_homograph"
    assert result.details["brand"] == "google"
    assert result.details["unicode_domain"] == "gооgle.com"


def test_a_mixed_script_sender_is_flagged_even_without_a_brand():
    result = check_lookalike_domain({"from": f"avisos@{_puny('bаnco.com')}"})

    assert result.verdict == "fail"
    assert result.details["type"] == "idn_mixed_script"


def test_a_cousin_domain_written_with_accents_is_still_a_cousin():
    """Un IDN válido sigue el análisis normal sobre su esqueleto:
    «paypal-segurídad» contiene la marca aunque lleve tildes."""
    result = check_lookalike_domain({"from": f"x@{_puny('paypal-segurídad.com')}"})

    assert result.verdict == "fail"
    assert result.details["findings"][0]["type"] == "cousin"


def test_a_brand_in_a_subdomain_of_a_government_suffix_is_detected():
    """Con la lista corta, ``gob.es`` no era un sufijo y la etiqueta
    registrable salía mal; con la PSL, «paypal» queda como subdominio."""
    result = check_subdomain_impersonation({"from": "x@paypal.fraude.gob.es"})

    assert result.verdict == "fail"
    assert result.details["findings"][0]["type"] == "brand_in_subdomain"


def test_body_links_only_flag_suspicious_idn_hosts():
    legit, _ = analyze_url(f"https://{_puny('münchen.de')}/rathaus")
    homograph, score = analyze_url("https://xn--pypal-4ve.com/login")

    assert not any(finding["type"] == "punycode" for finding in legit)
    punycode = [finding for finding in homograph if finding["type"] == "punycode"]
    assert punycode and punycode[0]["imitates"] == "paypal"
    assert score < 0


# ------------------------------------------------ remitente legítimo de principio a fin

def _run_engine(raw: str):
    context = parse_raw_message(raw)
    rules_defs = iris_rules.get_rules()
    results, named_results = [], {}
    for rule_def in rules_defs:
        result = rule_def["func"](context if rule_def.get("needs_context") else context.headers)
        result = replace(result, score=min(0.0, float(result.score)))
        results.append(result)
        named_results[rule_def["name"]] = result
    total_score = IrisManager._aggregate_score(rules_defs, results)
    verdict, gate_reasons = IrisManager._apply_verdict_gates(
        IrisManager()._determine_verdict(total_score), named_results)
    return verdict, total_score, gate_reasons


def test_an_authenticated_newsletter_from_an_idn_domain_is_legitimate():
    domain = _puny("münchen.de")
    date = format_datetime(datetime.now(timezone.utc))
    raw = (
        f"Received: from mail.{domain} (mail.{domain} [203.0.113.5]) by mx.example.com "
        f"with ESMTPS id q1; {date}\r\n"
        f"Authentication-Results: mx.example.com; spf=pass smtp.mailfrom={domain}; "
        f"dkim=pass header.d={domain}; dmarc=pass header.from={domain}\r\n"
        f"From: Stadt München <newsletter@{domain}>\r\n"
        f"Return-Path: <newsletter@{domain}>\r\n"
        "To: vecino@example.com\r\n"
        "Subject: Agenda cultural de septiembre\r\n"
        f"Date: {date}\r\n"
        f"Message-ID: <agenda-09@{domain}>\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n\r\n"
        "Hola, te enviamos la agenda cultural de este mes. Un saludo.\r\n"
    )

    verdict, _, gate_reasons = _run_engine(raw)

    assert verdict == "Legitimate", gate_reasons
