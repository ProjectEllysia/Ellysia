"""
Plantillas de correo de herald.

Lo que aquí se protege es el motivo por el que existe la capa: que el HTML
salga con la envoltura de marca y que los datos que vienen de la BD (nombres
de destinatario, títulos, hostnames) se escapen — antes se interpolaban con
f-strings y un nombre con etiquetas se colaba tal cual en el correo.
"""

import pytest

from src.modules.tools.herald import render_email

pytestmark = pytest.mark.unit

#: Marca del producto tal y como la deja una instancia configurada.
_BASE_BRAND = {
    "productName": "Ellysia",
    "accentColor": "#d4a04a",
    "logoUrl": "",
    "supportEmail": "soporte@ellysia.test",
    "footerNote": "Ellysia S.L.",
    "customerLogoUrl": "",
    "whiteLabelLevel": "none",
}


class TestCampaignTemplate:
    def test_renders_shell_and_link(self):
        html, text = render_email(
            "campaign",
            pill_title="Phishing por SMS",
            link="https://ellysia.es/quiz?t=abc123",
            recipient_name="Ana",
        )

        assert html.startswith("<!DOCTYPE html>")
        assert "https://ellysia.es/quiz?t=abc123" in html
        assert "Phishing por SMS" in html
        assert "Hola, Ana:" in html
        # La envoltura: tablas y estilos inline, no clases ni hojas externas.
        assert "<table" in html
        assert "<link" not in html

        assert text is not None
        assert "https://ellysia.es/quiz?t=abc123" in text
        assert "Phishing por SMS" in text
        # El texto plano no debe llevar entidades HTML ni etiquetas.
        assert "<" not in text
        assert "&amp;" not in text

    def test_greeting_without_name(self):
        html, text = render_email(
            "campaign", pill_title="X", link="https://e.es/quiz?t=1", recipient_name=None
        )
        assert "Hola:" in html
        assert "Hola:" in text

    def test_escapes_untrusted_values(self):
        html, _ = render_email(
            "campaign",
            pill_title='Título "raro" & <b>negrita</b>',
            link="https://ellysia.es/quiz?t=abc",
            recipient_name='<script>alert(1)</script>',
        )

        assert "<script>" not in html
        assert "&lt;script&gt;" in html
        assert "<b>negrita</b>" not in html
        assert "&amp;" in html

    def test_includes_the_pill_content_not_just_the_link(self):
        """El correo entrega la píldora entera, no solo el enlace al test —
        antes se pedía responder un test sobre un contenido nunca enviado."""
        html, text = render_email(
            "campaign",
            pill_title="Phishing por SMS",
            link="https://ellysia.es/quiz?t=abc123",
            recipient_name="Ana",
            company="ACME",
            intro="Primer párrafo.\n\nSegundo párrafo.",
            tips=[
                {
                    "headline": "Verifica el remitente",
                    "body": "No pulses enlaces de números desconocidos.",
                    "links": [{"text": "Guía de phishing", "url": "https://ejemplo.es/guia"}],
                },
            ],
            closing="Gracias por tu atención.",
            contact_email="seguridad@acme.test",
            contact_is_placeholder=False,
        )

        for fragment in (
            "Primer párrafo.", "Segundo párrafo.",
            "Verifica el remitente", "No pulses enlaces de números desconocidos.",
            "Guía de phishing", "https://ejemplo.es/guia",
            "Gracias por tu atención.", "ACME",
        ):
            assert fragment in html, fragment
            assert fragment in text, fragment

        assert 'mailto:seguridad@acme.test' in html
        assert "seguridad@acme.test" in text

    def test_placeholder_contact_email_is_not_shown_verbatim(self):
        """seguridad@empresa.com es el placeholder por defecto de la IA — no
        se envía como si fuera una dirección real (mismo criterio que
        services/exporters.py)."""
        html, text = render_email(
            "campaign",
            pill_title="X",
            link="https://e.es/quiz?t=1",
            recipient_name=None,
            contact_email="seguridad@empresa.com",
            contact_is_placeholder=True,
        )
        assert "seguridad@empresa.com" not in html
        assert "seguridad@empresa.com" not in text
        assert "responsable de seguridad" in html
        assert "responsable de seguridad" in text

    def test_includes_security_advisories(self):
        """El correo es el único canal que llega al empleado, y hasta ahora
        omitía los avisos por completo."""
        alerts = [{
            "position": 1,
            "title": "CVE-2026-1234 — microsoft windows",
            "description": "CVSS 9.8 (CRÍTICA) · Explotada activamente (CISA KEV)",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
            "severity": "crítica",
            "sourceLabel": "NVD/CVE",
            "published": "2026-07-01",
        }]
        html, text = render_email(
            "campaign", pill_title="X", link="https://e.es/quiz?t=1",
            recipient_name=None, alerts=alerts,
        )

        for fragment in ("CVE-2026-1234", "Explotada activamente", "NVD/CVE", "2026-07-01"):
            assert fragment in html, fragment
            assert fragment in text, fragment
        assert "https://nvd.nist.gov/vuln/detail/CVE-2026-1234" in html
        assert "Avisos recientes" in html

    def test_advisory_section_absent_without_alerts(self):
        html, text = render_email(
            "campaign", pill_title="X", link="https://e.es/quiz?t=1", recipient_name=None,
        )
        assert "Avisos recientes" not in html
        assert "AVISOS RECIENTES" not in text

    def test_omits_sections_with_no_content(self):
        """Sin intro/tips/closing/contacto, la plantilla no debe reventar ni
        dejar huecos en blanco con títulos vacíos."""
        html, _ = render_email(
            "campaign", pill_title="X", link="https://e.es/quiz?t=1", recipient_name=None,
        )
        assert "Recomendaciones" not in html
        assert "Para terminar" not in html


class TestAnomalyTemplate:
    def test_renders_with_metric(self):
        html, text = render_email(
            "anomaly",
            hostname="srv-01.local",
            kind="cpu_spike",
            metric="cpu",
            value=97,
            threshold=90,
            recipient_name="Ana",
        )
        assert "srv-01.local" in html
        assert "cpu_spike" in html
        assert "97" in html and "90" in html
        assert "srv-01.local" in text

    def test_metric_block_omitted_when_absent(self):
        html, _ = render_email(
            "anomaly", hostname="srv-01", kind="offline", metric=None,
            value=None, threshold=None, recipient_name=None,
        )
        assert "Umbral" not in html
        assert "None" not in html


class TestIrisPhishingTemplate:
    def test_renders_subject_analysis_id_and_score(self):
        html, text = render_email(
            "iris_phishing",
            subject="Tu factura caduca hoy",
            analysis_id=42,
            score=12.0,
            recipient_name="Ana",
        )
        assert "Ten cuidado con el correo" in html
        assert "Tu factura caduca hoy" in html
        assert "#42" in html
        assert "12.0" in html
        assert "TEN CUIDADO CON EL CORREO" in text
        assert "Tu factura caduca hoy" in text
        assert "#42" in text

    def test_score_row_omitted_when_absent(self):
        html, text = render_email(
            "iris_phishing", subject="X", analysis_id=1, recipient_name=None,
        )
        assert "Puntuación" not in html
        assert "Puntuación" not in text
        assert "None" not in html

    def test_escapes_untrusted_subject(self):
        html, _ = render_email(
            "iris_phishing", subject='<script>alert(1)</script>', analysis_id=1, recipient_name=None,
        )
        assert "<script>" not in html
        assert "&lt;script&gt;" in html


class TestMfaReminderTemplate:
    def test_renders_profile_link_in_html_and_text(self):
        html, text = render_email(
            "mfa_reminder",
            recipient_name="Ana",
            profile_url="https://ellysia.es/profile",
        )

        assert "Activa la autenticación multifactor" in html
        assert "https://ellysia.es/profile" in html
        assert "https://ellysia.es/profile" in text
        assert "Hola Ana" in html
        assert "Hola Ana" in text

    def test_escapes_recipient_and_profile_url(self):
        html, text = render_email(
            "mfa_reminder",
            recipient_name='<script>alert(1)</script>',
            profile_url="https://ellysia.es/profile?a=1&amp;b=2",
        )

        assert "<script>" not in html
        assert "&lt;script&gt;" in html
        assert "&amp;amp;" in html


class TestPasswordResetTemplate:
    def test_renders_the_reset_link_and_ttl(self):
        html, text = render_email(
            "password_reset",
            recipient_name="Ana",
            reset_url="https://ellysia.es/recuperar?token=abc123",
            ttl_minutes=30,
        )

        assert "https://ellysia.es/recuperar?token=abc123" in html
        assert "https://ellysia.es/recuperar?token=abc123" in text
        assert "30 minutos" in html
        assert "30 minutos" in text
        assert "Hola Ana," in html
        assert "<table" in html
        assert "<link" not in html
        assert "<" not in text

    def test_escapes_the_reset_url(self):
        html, _ = render_email(
            "password_reset",
            recipient_name=None,
            reset_url="https://ellysia.es/recuperar?token=<script>",
            ttl_minutes=30,
        )
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_warns_when_not_requested(self):
        html, text = render_email(
            "password_reset",
            recipient_name=None,
            reset_url="https://ellysia.es/recuperar?token=abc123",
            ttl_minutes=30,
        )
        assert "ignora este mensaje" in html
        assert "ignora este mensaje" in text


def test_brand_defaults_are_injected():
    """Sin ``brand`` explícita, render_email la saca de la config + defaults."""
    html, _ = render_email("campaign", pill_title="X", link="https://e.es/q", recipient_name=None)
    assert "Ellysia" in html


class TestWhiteLabel:
    """Los tres niveles, vistos desde el correo ya renderizado.

    Las plantillas no ramifican por nivel: leen las claves de ``brand`` que
    ``apply_white_label`` deja puestas. Por eso el nivel FULL lo hereda
    cualquier plantilla que use la envoltura, no solo la de campaña.
    """

    _LOGO_URI = (
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAA"
        "CklEQVR4nGNgAAAAAgABf6ZX1AAAAABJRU5ErkJggg=="
    )

    def _render(self, level, brand_name="ACME S.L.", logo=_LOGO_URI):
        from src.modules.shared import WhiteLabel, WhiteLabelLevel
        from src.modules.tools.herald.branding import apply_white_label

        brand, images = apply_white_label(
            {**_BASE_BRAND},
            WhiteLabel(level=WhiteLabelLevel(level), logo=logo, brand_name=brand_name),
        )
        html, text = render_email(
            "campaign",
            brand=brand,
            pill_title="Phishing por SMS",
            link="https://ellysia.es/quiz?t=abc",
            company="ACME S.L.",
        )
        return html, text, images

    def test_none_keeps_the_product_brand_and_adds_no_image(self):
        html, text, images = self._render("none")

        assert "ELLYSIA" in html.upper()
        assert "cid:" not in html
        assert images == ()
        assert "Ellysia" in text

    def test_logo_level_shows_the_customer_logo_above_the_intro(self):
        html, _, images = self._render("logo")

        assert 'src="cid:brand-logo"' in html
        assert 'alt="ACME S.L."' in html
        # El logo va antes del saludo, no al final del cuerpo.
        assert html.index("cid:brand-logo") < html.index("Hola:")
        # La marca del producto sigue en su sitio: este nivel solo añade.
        assert "Ellysia" in html
        assert len(images) == 1

    def test_full_level_removes_every_trace_of_the_product_brand(self):
        html, text, images = self._render("full")

        assert "Ellysia" not in html
        assert "Ellysia" not in text
        assert "ACME S.L." in text
        # El logo ocupa la cabecera y no se repite sobre el cuerpo.
        assert html.count("cid:brand-logo") == 1
        assert len(images) == 1

    def test_full_level_without_logo_falls_back_to_the_customer_name(self):
        html, text, images = self._render("full", logo="")

        assert "Ellysia" not in html
        assert "Ellysia" not in text
        assert "ACME S.L." in html
        assert images == ()

    def test_level_degrades_instead_of_rendering_half_a_brand(self):
        """FULL sin nombre no puede retirar la marca: se queda en el logo."""
        html, _, images = self._render("full", brand_name="")

        assert "Ellysia" in html
        assert 'src="cid:brand-logo"' in html
        assert len(images) == 1
