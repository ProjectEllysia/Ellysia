"""Unit tests for Lybra correlation (Fase 5): dedup, merge, lifecycle, scoring.

All pure functions over finding dicts — no DB, no network.
"""

import pytest

from src.modules.features.themis.lybra import (
    classify_exposure,
    compute_dedup_key,
    merge_findings,
    apply_lifecycle,
    score_finding,
)

pytestmark = pytest.mark.unit


# ------------------------------------------------------------------ exposure

@pytest.mark.parametrize("target,expected", [
    ("10.0.0.5", "private"),
    ("192.168.1.1", "private"),
    ("127.0.0.1", "private"),
    ("localhost", "private"),
    ("printer.lan", "private"),
    ("8.8.8.8", "public"),
    ("example.com", "public"),
])
def test_classify_exposure(target, expected):
    assert classify_exposure(target) == expected


# ----------------------------------------------------------------- dedup key

def test_dedup_key_stable_by_identity():
    a = {"host_id": 1, "port": 80, "cve_ids": ["CVE-2021-41773"]}
    b = {"host_id": 1, "port": 80, "cve_ids": ["CVE-2021-41773"], "source": "nikto"}
    assert compute_dedup_key(a) == compute_dedup_key(b)      # same issue, any source


def test_dedup_key_differs_by_port_and_identity():
    base = {"host_id": 1, "port": 80, "cve_ids": ["CVE-1"]}
    assert compute_dedup_key(base) != compute_dedup_key({**base, "port": 443})
    assert compute_dedup_key(base) != compute_dedup_key({"host_id": 1, "port": 80, "cve_ids": ["CVE-2"]})
    # No CVE -> keyed on check_id.
    chk = {"host_id": 1, "port": 80, "check_id": "lybra:git@1"}
    assert compute_dedup_key(chk) == compute_dedup_key({**chk, "source": "x"})


# ------------------------------------------------------- dedup key: protocol
# Ronda 1 (roadmap §6.3): un servicio puede abrir el mismo puerto por TCP y
# por UDP (161 es el caso real: SNMP). Estos tres tests son los más
# importantes del cambio: fijan digests literales para que cualquier
# modificación futura del material de hash de compute_dedup_key falle a
# gritos, no en silencio.

def test_dedup_key_unchanged_without_protocol():
    finding = {"host_id": 1, "port": 161, "check_id": "lybra:open-port@1"}
    assert compute_dedup_key(finding) == "7f8791d1bcece1467ddb920c88ddab46"


def test_dedup_key_unchanged_for_explicit_tcp():
    finding = {"host_id": 1, "port": 161, "check_id": "lybra:open-port@1"}
    expected = compute_dedup_key(finding)
    assert compute_dedup_key({**finding, "protocol": "tcp"}) == expected
    assert compute_dedup_key({**finding, "protocol": ""}) == expected
    assert compute_dedup_key({**finding, "protocol": None}) == expected


def test_dedup_key_differs_for_udp():
    tcp = {"host_id": 1, "port": 161, "check_id": "lybra:open-port@1", "protocol": "tcp"}
    udp = {**tcp, "protocol": "udp"}
    assert compute_dedup_key(tcp) != compute_dedup_key(udp)


# -------------------------------------------------------------------- merge

def test_merge_combines_sources_and_keeps_strongest():
    findings = [
        {"host_id": 1, "port": 80, "cve_ids": ["CVE-1"], "source": "lybra",
         "qod": 70, "confirmed": False, "in_kev": False, "title": "by version"},
        {"host_id": 1, "port": 80, "cve_ids": ["CVE-1"], "source": "nikto",
         "qod": 99, "confirmed": True, "in_kev": True, "title": "confirmed"},
    ]
    merged = merge_findings(findings)
    assert len(merged) == 1
    m = merged[0]
    assert m["source"] == "lybra,nikto"
    assert m["qod"] == 99 and m["confirmed"] is True and m["in_kev"] is True
    assert m["title"] == "confirmed"          # title follows the strongest qod


def test_merge_keeps_distinct_keys():
    findings = [
        {"host_id": 1, "port": 80, "cve_ids": ["CVE-1"], "source": "lybra", "qod": 70},
        {"host_id": 1, "port": 443, "cve_ids": ["CVE-1"], "source": "lybra", "qod": 70},
    ]
    assert len(merge_findings(findings)) == 2


# ---------------------------------------------------------------- lifecycle

def _prev(state, key):
    return {key: {"state": state, "snapshot": {"dedup_key": key, "title": "old", "category": "x"}}}


def test_lifecycle_new_is_open():
    cur = [{"dedup_key": "K1"}]
    assert apply_lifecycle(cur, {})[0]["state"] == "open"


def test_lifecycle_regressed_when_was_fixed():
    cur = [{"dedup_key": "K1"}]
    assert apply_lifecycle(cur, _prev("fixed", "K1"))[0]["state"] == "regressed"


def test_lifecycle_accepted_is_sticky():
    cur = [{"dedup_key": "K1"}]
    assert apply_lifecycle(cur, _prev("accepted", "K1"))[0]["state"] == "accepted"


def test_lifecycle_carries_gone_finding_as_fixed():
    cur = [{"dedup_key": "K2"}]                  # K1 was present before, gone now
    out = apply_lifecycle(cur, _prev("open", "K1"))
    fixed = [f for f in out if f["state"] == "fixed"]
    assert len(fixed) == 1 and fixed[0]["dedup_key"] == "K1"


def test_lifecycle_does_not_recarry_already_fixed():
    cur = [{"dedup_key": "K2"}]
    out = apply_lifecycle(cur, _prev("fixed", "K1"))   # K1 already fixed, absent now
    assert all(f["dedup_key"] != "K1" for f in out)


def test_a_partial_scan_closes_nothing():
    """Lo que no se llegó a mirar no se puede dar por corregido.

    Un barrido que se queda sin presupuesto de reloj deja puertos sin probar.
    Si el ciclo de vida cerrara por ausencia, ese escaneo le diría al usuario
    que sus vulnerabilidades fueron remediadas cuando lo único cierto es que
    esta vez no se comprobaron — el fallo de L48-c por otra puerta.
    """
    cur = [{"dedup_key": "K2"}]                  # K1 estaba antes y ahora no aparece
    out = apply_lifecycle(cur, _prev("open", "K1"), close_missing=False)

    assert all(finding["state"] != "fixed" for finding in out)
    assert [finding["dedup_key"] for finding in out] == ["K2"]


def test_a_partial_scan_still_states_what_it_did_see():
    """No cerrar no es no decir nada: lo encontrado se etiqueta con normalidad,
    incluida la regresión de algo que constaba como corregido."""
    cur = [{"dedup_key": "K1"}]
    out = apply_lifecycle(cur, _prev("fixed", "K1"), close_missing=False)
    assert out[0]["state"] == "regressed"


# ------------------------------------------------------------------ scoring

@pytest.mark.parametrize("finding,exposure,expected", [
    ({"cvss_score": 9.8}, "public", "CRITICAL"),
    ({"cvss_score": 7.5}, "public", "HIGH"),
    ({"cvss_score": 7.5}, "private", "HIGH"),                       # cap doesn't lower HIGH
    ({"cvss_score": 9.8}, "private", "HIGH"),                       # private caps CRITICAL->HIGH
    ({"cvss_score": 7.5, "in_kev": True}, "public", "CRITICAL"),    # KEV escalates
    ({"cvss_score": 5.0, "epss_score": 0.6}, "public", "HIGH"),     # high EPSS escalates
    ({"cvss_score": 0.0, "confirmed": True}, "public", "MEDIUM"),   # confirmed w/o CVSS floors
    ({"cvss_score": 0.0}, "public", "INFO"),
    # required_os: an unconfirmed, platform-gated CVSS 9.8 match cannot
    # be verified without OS-detection, so it is capped at MEDIUM instead of
    # reading as CRITICAL.
    ({"cvss_score": 9.8, "required_os": "windows_10"}, "public", "MEDIUM"),
    ({"cvss_score": 9.8, "required_os": "windows_10", "in_kev": True}, "public", "MEDIUM"),  # cap wins over the KEV boost
    # A confirmed finding (Hygeia inventory, host OS already known) is exempt
    # from the cap — the platform precondition isn't a guess in that case.
    ({"cvss_score": 9.8, "required_os": "windows_10", "confirmed": True}, "public", "CRITICAL"),
    # required_os alongside a private-LAN target: both caps apply, smallest wins.
    ({"cvss_score": 9.8, "required_os": "windows_10"}, "private", "MEDIUM"),
])
def test_score_finding(finding, exposure, expected):
    assert score_finding(finding, exposure) == expected


# ───────────────────────── falso positivo vs riesgo aceptado (L35)
#
# Dicen cosas opuestas y hasta ahora compartían casilla. "Acepto el riesgo" es
# una afirmación sobre el negocio: esto es real y lo asumo. "Falso positivo" es
# una afirmación sobre el motor: esto no es real, te has equivocado. Un informe
# que cuenta los segundos como los primeros miente sobre la postura de
# seguridad, y tira además la única muestra etiquetada gratis que hay.

from datetime import datetime, timedelta   # noqa: E402


def _prev_decided(state, key, *, expires=None, check_id=None, feed_version=None):
    return {key: {
        "state": state,
        "snapshot": {"dedup_key": key, "title": "old", "category": "x",
                     "check_id": check_id, "feed_version": feed_version},
        "state_reason": "backport de Debian",
        "state_set_by": 7,
        "state_set_at": datetime(2026, 1, 1),
        "state_expires_at": expires,
    }}


def test_a_false_positive_stays_refuted():
    cur = [{"dedup_key": "K1", "check_id": "c@1", "feed_version": "f1"}]
    out = apply_lifecycle(cur, _prev_decided("false_positive", "K1",
                                             check_id="c@1", feed_version="f1"))
    assert out[0]["state"] == "false_positive"


def test_a_refuted_finding_carries_its_reason_and_author():
    """Sin esto la decisión sobreviviría como estado pero perdería su
    justificación en el escaneo siguiente, que es volver a la deuda que L35
    quita de en medio."""
    cur = [{"dedup_key": "K1", "check_id": "c@1", "feed_version": "f1"}]
    out = apply_lifecycle(cur, _prev_decided("false_positive", "K1",
                                             check_id="c@1", feed_version="f1"))
    assert out[0]["state_reason"] == "backport de Debian"
    assert out[0]["state_set_by"] == 7
    assert out[0]["state_set_at"] == datetime(2026, 1, 1)


def test_a_new_check_version_reopens_a_refuted_finding():
    """El desmentido es contra una detección concreta. Si el check que la
    produce cambia de versión, lo que se enseña hoy no es lo que el usuario
    desmintió, y arrastrar el desmentido escondería una detección nueva."""
    cur = [{"dedup_key": "K1", "check_id": "c@2", "feed_version": "f1"}]
    out = apply_lifecycle(cur, _prev_decided("false_positive", "K1",
                                             check_id="c@1", feed_version="f1"))
    assert out[0]["state"] == "open"


def test_a_new_feed_version_reopens_a_refuted_finding():
    """Lo mismo por la otra vía: la KB ha aprendido algo desde el desmentido."""
    cur = [{"dedup_key": "K1", "check_id": "c@1", "feed_version": "f2"}]
    out = apply_lifecycle(cur, _prev_decided("false_positive", "K1",
                                             check_id="c@1", feed_version="f1"))
    assert out[0]["state"] == "open"


def test_a_refuted_finding_that_disappears_is_not_carried_as_fixed():
    """No se puede "corregir" algo que el usuario dijo que nunca fue un
    problema. `false_positive` queda fuera del arrastre por construcción."""
    cur = [{"dedup_key": "K2", "check_id": None, "feed_version": None}]
    out = apply_lifecycle(cur, _prev_decided("false_positive", "K1"))
    assert all(finding["state"] != "fixed" for finding in out)
    assert [finding["dedup_key"] for finding in out] == ["K2"]


def test_an_accepted_risk_expires_back_to_open():
    """Un riesgo asumido hace un año se asumió en unas circunstancias que quizá
    ya no son las mismas."""
    cur = [{"dedup_key": "K1"}]
    out = apply_lifecycle(
        cur,
        _prev_decided("accepted", "K1", expires=datetime(2026, 1, 1)),
        now=datetime(2026, 1, 2),
    )
    assert out[0]["state"] == "open"


def test_an_accepted_risk_holds_until_it_expires():
    cur = [{"dedup_key": "K1"}]
    out = apply_lifecycle(
        cur,
        _prev_decided("accepted", "K1", expires=datetime(2026, 6, 1)),
        now=datetime(2026, 1, 2),
    )
    assert out[0]["state"] == "accepted"
    assert out[0]["state_expires_at"] == datetime(2026, 6, 1)


def test_an_accepted_risk_without_an_expiry_does_not_expire():
    """Los `accepted` anteriores a L35 no tienen plazo porque nadie se lo puso.
    Inventarles uno los reabriría todos de golpe el día del despliegue."""
    cur = [{"dedup_key": "K1"}]
    out = apply_lifecycle(cur, _prev_decided("accepted", "K1", expires=None),
                          now=datetime(2030, 1, 1))
    assert out[0]["state"] == "accepted"


def test_a_false_positive_never_expires_by_time():
    """El motor no se equivoca más por ser más tarde."""
    cur = [{"dedup_key": "K1", "check_id": "c@1", "feed_version": "f1"}]
    out = apply_lifecycle(
        cur,
        _prev_decided("false_positive", "K1", expires=datetime(2026, 1, 1),
                      check_id="c@1", feed_version="f1"),
        now=datetime(2030, 1, 1),
    )
    assert out[0]["state"] == "false_positive"


# ───────────────────── madurez de explotación (L34)
#
# `Finding.exploit_maturity` se declaraba en el modelo, se documentaba como
# "rellenada desde la Fase 1" y estaba NULL en todas las filas. Una columna que
# promete un dato y siempre está vacía es peor que no tenerla, porque quien lee
# el modelo cree que existe.

from src.modules.features.themis.lybra.correlation import (   # noqa: E402
    exploit_maturity, EXPLOIT_MATURITY_LADDER,
)


def test_kev_is_the_strongest_evidence_and_wins():
    """Estar en KEV es explotación activa confirmada: no hay evidencia mejor,
    así que no la puede rebajar una señal más débil."""
    assert exploit_maturity(in_kev=True) == "in_the_wild"
    assert exploit_maturity(in_kev=True, evidence="poc") == "in_the_wild"


def test_an_nvd_exploit_reference_reads_as_a_proof_of_concept():
    assert exploit_maturity(in_kev=False, evidence="poc") == "poc"


def test_no_evidence_is_none_and_never_null():
    """`none` es una afirmación —no consta nada público— y `NULL` era la
    ausencia de afirmación. La columna existe para decir algo."""
    assert exploit_maturity(in_kev=False) == "none"
    assert exploit_maturity(in_kev=False, evidence=None) == "none"


def test_an_unknown_evidence_level_falls_back_to_none():
    """Una fuente futura que devuelva algo fuera de la escalera no puede
    colarlo en la columna."""
    assert exploit_maturity(in_kev=False, evidence="carísimo") == "none"


def test_the_ladder_runs_from_least_to_most_serious():
    assert EXPLOIT_MATURITY_LADDER.index("poc") < EXPLOIT_MATURITY_LADDER.index("functional")
    assert EXPLOIT_MATURITY_LADDER.index("weaponized") < EXPLOIT_MATURITY_LADDER.index("in_the_wild")
