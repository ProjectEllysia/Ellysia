"""Tests de integración del módulo Acheron (vaults de secretos)."""

import pytest

pytestmark = pytest.mark.integration


def test_get_vault_requires_authentication(client):
    assert client.get("/acheron/vault").status_code == 401


def test_create_vault_requires_create_attribute(client, regular_user, auth_headers):
    # role_user tiene acheron_read pero no acheron_create.
    resp = client.post("/acheron/vault", headers=auth_headers(regular_user),
                       json={"storables": []})
    assert resp.status_code == 403


def test_get_vault_empty_returns_404(client, regular_user, auth_headers):
    # El usuario tiene acheron_read (baseline) pero no tiene vault creado.
    resp = client.get("/acheron/vault", headers=auth_headers(regular_user))
    assert resp.status_code == 404


def test_add_storable_requires_create_attribute(client, regular_user, auth_headers):
    resp = client.post("/acheron/storables", headers=auth_headers(regular_user), json={
        "kind": "account",
        "username": "u",
        "domain": "d",
        "password": "p",
    })
    assert resp.status_code == 403


# ── PATCH /vault (cambio de contraseña maestra) ──────────────────────────────


def _vault_payload(checker="checker-old", vault_key="vaultkey-old", salt="salt-old"):
    return {
        "checker": checker,
        "vaultKey": vault_key,
        "algorithm": {
            "transformation": "AES/GCM/NoPadding",
            "kdf": "Argon2",
            "kdfIterations": "3",
            "kdfMemoryKiB": "65536",
            "kdfParallelism": "1",
            "salt": salt,
        },
        "accounts": [
            {
                "id": "acc0001",
                "title": "enc-title",
                "createdAt": "2026-01-01T00:00:00.000Z",
                "updatedAt": "2026-01-01T00:00:00.000Z",
                "username": "enc-user",
                "domain": "enc-domain",
                "password": "enc-pass",
            }
        ],
    }


def test_change_vault_password_requires_update_attribute(client, regular_user, auth_headers):
    # role_user tiene acheron_read pero no acheron_update.
    resp = client.patch("/acheron/vault", headers=auth_headers(regular_user), json={
        "checker": "c", "vaultKey": "k", "algorithm": {"salt": "s"},
    })
    assert resp.status_code == 403


def test_change_vault_password_without_vault_returns_404(client, make_user, auth_headers):
    user = make_user(role="role_user", attributes=["acheron_update"])
    resp = client.patch("/acheron/vault", headers=auth_headers(user), json={
        "checker": "c", "vaultKey": "k", "algorithm": {"salt": "s"},
    })
    assert resp.status_code == 404


def test_change_vault_password_invalid_body_is_rejected(client, make_user, auth_headers):
    user = make_user(role="role_user", attributes=["acheron_create", "acheron_update"])
    # Falta vaultKey/algorithm -> error de validación del schema.
    resp = client.patch("/acheron/vault", headers=auth_headers(user), json={"checker": "c"})
    assert resp.status_code in (400, 422)


def test_change_vault_password_updates_metadata_and_keeps_storables(client, make_user, auth_headers):
    user = make_user(role="role_user", attributes=["acheron_create", "acheron_update"])
    headers = auth_headers(user)

    # 1. Crear el vault con un storable.
    created = client.post("/acheron/vault", headers=headers, json=_vault_payload())
    assert created.status_code in (200, 201)

    # 2. Cambiar la contraseña: solo metadatos (checker/vaultKey/algorithm).
    patch = client.patch("/acheron/vault", headers=headers, json={
        "checker": "checker-new",
        "vaultKey": "vaultkey-new",
        "algorithm": {
            "transformation": "AES/GCM/NoPadding",
            "kdf": "Argon2",
            "kdfIterations": "3",
            "kdfMemoryKiB": "65536",
            "kdfParallelism": "1",
            "salt": "salt-new",
        },
    })
    assert patch.status_code == 200

    # 3. El vault refleja los nuevos metadatos y conserva el storable intacto.
    got = client.get("/acheron/vault", headers=headers)
    assert got.status_code == 200
    body = got.get_json()

    assert body["checker"] == "checker-new"
    assert body["vaultKey"] == "vaultkey-new"
    assert body["algorithm"]["salt"] == "salt-new"

    assert len(body["accounts"]) == 1
    account = body["accounts"][0]
    assert account["id"] == "acc0001"
    assert account["password"] == "enc-pass"
    assert account["username"] == "enc-user"


def test_metadata_version_starts_at_one_and_bumps_on_password_change(client, make_user, auth_headers):
    user = make_user(role="role_user", attributes=["acheron_create", "acheron_update"])
    headers = auth_headers(user)

    client.post("/acheron/vault", headers=headers, json=_vault_payload())

    first = client.get("/acheron/vault", headers=headers).get_json()
    assert first["metadataVersion"] == 1

    patch = client.patch("/acheron/vault", headers=headers, json={
        "checker": "checker-new",
        "vaultKey": "vaultkey-new",
        "algorithm": {
            "transformation": "AES/GCM/NoPadding",
            "kdf": "Argon2",
            "kdfIterations": "3",
            "kdfMemoryKiB": "65536",
            "kdfParallelism": "1",
            "salt": "salt-new",
        },
    })
    assert patch.status_code == 200

    second = client.get("/acheron/vault", headers=headers).get_json()
    assert second["metadataVersion"] == 2


# ── Storables: los 7 kinds soportados (cobertura del registro storable_specs) ─


def test_all_storable_kinds_add_update_and_export_roundtrip(client, make_user, auth_headers):
    """Todos los kinds pasan por add_storable_to_vault, update_storable y
    export_vault_to_json: guarda contra typos en el registro storable_specs
    (un solo test de account no detectaría un mapeo mal escrito en, p. ej.,
    bankaccount o identity)."""
    user = make_user(role="role_user", attributes=["acheron_create", "acheron_update"])
    headers = auth_headers(user)

    created = client.post("/acheron/vault", headers=headers, json=_vault_payload())
    assert created.status_code in (200, 201)

    creates = [
        {"kind": "account", "internalId": "k-account", "username": "u", "domain": "d", "password": "p"},
        {"kind": "creditcard", "internalId": "k-cc", "cardHolderName": "Jane", "cardNumber": "4111",
         "expirationDate": "12/30", "postalCode": "00000", "cvv": "123"},
        {"kind": "securenote", "internalId": "k-note", "content": "secret note"},
        {"kind": "identity", "internalId": "k-id", "fullName": "Jane Doe", "email": "j@x.com",
         "phone": "123", "address": "addr", "city": "city", "country": "country", "documentId": "doc1"},
        {"kind": "bankaccount", "internalId": "k-bank", "bankName": "Bank", "holder": "Jane",
         "iban": "ES00", "swiftBic": "BIC", "accountNumber": "0001"},
        {"kind": "wifi", "internalId": "k-wifi", "ssid": "myssid", "password": "wifipass",
         "securityType": "WPA2"},
        {"kind": "license", "internalId": "k-lic", "product": "prod", "licenseKey": "key",
         "licensedTo": "Jane", "version": "1.0"},
    ]
    for body in creates:
        resp = client.post("/acheron/storables", headers=headers, json=body)
        assert resp.status_code == 201, (body["kind"], resp.get_json())

    got = client.get("/acheron/vault", headers=headers)
    assert got.status_code == 200
    body = got.get_json()

    def _by_id(items, internal_id):
        return next(item for item in items if item["id"] == internal_id)

    assert _by_id(body["accounts"], "k-account")["username"] == "u"
    assert _by_id(body["creditcards"], "k-cc")["cardHolderName"] == "Jane"
    assert _by_id(body["securenotes"], "k-note")["content"] == "secret note"
    assert _by_id(body["identities"], "k-id")["documentId"] == "doc1"
    assert _by_id(body["bankaccounts"], "k-bank")["swiftBic"] == "BIC"
    assert _by_id(body["wifinetworks"], "k-wifi")["securityType"] == "WPA2"
    assert _by_id(body["licenses"], "k-lic")["licensedTo"] == "Jane"

    bulk = client.patch("/acheron/storables", headers=headers, json=[
        {"internalId": "k-bank", "changes": {"holder": "New Holder"}},
        {"internalId": "k-wifi", "changes": {"ssid": "newssid"}},
    ])
    assert bulk.status_code == 200
    statuses = {r["internalId"]: r["status"] for r in bulk.get_json()["results"]}
    assert statuses["k-bank"] == "updated"
    assert statuses["k-wifi"] == "updated"

    got2 = client.get("/acheron/vault", headers=headers)
    body2 = got2.get_json()
    assert _by_id(body2["bankaccounts"], "k-bank")["holder"] == "New Holder"
    assert _by_id(body2["wifinetworks"], "k-wifi")["ssid"] == "newssid"


# ── Revisión del vault (concurrencia optimista) ──────────────────────────────


def _full_user(make_user):
    return make_user(role="role_user", attributes=[
        "acheron_read", "acheron_create", "acheron_update", "acheron_delete",
    ])


def _account(internal_id, password="p"):
    return {
        "kind": "account", "internalId": internal_id, "title": internal_id,
        "username": "u", "domain": "d", "password": password,
    }


def test_new_vault_starts_at_revision_one_and_exposes_etag(client, make_user, auth_headers):
    headers = auth_headers(_full_user(make_user))
    created = client.post("/acheron/vault", headers=headers, json=_vault_payload())
    assert created.status_code == 201
    assert created.get_json()["revision"] == 1

    got = client.get("/acheron/vault", headers=headers)
    assert got.get_json()["revision"] == 1
    assert got.headers["ETag"] == '"1"'


def test_every_granular_mutation_bumps_the_revision(client, make_user, auth_headers):
    """El bump vive en un único helper: si alguna ruta de mutación se lo salta,
    este test lo caza."""
    headers = auth_headers(_full_user(make_user))
    client.post("/acheron/vault", headers=headers, json=_vault_payload())

    def revision():
        return client.get("/acheron/vault/revision", headers=headers).get_json()["revision"]

    assert revision() == 1

    assert client.post("/acheron/storables", headers=headers,
                       json=_account("k-1")).status_code == 201
    assert revision() == 2

    assert client.patch("/acheron/storables", headers=headers, json=[
        {"internalId": "k-1", "changes": {"password": "nueva"}},
    ]).status_code == 200
    assert revision() == 3

    assert client.delete("/acheron/storables", headers=headers,
                         json={"internalId": "k-1"}).status_code == 200
    assert revision() == 4

    assert client.patch("/acheron/vault", headers=headers, json={
        "checker": "c2", "vaultKey": "k2", "algorithm": {"salt": "s2"},
    }).status_code == 200
    assert revision() == 5


def test_revision_probe_does_not_leak_storables(client, make_user, auth_headers):
    headers = auth_headers(_full_user(make_user))
    client.post("/acheron/vault", headers=headers, json=_vault_payload())

    resp = client.get("/acheron/vault/revision", headers=headers)
    assert resp.status_code == 200
    assert resp.get_json() == {"revision": 1}
    assert resp.headers["ETag"] == '"1"'


def test_revision_probe_without_vault_returns_404(client, regular_user, auth_headers):
    assert client.get("/acheron/vault/revision",
                      headers=auth_headers(regular_user)).status_code == 404


def test_malformed_if_match_is_rejected(client, make_user, auth_headers):
    headers = auth_headers(_full_user(make_user))
    client.post("/acheron/vault", headers=headers, json=_vault_payload())

    resp = client.post("/acheron/storables",
                       headers={**headers, "If-Match": "*"}, json=_account("k-1"))
    assert resp.status_code == 400


def test_granular_write_with_stale_revision_is_rejected_and_changes_nothing(
    client, make_user, auth_headers
):
    headers = auth_headers(_full_user(make_user))
    client.post("/acheron/vault", headers=headers, json=_vault_payload())
    client.post("/acheron/storables", headers=headers, json=_account("k-1"))  # rev 2

    stale = client.post("/acheron/storables",
                        headers={**headers, "If-Match": '"1"'}, json=_account("k-2"))
    assert stale.status_code == 409
    body = stale.get_json()
    assert body["error"] == "vault_revision_mismatch"
    assert body["currentRevision"] == 2
    assert body["yourRevision"] == 1

    vault = client.get("/acheron/vault", headers=headers).get_json()
    assert {a["id"] for a in vault["accounts"]} == {"acc0001", "k-1"}
    assert vault["revision"] == 2


def test_granular_write_with_current_revision_succeeds(client, make_user, auth_headers):
    headers = auth_headers(_full_user(make_user))
    client.post("/acheron/vault", headers=headers, json=_vault_payload())

    resp = client.post("/acheron/storables",
                       headers={**headers, "If-Match": '"1"'}, json=_account("k-1"))
    assert resp.status_code == 201
    assert resp.get_json()["revision"] == 2
    assert resp.headers["ETag"] == '"2"'


def test_granular_write_without_if_match_still_works(client, make_user, auth_headers):
    """Compatibilidad: hasta que web y móvil manden If-Match, las ops granulares
    mantienen el comportamiento actual."""
    headers = auth_headers(_full_user(make_user))
    client.post("/acheron/vault", headers=headers, json=_vault_payload())

    assert client.post("/acheron/storables", headers=headers,
                       json=_account("k-1")).status_code == 201


def test_replacing_existing_vault_requires_explicit_mode(client, make_user, auth_headers):
    headers = auth_headers(_full_user(make_user))
    client.post("/acheron/vault", headers=headers, json=_vault_payload())

    resp = client.post("/acheron/vault", headers={**headers, "If-Match": '"1"'},
                       json=_vault_payload(checker="otro"))
    assert resp.status_code == 400

    vault = client.get("/acheron/vault", headers=headers).get_json()
    assert vault["checker"] == "checker-old"


def test_replacing_existing_vault_requires_if_match(client, make_user, auth_headers):
    headers = auth_headers(_full_user(make_user))
    client.post("/acheron/vault", headers=headers, json=_vault_payload())

    resp = client.post("/acheron/vault?mode=replace", headers=headers,
                       json=_vault_payload(checker="otro"))
    assert resp.status_code == 409
    assert resp.get_json()["yourRevision"] is None

    vault = client.get("/acheron/vault", headers=headers).get_json()
    assert vault["checker"] == "checker-old"


def test_replacing_existing_vault_with_current_revision_succeeds(client, make_user, auth_headers):
    headers = auth_headers(_full_user(make_user))
    client.post("/acheron/vault", headers=headers, json=_vault_payload())

    resp = client.post("/acheron/vault?mode=replace",
                       headers={**headers, "If-Match": '"1"'},
                       json=_vault_payload(checker="checker-nuevo"))
    assert resp.status_code == 200
    assert resp.get_json()["revision"] == 2

    vault = client.get("/acheron/vault", headers=headers).get_json()
    assert vault["checker"] == "checker-nuevo"
    assert vault["revision"] == 2


def test_stale_mobile_push_does_not_wipe_the_web_edit(client, make_user, auth_headers):
    """Regresión del bug reportado: sesión abierta en web y móvil a la vez.

    El móvil se desbloqueó con la revisión 1; la web añade una credencial
    (revisión 2); el móvil pulsa "Sincronizar" y empuja su snapshot de la
    revisión 1. Antes esto borraba el cambio de la web sin avisar.
    """
    headers = auth_headers(_full_user(make_user))
    client.post("/acheron/vault", headers=headers, json=_vault_payload())

    # Snapshot con el que el móvil se desbloqueó (revisión 1).
    snapshot = client.get("/acheron/vault", headers=headers).get_json()
    assert snapshot["revision"] == 1

    # La web añade una credencial nueva.
    assert client.post("/acheron/storables", headers=headers,
                       json=_account("web-nueva", password="secreto-web")).status_code == 201

    # El móvil empuja su snapshot obsoleto.
    push = client.post(
        "/acheron/vault?mode=replace",
        headers={**headers, "If-Match": f'"{snapshot["revision"]}"'},
        json=snapshot,
    )
    assert push.status_code == 409
    assert push.get_json()["currentRevision"] == 2

    # El cambio de la web sobrevive intacto.
    vault = client.get("/acheron/vault", headers=headers).get_json()
    assert vault["revision"] == 2
    nueva = next(a for a in vault["accounts"] if a["id"] == "web-nueva")
    assert nueva["password"] == "secreto-web"
    assert {a["id"] for a in vault["accounts"]} == {"acc0001", "web-nueva"}


# ── GET /generate-password ────────────────────────────────────────────────
# S6: era el único endpoint fuera de /aegis/quiz sin autenticación, pese a no
# tener ningún consumidor que lo necesite sin sesión — ahora exige JWT como
# el resto de la API.


def test_generate_password_requires_authentication(client):
    assert client.get("/acheron/generate-password").status_code == 401


def test_generate_password_default_length(client, regular_user, auth_headers):
    resp = client.get("/acheron/generate-password", headers=auth_headers(regular_user))
    assert len(resp.get_json()["password"]) == 20


def test_generate_password_respects_length(client, regular_user, auth_headers):
    resp = client.get("/acheron/generate-password?length=32", headers=auth_headers(regular_user))
    assert resp.status_code == 200
    assert len(resp.get_json()["password"]) == 32


def test_generate_password_rejects_length_out_of_range(client, regular_user, auth_headers):
    headers = auth_headers(regular_user)
    assert client.get("/acheron/generate-password?length=200", headers=headers).status_code == 422
    assert client.get("/acheron/generate-password?length=2", headers=headers).status_code == 422


def test_generate_password_rejects_all_charsets_disabled(client, regular_user, auth_headers):
    resp = client.get(
        "/acheron/generate-password"
        "?uppercase=false&lowercase=false&digits=false&symbols=false",
        headers=auth_headers(regular_user),
    )
    assert resp.status_code == 422


def test_generate_password_exclude_ambiguous(client, regular_user, auth_headers):
    resp = client.get(
        "/acheron/generate-password?length=64&excludeAmbiguous=true",
        headers=auth_headers(regular_user),
    )
    assert resp.status_code == 200
    password = resp.get_json()["password"]
    assert not set(password) & set("0O1lI")
