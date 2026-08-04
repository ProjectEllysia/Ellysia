"""
GmailConnector — Gmail API v1 sobre OAuth 2.0 de Google.

``requests`` (ya dependencia del proyecto, sin uso previo en ``src/`` —
verificado) en vez de ``google-auth``/``google-api-python-client``: la
superficie que necesitamos (token endpoint + 4 llamadas REST) no justifica
esas dependencias, mismo criterio que ``tools/scribe``/``tools/herald`` usan
SDKs nativos solo cuando el proveedor no tiene una API REST simple.

Scope según ``full_message_mode``: ``gmail.metadata`` (más restrictivo,
"como mínimo las cabeceras") o ``gmail.readonly`` (cuerpo completo) — a
diferencia de Microsoft Graph, Gmail sí tiene un scope granular para esto,
fijado en el consentimiento inicial y no ampliable después sin re-consentir.
"""

from __future__ import annotations

import base64
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlencode

import requests

import src.modules.system.config_reading as CR

from .base import MailboxConnector, MessageRef, TokenSet
from .registry import register_connector

logger = logging.getLogger(__name__)

_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
_TOKEN_URL = "https://oauth2.googleapis.com/token"
_REVOKE_URL = "https://oauth2.googleapis.com/revoke"
_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"

_SCOPE_METADATA = "https://www.googleapis.com/auth/gmail.metadata"
_SCOPE_READONLY = "https://www.googleapis.com/auth/gmail.readonly"

# Cabeceras que alimentan las 40 reglas de Iris (ver services/shared.py y
# services/rules/*) — restringir a estas en vez de pedir todas mantiene el
# payload de format=metadata pequeño sin perder ninguna señal que el motor
# use hoy.
_METADATA_HEADERS = [
    "From", "To", "Cc", "Reply-To", "Return-Path", "Sender", "Envelope-From",
    "Subject", "Date", "Message-ID", "In-Reply-To", "References",
    "Received", "Authentication-Results", "Received-SPF",
    "ARC-Seal", "ARC-Message-Signature", "ARC-Authentication-Results",
    "DKIM-Signature", "List-Unsubscribe", "List-Unsubscribe-Post",
    "Content-Type", "Thread-Index", "Thread-Topic",
]

_TIMEOUT_SECONDS = 20


@register_connector("gmail")
class GmailConnector(MailboxConnector):
    provider = "gmail"

    def __init__(self, redirect_uri: str, folder: Optional[str] = None) -> None:
        env = CR.get_gmail_environment()
        self._client_id = env["client_id"]
        self._client_secret = env["client_secret"]
        self._redirect_uri = redirect_uri
        # Gmail label id to restrict history.list to (e.g. "INBOX"); None =
        # every new message account-wide, Gmail's own default.
        self._label_id = folder

    def authorize_url(self, state: str, full_message_mode: bool) -> str:
        scope = _SCOPE_READONLY if full_message_mode else _SCOPE_METADATA
        params = {
            "client_id": self._client_id,
            "redirect_uri": self._redirect_uri,
            "response_type": "code",
            "scope": f"{scope} openid email",
            "state": state,
            "access_type": "offline",
            # "consent" fuerza a Google a devolver un refresh_token incluso
            # si el usuario ya había concedido este scope antes — sin esto,
            # una reconexión silenciosa no devuelve refresh_token.
            "prompt": "consent",
        }
        return f"{_AUTH_URL}?{urlencode(params)}"

    def exchange_code(self, code: str) -> TokenSet:
        response = requests.post(_TOKEN_URL, data={
            "code": code,
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "redirect_uri": self._redirect_uri,
            "grant_type": "authorization_code",
        }, timeout=_TIMEOUT_SECONDS)
        response.raise_for_status()
        payload = response.json()
        account_email = self._get_account_email(payload["access_token"])
        return self._token_set_from(payload, account_email)

    def refresh(self, refresh_token: str) -> TokenSet:
        response = requests.post(_TOKEN_URL, data={
            "refresh_token": refresh_token,
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "grant_type": "refresh_token",
        }, timeout=_TIMEOUT_SECONDS)
        response.raise_for_status()
        payload = response.json()
        # Google no siempre re-emite el refresh_token en un refresh -- el
        # llamante (IrisMailboxManager) mantiene el original si este viene vacío.
        payload.setdefault("refresh_token", refresh_token)
        account_email = self._get_account_email(payload["access_token"])
        return self._token_set_from(payload, account_email)

    def list_new(self, access_token: str, cursor: Optional[str]) -> tuple[list[MessageRef], str]:
        headers = {"Authorization": f"Bearer {access_token}"}

        if cursor is None:
            # Bootstrap: solo capturar el historyId actual, sin backfill.
            response = requests.get(f"{_API_BASE}/profile", headers=headers, timeout=_TIMEOUT_SECONDS)
            response.raise_for_status()
            return [], str(response.json()["historyId"])

        refs: list[MessageRef] = []
        new_cursor = cursor
        page_token: Optional[str] = None
        while True:
            params = {"startHistoryId": cursor, "historyTypes": "messageAdded"}
            if self._label_id:
                params["labelId"] = self._label_id
            if page_token:
                params["pageToken"] = page_token
            response = requests.get(f"{_API_BASE}/history", headers=headers,
                                     params=params, timeout=_TIMEOUT_SECONDS)
            if response.status_code == 404:
                # historyId demasiado antiguo (fuera de la ventana de retención de
                # Gmail, ~7 días de inactividad) -- solo opción es re-bootstrapear.
                logger.warning("Gmail history cursor expirado, re-bootstrapping")
                return self.list_new(access_token, cursor=None)
            response.raise_for_status()
            data = response.json()

            for record in data.get("history", []):
                for added in record.get("messagesAdded", []):
                    message_id = added["message"]["id"]
                    refs.append(MessageRef(provider_message_id=message_id))

            new_cursor = str(data.get("historyId", new_cursor))
            page_token = data.get("nextPageToken")
            if not page_token:
                break

        return refs, new_cursor

    def fetch_headers(self, access_token: str, message_ref: MessageRef) -> str:
        headers = {"Authorization": f"Bearer {access_token}"}
        params = {"format": "metadata", "metadataHeaders": _METADATA_HEADERS}
        response = requests.get(
            f"{_API_BASE}/messages/{message_ref.provider_message_id}",
            headers=headers, params=params, timeout=_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload_headers = response.json().get("payload", {}).get("headers", [])
        return "".join(f"{h['name']}: {h['value']}\r\n" for h in payload_headers)

    def fetch_raw(self, access_token: str, message_ref: MessageRef) -> str:
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(
            f"{_API_BASE}/messages/{message_ref.provider_message_id}",
            headers=headers, params={"format": "raw"}, timeout=_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        raw_b64url = response.json()["raw"]
        padded = raw_b64url + "=" * (-len(raw_b64url) % 4)
        return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")

    def revoke(self, refresh_token: str) -> None:
        response = requests.post(_REVOKE_URL, data={"token": refresh_token}, timeout=_TIMEOUT_SECONDS)
        # Un token ya revocado/expirado devuelve 400 -- no es un fallo real
        # del lado del usuario que está desconectando su cuenta.
        if response.status_code not in (200, 400):
            response.raise_for_status()

    @staticmethod
    def _get_account_email(access_token: str) -> str:
        response = requests.get(
            f"{_API_BASE}/profile",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        return response.json()["emailAddress"]

    @staticmethod
    def _token_set_from(payload: dict, account_email: str) -> TokenSet:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(payload.get("expires_in", 3600)))
        return TokenSet(
            refresh_token=payload["refresh_token"],
            access_token=payload["access_token"],
            access_token_expires_at=expires_at,
            scopes=payload.get("scope", ""),
            account_email=account_email,
        )
