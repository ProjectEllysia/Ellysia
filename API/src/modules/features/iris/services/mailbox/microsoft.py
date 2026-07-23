"""
GraphConnector — Microsoft Graph API v1.0 sobre OAuth 2.0 de Entra ID
(Azure AD).

Mismo criterio que ``gmail.py``: ``requests`` puro, sin ``msal``.

**Matiz que el plan no cubre (decisión de diseño de esta sesión):** Graph no
tiene un scope "solo metadata" para correo como Gmail (``gmail.metadata``);
el permiso delegado ``Mail.Read`` da acceso al cuerpo completo siempre. Para
este conector, "solo cabeceras" se aplica a nivel de *aplicación* — el
conector simplemente nunca pide ``$value``/el cuerpo del mensaje cuando
``full_message_mode`` es False — no a nivel de scope OAuth. El usuario que
conecta una cuenta Microsoft con el modo completo desactivado sigue
concediendo un permiso que técnicamente permite más de lo que Iris
efectivamente usa; es una limitación de la plataforma, no de este código.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlencode

import requests

import src.modules.system.config_reading as CR

from .base import MailboxConnector, MessageRef, TokenSet

logger = logging.getLogger(__name__)

_GRAPH_API = "https://graph.microsoft.com/v1.0"

# Mismo criterio que _METADATA_HEADERS de gmail.py: solo lo que las 40
# reglas de Iris usan.
_SELECT_FIELDS = "internetMessageHeaders"

_TIMEOUT_SECONDS = 20


class GraphConnector(MailboxConnector):
    provider = "microsoft"

    def __init__(self, redirect_uri: str, folder: Optional[str] = None) -> None:
        env = CR.get_graph_environment()
        self._client_id = env["client_id"]
        self._client_secret = env["client_secret"]
        self._tenant = env["tenant"]
        self._redirect_uri = redirect_uri
        # Nombre bien conocido ("inbox") o id de mailFolder de Graph.
        self._folder = folder or "inbox"

    @property
    def _authority(self) -> str:
        return f"https://login.microsoftonline.com/{self._tenant}"

    def authorize_url(self, state: str, full_message_mode: bool) -> str:
        # full_message_mode no cambia el scope aquí (ver docstring del
        # módulo) -- se aplica en fetch_raw/list_new, no en el consentimiento.
        params = {
            "client_id": self._client_id,
            "response_type": "code",
            "redirect_uri": self._redirect_uri,
            "response_mode": "query",
            "scope": "offline_access openid email Mail.Read",
            "state": state,
        }
        return f"{self._authority}/oauth2/v2.0/authorize?{urlencode(params)}"

    def exchange_code(self, code: str) -> TokenSet:
        response = requests.post(f"{self._authority}/oauth2/v2.0/token", data={
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "code": code,
            "redirect_uri": self._redirect_uri,
            "grant_type": "authorization_code",
        }, timeout=_TIMEOUT_SECONDS)
        response.raise_for_status()
        payload = response.json()
        account_email = self._get_account_email(payload["access_token"])
        return self._token_set_from(payload, account_email)

    def refresh(self, refresh_token: str) -> TokenSet:
        response = requests.post(f"{self._authority}/oauth2/v2.0/token", data={
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }, timeout=_TIMEOUT_SECONDS)
        response.raise_for_status()
        payload = response.json()
        payload.setdefault("refresh_token", refresh_token)
        account_email = self._get_account_email(payload["access_token"])
        return self._token_set_from(payload, account_email)

    def list_new(self, access_token: str, cursor: Optional[str]) -> tuple[list[MessageRef], str]:
        headers = {"Authorization": f"Bearer {access_token}"}

        if cursor is None:
            # Bootstrap: paginar el delta completo UNA vez, descartando el
            # contenido, hasta obtener el deltaLink final -- sin backfill.
            url = (
                f"{_GRAPH_API}/me/mailFolders/{self._folder}/messages/delta"
                f"?$select={_SELECT_FIELDS}"
            )
            while True:
                response = requests.get(url, headers=headers, timeout=_TIMEOUT_SECONDS)
                response.raise_for_status()
                data = response.json()
                if "@odata.deltaLink" in data:
                    return [], data["@odata.deltaLink"]
                url = data["@odata.nextLink"]

        refs: list[MessageRef] = []
        url = cursor
        new_cursor = cursor
        while True:
            response = requests.get(url, headers=headers, timeout=_TIMEOUT_SECONDS)
            if response.status_code == 410:
                # Gone: el deltaLink expiró (ventana de retención de Graph) --
                # única opción es re-bootstrapear, igual que el 404 de Gmail.
                logger.warning("Graph delta cursor expirado, re-bootstrapping")
                return self.list_new(access_token, cursor=None)
            response.raise_for_status()
            data = response.json()

            for item in data.get("value", []):
                refs.append(MessageRef(
                    provider_message_id=item["id"],
                    raw={"internetMessageHeaders": item.get("internetMessageHeaders", [])},
                ))

            if "@odata.deltaLink" in data:
                new_cursor = data["@odata.deltaLink"]
                break
            url = data["@odata.nextLink"]

        return refs, new_cursor

    def fetch_headers(self, access_token: str, message_ref: MessageRef) -> str:
        cached = message_ref.raw.get("internetMessageHeaders")
        if cached is None:
            response = requests.get(
                f"{_GRAPH_API}/me/messages/{message_ref.provider_message_id}",
                headers={"Authorization": f"Bearer {access_token}"},
                params={"$select": _SELECT_FIELDS}, timeout=_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            cached = response.json().get("internetMessageHeaders", [])
        return "".join(f"{h['name']}: {h['value']}\r\n" for h in cached)

    def fetch_raw(self, access_token: str, message_ref: MessageRef) -> str:
        response = requests.get(
            f"{_GRAPH_API}/me/messages/{message_ref.provider_message_id}/$value",
            headers={"Authorization": f"Bearer {access_token}"}, timeout=_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        return response.text

    def revoke(self, refresh_token: str) -> None:
        # Microsoft Graph no expone una API para que una app confidencial
        # revoque un refresh_token concreto emitido a un usuario (a
        # diferencia de Google) -- solo el propio usuario
        # (myaccount.microsoft.com) o un admin de Entra ID pueden hacerlo.
        # Documentado explícitamente en vez de fingir una llamada que no
        # existe: borrar la fila localmente sigue siendo correcto (Fase 3:
        # "guardar lo mínimo"), el token simplemente sigue siendo válido en
        # el lado de Microsoft hasta que expire o el usuario lo revoque allí.
        logger.warning(
            "Microsoft Graph no soporta revocación de refresh_token por la "
            "app; la conexión se borra localmente pero el token puede "
            "seguir siendo válido hasta que el usuario lo revoque en "
            "myaccount.microsoft.com."
        )

    @staticmethod
    def _get_account_email(access_token: str) -> str:
        response = requests.get(
            f"{_GRAPH_API}/me",
            headers={"Authorization": f"Bearer {access_token}"},
            params={"$select": "mail,userPrincipalName"}, timeout=_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        profile = response.json()
        # "mail" es NULL para algunas cuentas (p.ej. algunas de solo-Azure-AD
        # sin buzón Exchange asociado a ese campo); userPrincipalName es el
        # identificador que siempre existe.
        return profile.get("mail") or profile["userPrincipalName"]

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
