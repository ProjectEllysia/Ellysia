from .model import (
    User,
    AccessToken,
    RefreshToken,
    UserAttribute,
    MFATotpCredential,
    MFARecoveryCode,
    MFAChallenge,
)
from .services import require_oauth_token, require_attributes, require_role, AttributeType
from .endpoints import oauth_blp, users_blp, get_current_user
from .managers import UserManager, OAuthTokenManager, MFAManager
from src.modules.acheron.model import Vault


class _LazyLoader:
    _users_blp = None
    _oauth_blp = None

    @property
    def users_blp(self):
        if self._users_blp is None:
            self._users_blp = users_blp
        return self._users_blp

    @property
    def oauth_blp(self):
        if self._oauth_blp is None:
            self._oauth_blp = oauth_blp
        return self._oauth_blp

_loader = _LazyLoader()


def __getattr__(name):
    if name == "users_blp":
        return _loader.users_blp
    if name == "oauth_blp":
        return _loader.oauth_blp
    if name == "users_bp":
        return _loader.users_blp
    if name == "oauth_bp":
        return _loader.oauth_blp
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "User",
    "AccessToken",
    "RefreshToken",
    "UserAttribute",
    "MFATotpCredential",
    "MFARecoveryCode",
    "MFAChallenge",
    "UserManager",
    "OAuthTokenManager",
    "MFAManager",
    "users_blp",
    "oauth_blp",
    "require_oauth_token",
    "require_attributes",
    "require_role",
    "AttributeType",
    "get_current_user",
]
