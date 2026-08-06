from logging.config import fileConfig
from urllib.parse import quote_plus

from alembic import context
from sqlalchemy import create_engine, pool

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

from src.modules.shared._model import Base
import src.modules.users.model       # User, AccessToken, RefreshToken, UserAttribute
import src.modules.accounts.model    # Plan, PlanLimit, Subscription, Organization, OrganizationMember, OrganizationInvitation, UsageCounter
import src.modules.features.themis.model      # Scan, Host, NmapScan, NiktoScan, LybraScan, NucleiScan, etc.
import src.modules.features.acheron.model     # Vault, Storable, Account, CreditCard, etc.
import src.modules.features.aegis.model       # Topic, AegisDocument, AegisTip, AegisDocumentAlert
import src.modules.features.iris.model        # IrisAnalysis, IrisRuleResult, IrisDocument
import src.modules.features.hygeia.model      # MonitoredAsset, AssetSnapshot, Anomaly

target_metadata = Base.metadata


def get_url():
    from src.modules.system.config_reading import get_db_credentials as _creds
    c = _creds()
    return (
        f"{c['dialect']}://"
        f"{c['username']}:{quote_plus(c['password'])}"
        f"@{c['host']}:{c['port']}/{c['dbname']}"
    )


def run_migrations_offline() -> None:
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    url = get_url()
    connectable = create_engine(url, poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
