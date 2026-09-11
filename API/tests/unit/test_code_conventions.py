"""Tests de arquitectura: hacen cumplir las reglas de ``CONVENCIONES.md`` (§ 11.2).

Recorren todos los ``.py`` de ``API/src/`` y los analizan con ``ast`` —nunca con
expresiones regulares sobre el texto: una regex confunde ``item.findtext(...)``
con el ``text(...)`` de SQLAlchemy y no distingue un import de un comentario que
lo menciona—. Son cinco reglas:

1. ``sql-outside-repository``: ningún SQL fuera de una clase ``*Repository`` (§ 4).
2. ``private-method``: una clase solo tiene métodos ``_x`` si son ganchos (§ 5.1).
3. ``module-internals-import``: no se entra en los ``services``/``repositories``
   de otro módulo (§ 3.3).
4. ``private-name-import``: un ``_nombre`` no sale de su fichero (§ 5.4, § 6.2).
5. ``module-direction``: un módulo no importa a otro de rango mayor (§ 3.4).

El código de hoy no las cumple todas, así que las violaciones existentes viven
en ``KNOWN_VIOLATIONS``, una lista que solo encoge: el test falla si aparece una
violación nueva **y** si una de la lista deja de existir (hay que borrarla, igual
que un ``xfail(strict=True)`` que pasa a XPASS).

Cada violación se identifica por ``(regla, ruta relativa a API/, símbolo)``. El
símbolo es la función o ``Clase.método`` donde aparece (``<module>`` si está a
nivel de fichero); en las reglas de imports (3, 4 y 5) es el nombre importado,
para que dos imports distintos del mismo fichero no se confundan. Nunca es un
número de línea, así que la lista no se rompe al editar el fichero.
"""

import ast
import textwrap
from dataclasses import dataclass, field
from functools import cached_property, lru_cache
from pathlib import Path
from typing import Iterator, Optional

import pytest

pytestmark = pytest.mark.unit

_API_ROOT = Path(__file__).resolve().parents[2]
_SRC_ROOT = _API_ROOT / "src"

RULE_SQL = "sql-outside-repository"
RULE_PRIVATE_METHOD = "private-method"
RULE_MODULE_INTERNALS = "module-internals-import"
RULE_PRIVATE_IMPORT = "private-name-import"
RULE_DIRECTION = "module-direction"

ALL_RULES = (RULE_SQL, RULE_PRIVATE_METHOD, RULE_MODULE_INTERNALS, RULE_PRIVATE_IMPORT, RULE_DIRECTION)

_RULE_SECTIONS = {
    RULE_SQL: "§ 4 (Repositorios)",
    RULE_PRIVATE_METHOD: "§ 5.1 (Managers: la regla)",
    RULE_MODULE_INTERNALS: "§ 3.3 (La frontera entre módulos)",
    RULE_PRIVATE_IMPORT: "§ 5.4 y § 6.2 (La escalera)",
    RULE_DIRECTION: "§ 3.4 (La dirección entre módulos)",
}

#: Métodos de una sesión de SQLAlchemy que ejecutan o preparan SQL.
_SESSION_METHODS = frozenset({"query", "execute", "add", "add_all", "delete", "merge", "flush", "get"})
#: Constructores de sentencias de SQLAlchemy; solo cuentan si se importaron de ``sqlalchemy``.
_SQLALCHEMY_STATEMENTS = frozenset({"select", "update", "delete", "insert", "text"})
#: Segmentos de ruta que marcan las tripas de un módulo (§ 3.3).
_MODULE_INTERNALS = frozenset({"services", "repositories"})
#: Rango de cada módulo (§ 3.4): se importa hacia rangos iguales o menores.
_MODULE_RANKS = {"shared": 0, "infrastructure": 0, "system": 1, "tools": 1, "users": 2, "accounts": 2, "features": 3}

#: Dependencias hacia un rango mayor autorizadas por el convenio: (fichero, módulo destino).
_AUTHORIZED_DIRECTION_EXCEPTIONS = {
    # CR.THEMIS_SCANNERS se deriva de ScanType a propósito (CLAUDE.md § Configuración).
    ("src/modules/system/config_reading.py", "features.themis"),
}

#: Métodos privados que sobrescriben un método de una librería externa; el grafo de
#: herencia de ``src/`` no los ve. Clave: (ruta, ``Clase._método``); valor: la librería.
EXTERNAL_HOOKS: dict[tuple[str, str], str] = {
    ("src/modules/shared/schemas.py", "UTCDateTime._serialize"): "marshmallow (fields.Field)",
    ("src/modules/system/taskqueue/worker.py", "_ThreadSafeWorker._install_signal_handlers"): "rq (SimpleWorker)",
}

_PLAN_SQL = "pendiente de mover la consulta a un repositorio del módulo (§ 4)"
_PLAN_PRIVATE_METHOD = "pendiente de sacar a función de módulo (§ 5.1)"
_PLAN_MODULE_INTERNALS = "pendiente de exportarlo en el __init__.py del módulo dueño (§ 3.3)"
_PLAN_PRIVATE_IMPORT = "pendiente de subir a un servicio o a shared/ (§ 6.2)"
_PLAN_DIRECTION = "pendiente de invertir la dependencia con un registro (§ 3.4)"

#: Violaciones existentes. Generada ejecutando el detector sobre el código; solo encoge.
KNOWN_VIOLATIONS: dict[tuple[str, str, str], str] = {
    # --- sql-outside-repository
    ("sql-outside-repository", "src/modules/accounts/managers/invitations.py", "InvitationManager._invite_existing_account"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/accounts/managers/invitations.py", "InvitationManager._invite_new_account"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/accounts/managers/invitations.py", "InvitationManager.accept"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/accounts/managers/organizations.py", "OrganizationManager.create"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/accounts/managers/organizations.py", "OrganizationManager.rename"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/accounts/managers/plans.py", "PlanManager.create_plan"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/accounts/managers/plans.py", "PlanManager.delete_plan"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/accounts/managers/plans.py", "PlanManager.replace_limits"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/accounts/managers/plans.py", "PlanManager.set_default_plan"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/accounts/managers/subscriptions.py", "SubscriptionManager.activate"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/accounts/services/limits.py", "_count_acheron_items"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/accounts/services/limits.py", "_count_acheron_vaults"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/accounts/services/limits.py", "_count_aegis_recipients"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/accounts/services/limits.py", "_count_hygeia_assets"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/accounts/services/limits.py", "_count_iris_mailbox_connections"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/accounts/services/limits.py", "_count_organization_members"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/accounts/services/limits.py", "_count_themis_scheduled"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/accounts/services/notices.py", "_notify"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/accounts/services/notices.py", "send_subscription_notices"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/accounts/services/quotas.py", "QuotaManager._consume_counter"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/accounts/services/quotas.py", "QuotaManager._ensure_counter_row"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/accounts/services/quotas.py", "QuotaManager._read_counter"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/accounts/services/quotas.py", "QuotaManager.refund"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/features/acheron/managers.py", "VaultManager.upsert_vault_from_json"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/features/iris/managers/analysis.py", "IrisManager._claim_ai_summary"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/features/iris/managers/analysis.py", "IrisManager.cancel_analysis"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/features/iris/managers/mailbox.py", "IrisMailboxManager._enqueue_pending"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/users/services/account_deletion.py", "_delete_by_user"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/users/services/account_deletion.py", "_purge_accounts"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/users/services/account_deletion.py", "_purge_aegis"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/users/services/account_deletion.py", "_purge_hygeia"):
        _PLAN_SQL,
    ("sql-outside-repository", "src/modules/users/services/account_deletion.py", "purge_user_data"):
        _PLAN_SQL,
    # --- private-method
    ("private-method", "src/modules/accounts/managers/invitations.py", "InvitationManager._assert_not_in_an_organization"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/managers/invitations.py", "InvitationManager._assert_owner_can_grow"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/managers/invitations.py", "InvitationManager._available_username"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/managers/invitations.py", "InvitationManager._find_user_by_email"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/managers/invitations.py", "InvitationManager._invite_existing_account"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/managers/invitations.py", "InvitationManager._invite_new_account"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/managers/invitations.py", "InvitationManager._send_credentials_email"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/managers/invitations.py", "InvitationManager._send_invitation_email"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/managers/invitations.py", "InvitationManager._serialize"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/managers/organizations.py", "OrganizationManager._assert_can_own_organization"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/managers/organizations.py", "OrganizationManager._delete_membership"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/managers/organizations.py", "OrganizationManager._serialize"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/managers/organizations.py", "OrganizationManager._unique_slug"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/managers/plans.py", "PlanManager._flatten_limits"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/managers/plans.py", "PlanManager._group_limits_by_scope"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/managers/plans.py", "PlanManager._validated_limit"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/managers/subscriptions.py", "SubscriptionManager._apply_external"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/managers/subscriptions.py", "SubscriptionManager._is_stale"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/managers/subscriptions.py", "SubscriptionManager._require"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/managers/subscriptions.py", "SubscriptionManager._serialize"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/managers/subscriptions.py", "SubscriptionManager._transition"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/services/quotas.py", "QuotaManager._assert_email_verified"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/services/quotas.py", "QuotaManager._consume_counter"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/services/quotas.py", "QuotaManager._consume_stock"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/services/quotas.py", "QuotaManager._count_stock"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/services/quotas.py", "QuotaManager._current_usage"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/services/quotas.py", "QuotaManager._ensure_counter_row"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/services/quotas.py", "QuotaManager._holder_user_ids"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/services/quotas.py", "QuotaManager._read_counter"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/accounts/services/scheduling.py", "AccountsScheduler._run_notices"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/acheron/managers.py", "VaultManager._bump_revision"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/acheron/managers.py", "VaultManager._ensure_vault_ownership"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/acheron/managers.py", "VaultManager._parse_dt"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/acheron/managers.py", "VaultManager._require_revision"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/managers/campaigns.py", "CampaignManager._assert_campaign_ownership"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/managers/campaigns.py", "CampaignManager._assert_list_ownership"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/managers/campaigns.py", "CampaignManager._public_white_label"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/managers/campaigns.py", "CampaignManager._run_campaign_send"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/managers/org_profile.py", "AegisOrgProfileManager._assert_white_label_allowed"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/managers/org_profile.py", "AegisOrgProfileManager._hygeia_inventory_available"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/managers/pills.py", "AegisManager._create_pending_document_and_dispatch"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/managers/pills.py", "AegisManager._get_topic_from_db"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/managers/pills.py", "AegisManager._load_reference_stack"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/managers/pills.py", "AegisManager._persist_alerts_atomic"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/managers/pills.py", "AegisManager._persist_content_atomic"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/managers/pills.py", "AegisManager._read_cfg"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/managers/pills.py", "AegisManager._resolve_tracked_products"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/managers/pills.py", "AegisManager._rewrite_archive_file"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/managers/pills.py", "AegisManager._run_generation_workflow"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/managers/pills.py", "AegisManager._update_document_status"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/exporters.py", "AegisExporter._format_datetime"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/exporters.py", "AegisExporter._sanitize"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/exporters.py", "AegisExporter._validate_configuration"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/exporters.py", "HTMLExporter._esc"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/exporters.py", "HTMLExporter._generate_content"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/exporters.py", "HTMLExporter._html_alerts"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/exporters.py", "HTMLExporter._html_body"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/exporters.py", "HTMLExporter._html_closing"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/exporters.py", "HTMLExporter._html_footer"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/exporters.py", "HTMLExporter._html_header"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/exporters.py", "HTMLExporter._html_intro"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/exporters.py", "HTMLExporter._html_tips"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/exporters.py", "HTMLExporter._safe_url"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/exporters.py", "JsonExporter._to_dict"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/exporters.py", "MarkdownExporter._alerts"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/exporters.py", "MarkdownExporter._closing"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/exporters.py", "MarkdownExporter._footer"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/exporters.py", "MarkdownExporter._frontmatter"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/exporters.py", "MarkdownExporter._generate_content"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/exporters.py", "MarkdownExporter._header"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/exporters.py", "MarkdownExporter._intro"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/exporters.py", "MarkdownExporter._tips"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/pills.py", "AegisAIWriter._build_intro_context"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/pills.py", "AegisAIWriter._build_replacements"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/pills.py", "AegisAIWriter._build_system_prompt"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/pills.py", "AegisAIWriter._build_user_prompt"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/pills.py", "AegisAIWriter._format_advisories"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/pills.py", "AegisAlertFetcher._describe_advisory"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/pills.py", "AegisAlertFetcher._fetch_incibe"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/pills.py", "AegisAlertFetcher._fetch_kb_advisories"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/pills.py", "AegisAlertFetcher._get_cached"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/pills.py", "AegisAlertFetcher._is_recent"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/pills.py", "AegisAlertFetcher._set_cached"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/aegis/services/pills.py", "AegisContent._checksum"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/hygeia/managers.py", "HygeiaAlertManager._get_owned_anomaly"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/hygeia/managers.py", "HygeiaAssetManager._current_power_reading"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/hygeia/managers.py", "HygeiaAssetManager._power_window"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/hygeia/managers.py", "HygeiaAssetManager._power_window_samples"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/hygeia/managers.py", "HygeiaAssetManager._summarize_window"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/hygeia/managers.py", "HygeiaIngestManager._enforce_min_interval"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/hygeia/managers.py", "HygeiaIngestManager._evaluate_thresholds"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/hygeia/managers.py", "HygeiaNotifyManager._run_notify"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/hygeia/managers.py", "HygeiaReportManager._organization_scope"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/hygeia/services/scheduling.py", "HygeiaScheduler._run_presence_check"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/hygeia/services/scheduling.py", "HygeiaScheduler._run_retention"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/analysis.py", "IrisManager._aggregate_score"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/analysis.py", "IrisManager._apply_verdict_gates"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/analysis.py", "IrisManager._claim_ai_summary"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/analysis.py", "IrisManager._determine_verdict"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/analysis.py", "IrisManager._enqueue_phishing_notification"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/analysis.py", "IrisManager._evaluate_contexts"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/analysis.py", "IrisManager._evaluate_gates"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/analysis.py", "IrisManager._extract_verdict_signals"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/analysis.py", "IrisManager._fail_analysis"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/analysis.py", "IrisManager._persist_analysis_results"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/analysis.py", "IrisManager._refund_ai_summary_quota"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/analysis.py", "IrisManager._release_ai_summary"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/analysis.py", "IrisManager._run_analysis"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/analysis.py", "IrisManager._top_signals"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/analysis.py", "IrisManager._update_analysis"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/analysis.py", "IrisManager._validate_headers_parsed"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/analysis.py", "IrisManager._validate_headers_pre"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/mailbox.py", "IrisMailboxManager._clear_sync_started"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/mailbox.py", "IrisMailboxManager._consume_state"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/mailbox.py", "IrisMailboxManager._current_daily_counter"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/mailbox.py", "IrisMailboxManager._drain_pending"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/mailbox.py", "IrisMailboxManager._enqueue_pending"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/mailbox.py", "IrisMailboxManager._ensure_access_token"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/mailbox.py", "IrisMailboxManager._finish_sync"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/mailbox.py", "IrisMailboxManager._ingest_message"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/mailbox.py", "IrisMailboxManager._mark_reauth_required"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/mailbox.py", "IrisMailboxManager._mark_sync_started"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/mailbox.py", "IrisMailboxManager._record_sync_error"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/mailbox.py", "IrisMailboxManager._redirect_uri"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/mailbox.py", "IrisMailboxManager._resolve_inbox_entry"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/mailbox.py", "IrisMailboxManager._retry_or_deadletter"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/mailbox.py", "IrisMailboxManager._sign_state"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/mailbox.py", "IrisMailboxManager._state_serializer"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/mailbox.py", "IrisMailboxManager._sync_connection"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/mailbox.py", "IrisMailboxManager._validate_folder"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/mailbox.py", "IrisMailboxManager._verify_state"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/notifications.py", "IrisDigestNotifyManager._run_notify"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/notifications.py", "IrisPhishingNotifyManager._run_notify"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/notifications.py", "IrisReauthNotifyManager._run_notify"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/notifications.py", "IrisStuckSyncNotifyManager._run_notify"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/reports.py", "IrisReportManager._create_document"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/managers/reports.py", "IrisReportManager._generate_pdf_async"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/services/ai_writer.py", "IrisAIWriter._build_prompts"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/services/ai_writer.py", "IrisAIWriter._build_user_prompt"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/services/ai_writer.py", "IrisAIWriter._degradation_note"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/services/ai_writer.py", "IrisAIWriter._parse_response"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/services/ai_writer.py", "IrisAIWriter._try_parse"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/services/mailbox/gmail.py", "GmailConnector._get_account_email"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/services/mailbox/gmail.py", "GmailConnector._token_set_from"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/services/mailbox/microsoft.py", "GraphConnector._get_account_email"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/services/mailbox/microsoft.py", "GraphConnector._token_set_from"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/services/mailbox/scheduling.py", "IrisMailboxScheduler._poll_connections"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/services/mailbox/scheduling.py", "IrisMailboxScheduler._run_notifications"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/services/mailbox/scheduling.py", "IrisMailboxScheduler._run_retention"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/services/reports.py", "IrisPDFCreator._on_page"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/services/reports.py", "IrisPDFCreator._output_path"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/iris/services/reports.py", "IrisPDFCreator._set_pdf_metadata"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "CheckRuntime._applies"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "CheckRuntime._applies_mode"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "CheckRuntime._applies_network"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "CheckRuntime._applies_script"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "CheckRuntime._applies_tls"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "CheckRuntime._finding"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "CheckRuntime._payload_combinations"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "CheckRuntime._probe_handshake"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "CheckRuntime._probe_response"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "CheckRuntime._run_check"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "CheckRuntime._run_for_service"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "CheckRuntime._run_network_check"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "CheckRuntime._run_request_sequence"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "CheckRuntime._run_script_check"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "CheckRuntime._run_tls_check"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "HttpProbe._request"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "HttpProbe._scheme_for"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "HttpProbe._to_response"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "Matcher._part_text"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "Matcher._raw_match"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "NetworkSession._fill"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "NetworkSession._read_block"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "NetworkSession._read_line"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/checks.py", "NetworkSession._read_resp_bulk"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/credentials.py", "CredentialRuntime._finding"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/credentials.py", "CredentialRuntime._try_entry"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/engine.py", "LybraEngine._informational_finding"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/engine.py", "LybraEngine._version_finding"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/engine.py", "LybraEngine._version_findings"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/engine.py", "LybraEngine._version_label"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/fingerprinting/postgres.py", "PostgresProbe._exchange"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/fingerprinting/smb.py", "SmbProbe._exchange"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/fingerprinting/tls.py", "TlsProbe._parse_cert"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/transport.py", "AsyncConnectScanner._is_open"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/lybra/transport.py", "AsyncConnectScanner._probe_outcome"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/authorized_target.py", "AuthorizedTargetManager._normalize"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/kb_sync.py", "KbSyncManager._flush_cves"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/kb_sync.py", "KbSyncManager._record"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/kb_sync.py", "KbSyncManager._sync_source"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/lybra/engine.py", "LybraEngineManager._changed_surface_title"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/lybra/engine.py", "LybraEngineManager._detect_surface_changes"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/lybra/engine.py", "LybraEngineManager._discover_ports"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/lybra/engine.py", "LybraEngineManager._discover_udp_ports"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/lybra/engine.py", "LybraEngineManager._finding_counters"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/lybra/engine.py", "LybraEngineManager._finding_view_dict"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/lybra/engine.py", "LybraEngineManager._fingerprint_finding"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/lybra/engine.py", "LybraEngineManager._fingerprint_services"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/lybra/engine.py", "LybraEngineManager._group_to_json"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/lybra/engine.py", "LybraEngineManager._in_host_pool"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/lybra/engine.py", "LybraEngineManager._ingested_checks"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/lybra/engine.py", "LybraEngineManager._layer_findings"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/lybra/engine.py", "LybraEngineManager._new_surface_title"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/lybra/engine.py", "LybraEngineManager._rehydrate_services"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/lybra/engine.py", "LybraEngineManager._remaining_budget"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/lybra/engine.py", "LybraEngineManager._run_active_checks"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/lybra/engine.py", "LybraEngineManager._run_credential_checks"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/lybra/engine.py", "LybraEngineManager._run_lybra"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/lybra/engine.py", "LybraEngineManager._surface_finding"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/lybra/engine.py", "LybraEngineManager._surface_key"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/lybra/sources.py", "ServiceSource._resolve_host"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/programed.py", "ProgramedScanManager._assert_valid_arguments"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/programed.py", "ProgramedScanManager._assert_valid_scheduling_config"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/reports.py", "ThemisReportManager._create_document"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/reports.py", "ThemisReportManager._generate_pdf_async"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/scan.py", "ScanManager._append_document_info"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/scan.py", "ScanManager._build_scan"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/scan.py", "ScanManager._create_scan_and_dispatch"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/scan.py", "ScanManager._log_to_csv"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/scan.py", "ScanManager._previous_findings_map"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/scan_folder.py", "ScanFolderManager._assert_folder_ownership"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/scan_folder.py", "ScanFolderManager._assert_scan_ownership"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/scan_folder.py", "ScanFolderManager._format_scan"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/scan_folder.py", "ScanFolderManager._validate_name"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/traceroute.py", "TracerouteManager._enqueue"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/traceroute.py", "TracerouteManager._format"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/traceroute.py", "TracerouteManager._get_fresh_cached"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/traceroute.py", "TracerouteManager._pending"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/traceroute.py", "TracerouteManager._probe_host"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/managers/traceroute.py", "TracerouteManager._trace_key"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/analyzers.py", "LybraAIWriter._build_service_rollup"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/analyzers.py", "LybraAIWriter._build_system_prompt"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/analyzers.py", "LybraAIWriter._build_user_prompt"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/analyzers.py", "LybraAIWriter._sort_key"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/analyzers.py", "LybraAIWriter._validate"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/analyzers.py", "NiktoAIWriter._assess_control_severity"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/analyzers.py", "NiktoAIWriter._build_system_prompt"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/analyzers.py", "NiktoAIWriter._build_user_prompt"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/analyzers.py", "NiktoAIWriter._preprocess_incidents"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/analyzers.py", "NiktoAIWriter._severity_rank"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/analyzers.py", "NiktoAIWriter._validate"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/analyzers.py", "NmapAIWriter._analyze_port_patterns"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/analyzers.py", "NmapAIWriter._build_system_prompt"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/analyzers.py", "NmapAIWriter._build_user_prompt"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/analyzers.py", "NmapAIWriter._classify_network_context"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/analyzers.py", "NmapAIWriter._infer_functional_category"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/analyzers.py", "NmapAIWriter._validate"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/csv_logger.py", "BaseScanLogger._ensure_header"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/csv_logger.py", "BaseScanLogger._get_file_path"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/csv_logger.py", "BaseScanLogger._infer_ssl"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/csv_logger.py", "BaseScanLogger._parse_ports_count"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/history.py", "HistoryStatsService._compute_diff"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/history.py", "HistoryStatsService._nice_step"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/processors.py", "NiktoResultProcessor._classify_threat_level"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/processors.py", "NiktoResultProcessor._extract_nikto_items"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/processors.py", "NiktoResultProcessor._parse_nikto_xml"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/processors.py", "NmapResultProcessor._parse_nmap_structure"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/processors.py", "NmapResultProcessor._parse_nmap_xml"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/processors.py", "NucleiResultProcessor._parse_nuclei_jsonl"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/reports/base.py", "PrintingStrategy._append_ai_analysis"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/reports/base.py", "PrintingStrategy._append_history_stats"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/reports/creator.py", "PDFCreator._make_logo_badge"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/reports/creator.py", "PDFCreator._on_page"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/reports/creator.py", "PDFCreator._set_pdf_metadata"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/reports/findings.py", "FindingsPrintingStrategy._append_cpe_coverage_note"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/reports/findings.py", "FindingsPrintingStrategy._append_finding_card"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/reports/findings.py", "FindingsPrintingStrategy._append_finding_header"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/reports/findings.py", "FindingsPrintingStrategy._append_finding_summary"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/reports/findings.py", "FindingsPrintingStrategy._append_findings_section"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/reports/findings.py", "FindingsPrintingStrategy._append_group_header"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/reports/findings.py", "FindingsPrintingStrategy._append_group_index"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/reports/findings.py", "FindingsPrintingStrategy._append_grouped_findings"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/reports/findings.py", "FindingsPrintingStrategy._knowledge_base_line"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/reports/findings.py", "FindingsPrintingStrategy._outline_key"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/reports/findings.py", "FindingsPrintingStrategy._sorted_findings"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/reports/findings.py", "FindingsPrintingStrategy._split_into_sections"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/reports/nikto.py", "NiktoPrintingStrategy._append_nikto_header"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/reports/nikto.py", "NiktoPrintingStrategy._append_nikto_incident_card"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/reports/nikto.py", "NiktoPrintingStrategy._append_nikto_severity_summary"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/scheduling.py", "ThemisScheduler._build_job_id"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/scheduling.py", "ThemisScheduler._build_trigger"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/scheduling.py", "ThemisScheduler._job_next_run"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/scheduling.py", "ThemisScheduler._load_and_guard"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/scheduling.py", "ThemisScheduler._record_run"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/scheduling.py", "ThemisScheduler._run_scheduled_scan"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/scheduling.py", "ThemisScheduler._schedule_kb_sync"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/scheduling.py", "ThemisScheduler._sync_from_db"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/tasks.py", "_Task._parse_progress"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/tasks.py", "_Task._read_output"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/tasks.py", "_Task._terminate_proc"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/traceroute.py", "TracerouteService._build_command"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/traceroute.py", "TracerouteService._extract_host_ip"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/traceroute.py", "TracerouteService._extract_rtt"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/features/themis/services/traceroute.py", "TracerouteService._parse"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/infrastructure/document_repository.py", "DocumentRepository._ordered"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/infrastructure/document_repository.py", "DocumentRepository._parent_column"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/shared/_exceptions.py", "EllysiaException._capture_traceback"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/shared/_exceptions.py", "EllysiaException._generate_user_message"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/system/taskqueue/connection.py", "RedisConnectionFactory._kwargs"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/system/taskqueue/queue.py", "TaskQueue._count_alive_workers"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/system/taskqueue/queue.py", "TaskQueue._force_cancel_started"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/system/taskqueue/queue.py", "TaskQueue._jobs_to_tasks"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/system/taskqueue/queue.py", "TaskQueue._queue_for"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/system/taskqueue/queue.py", "TaskQueue._reset_instance"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/system/taskqueue/queue.py", "TaskQueue._try_fetch_job"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/system/taskqueue/queue.py", "TaskQueue._worker_alive"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/system/taskqueue/scheduling.py", "TaskDispatchScheduler._sweep"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/system/taskqueue/stores.py", "HistoryStore._migrate_legacy"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/system/taskqueue/stores.py", "HistoryStore._trim"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/system/taskqueue/task.py", "Task._rq_status_to_task_status"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/tools/herald/strategies.py", "SmtpStrategy._build_mime"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/tools/scribe/generator.py", "AIGenerator._check_breaker"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/tools/scribe/generator.py", "AIGenerator._check_payload_size"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/tools/scribe/generator.py", "AIGenerator._record_failure"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/tools/scribe/generator.py", "AIGenerator._record_success"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/tools/scribe/strategies.py", "GoogleStrategy._build_tool_declarations"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/tools/scribe/strategies.py", "GoogleStrategy._contents_from_messages"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/tools/scribe/strategies.py", "OllamaStrategy._options"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/tools/scribe/strategies.py", "OpenAIStrategy._create"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/users/managers.py", "UserManager._get_role_rank"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/users/managers.py", "UserManager._mint_and_send_password_reset"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/users/managers.py", "UserManager._owns_the_organization_of"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/users/managers.py", "UserManager._send_password_reset_email"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/users/managers.py", "UserManager._send_verification_email"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/users/repositories.py", "TokenRepository._delete_expired"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/users/repositories.py", "TokenRepository._get_token"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/users/repositories.py", "TokenRepository._revoke_all"):
        _PLAN_PRIVATE_METHOD,
    ("private-method", "src/modules/users/services/scheduling.py", "UsersScheduler._run_mfa_reminders"):
        _PLAN_PRIVATE_METHOD,
    # --- module-internals-import
    ("module-internals-import", "src/modules/accounts/endpoints.py", "src.modules.users.services.permissions.Role"):
        _PLAN_MODULE_INTERNALS,
    ("module-internals-import", "src/modules/accounts/managers/invitations.py", "src.modules.users.repositories.UserRepository"):
        _PLAN_MODULE_INTERNALS,
    ("module-internals-import", "src/modules/accounts/managers/invitations.py", "src.modules.users.services.secrets.generate_opaque_token"):
        _PLAN_MODULE_INTERNALS,
    ("module-internals-import", "src/modules/accounts/managers/invitations.py", "src.modules.users.services.secrets.hash_opaque_token"):
        _PLAN_MODULE_INTERNALS,
    ("module-internals-import", "src/modules/features/aegis/managers/org_profile.py", "src.modules.accounts.services.entitlements.resolve_entitlement"):
        _PLAN_MODULE_INTERNALS,
    ("module-internals-import", "src/modules/features/hygeia/services/enrollment.py", "src.modules.users.services.secrets.hash_password"):
        _PLAN_MODULE_INTERNALS,
    ("module-internals-import", "src/modules/features/hygeia/services/enrollment.py", "src.modules.users.services.secrets.verify_password"):
        _PLAN_MODULE_INTERNALS,
    ("module-internals-import", "src/modules/system/endpoints.py", "src.modules.users.services.permissions.Role"):
        _PLAN_MODULE_INTERNALS,
    ("module-internals-import", "src/modules/users/managers.py", "src.modules.accounts.repositories.OrganizationMemberRepository"):
        _PLAN_MODULE_INTERNALS,
    ("module-internals-import", "src/modules/users/managers.py", "src.modules.accounts.repositories.OrganizationRepository"):
        _PLAN_MODULE_INTERNALS,
    # --- private-name-import
    ("private-name-import", "src/modules/features/iris/services/rules/received_timing_rules.py", "src.modules.features.iris.services.parsers._hop_timestamp"):
        _PLAN_PRIVATE_IMPORT,
    ("private-name-import", "src/modules/features/iris/services/rules/received_timing_rules.py", "src.modules.features.iris.services.parsers._is_private_ip"):
        _PLAN_PRIVATE_IMPORT,
    ("private-name-import", "src/modules/features/themis/managers/lybra/engine.py", "src.modules.features.themis.services._Task"):
        _PLAN_PRIVATE_IMPORT,
    ("private-name-import", "src/modules/features/themis/managers/nikto.py", "src.modules.features.themis.services._Task"):
        _PLAN_PRIVATE_IMPORT,
    ("private-name-import", "src/modules/features/themis/managers/nmap.py", "src.modules.features.themis.services._Task"):
        _PLAN_PRIVATE_IMPORT,
    ("private-name-import", "src/modules/features/themis/managers/nuclei.py", "src.modules.features.themis.services._Task"):
        _PLAN_PRIVATE_IMPORT,
    ("private-name-import", "src/modules/features/themis/managers/scan.py", "src.modules.features.themis.services._Task"):
        _PLAN_PRIVATE_IMPORT,
    ("private-name-import", "src/modules/features/themis/services/__init__.py", "src.modules.features.themis.services.tasks._Task"):
        _PLAN_PRIVATE_IMPORT,
    ("private-name-import", "src/modules/system/taskqueue/worker.py", "src.modules.system.taskqueue.deadline._UnswallowableTimerDeathPenalty"):
        _PLAN_PRIVATE_IMPORT,
    # --- module-direction
    ("module-direction", "src/modules/accounts/services/limits.py", "src.modules.features.acheron.model.Storable"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/accounts/services/limits.py", "src.modules.features.acheron.model.Vault"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/accounts/services/limits.py", "src.modules.features.aegis.model.DistributionList"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/accounts/services/limits.py", "src.modules.features.aegis.model.Recipient"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/accounts/services/limits.py", "src.modules.features.hygeia.model.MonitoredAsset"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/accounts/services/limits.py", "src.modules.features.iris.model.IrisMailboxConnection"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/accounts/services/limits.py", "src.modules.features.themis.model.ProgramedScan"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/infrastructure/engine.py", "src.modules.system.config_reading"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/shared/_crypto.py", "src.modules.system.config_reading"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/shared/_documents.py", "src.modules.system.taskqueue.TaskTrackingMixin"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/shared/_endpoints.py", "src.modules.system.config_reading"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/system/endpoints.py", "src.modules.users.require_oauth_token"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/system/endpoints.py", "src.modules.users.require_role"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/system/endpoints.py", "src.modules.users.services.permissions.Role"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/users/__init__.py", "src.modules.features.acheron.model.Vault"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/users/services/account_deletion.py", "src.modules.features.aegis.model.AegisOrgProfile"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/users/services/account_deletion.py", "src.modules.features.aegis.model.Campaign"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/users/services/account_deletion.py", "src.modules.features.aegis.model.CampaignAnswer"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/users/services/account_deletion.py", "src.modules.features.aegis.model.CampaignRecipient"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/users/services/account_deletion.py", "src.modules.features.aegis.model.DistributionList"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/users/services/account_deletion.py", "src.modules.features.aegis.model.Recipient"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/users/services/account_deletion.py", "src.modules.features.hygeia.model.Anomaly"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/users/services/account_deletion.py", "src.modules.features.hygeia.model.AssetSnapshot"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/users/services/account_deletion.py", "src.modules.features.hygeia.model.MonitoredAsset"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/users/services/account_deletion.py", "src.modules.features.iris.model.IrisMailboxConnection"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/users/services/account_deletion.py", "src.modules.features.themis.model.AuthorizedTarget"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/users/services/account_deletion.py", "src.modules.features.themis.model.ProgramedScan"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/users/services/account_deletion.py", "src.modules.features.themis.model.ScanFolder"):
        _PLAN_DIRECTION,
    ("module-direction", "src/modules/users/services/account_deletion.py", "src.modules.features.themis.model.Traceroute"):
        _PLAN_DIRECTION,
}


# ------------------------------------------------------------------ modelo


@dataclass(frozen=True)
class SourceFile:
    """Un fichero de ``src/`` ya analizado.

    Attributes:
        path: Ruta relativa a ``API/`` con ``/`` como separador
            (``src/modules/features/iris/managers/analysis.py``).
        tree: Árbol ``ast`` del fichero.
    """

    path: str
    tree: ast.Module = field(compare=False)

    @cached_property
    def dotted(self) -> str:
        """Nombre de módulo Python (``src.modules.features.iris.managers.analysis``).

        Un ``__init__.py`` toma el nombre de su paquete.
        """
        parts = self.path.removesuffix(".py").split("/")
        if parts[-1] == "__init__":
            parts.pop()
        return ".".join(parts)

    @cached_property
    def package(self) -> str:
        """Paquete contra el que se resuelven los imports relativos del fichero."""
        return self.dotted if self.path.endswith("/__init__.py") else self.dotted.rpartition(".")[0]

    @cached_property
    def owner(self) -> Optional[str]:
        """Módulo del convenio al que pertenece el fichero; ver ``owner_module_of``."""
        return owner_module_of(self.dotted)


def owner_module_of(dotted: str) -> Optional[str]:
    """Deduce el módulo del convenio al que pertenece un nombre de módulo Python.

    Sigue la tabla de § 11.2: ``src.modules.features.<n>`` → ``features.<n>``,
    ``src.modules.tools.<n>`` → ``tools.<n>`` y ``src.modules.<n>`` → ``<n>``.

    Args:
        dotted: Nombre absoluto con puntos, de módulo o de un nombre dentro de él
            (``src.modules.users.services.secrets.hash_password``).

    Returns:
        Optional[str]: El módulo (``users``, ``features.iris``…), o ``None`` si
            el nombre no está bajo ``src.modules`` (una librería externa).
    """
    parts = dotted.split(".")
    if parts[:2] != ["src", "modules"] or len(parts) < 3:
        return None
    if parts[2] in ("features", "tools") and len(parts) > 3:
        return f"{parts[2]}.{parts[3]}"
    return parts[2]


def rank_of(owner: str) -> Optional[int]:
    """Rango de un módulo en la dirección de dependencias (§ 3.4).

    Args:
        owner: Módulo devuelto por ``owner_module_of``.

    Returns:
        Optional[int]: De ``0`` (``shared``, ``infrastructure``) a ``3``
            (``features.*``), o ``None`` si el módulo no figura en la tabla.
    """
    return _MODULE_RANKS.get(owner.split(".")[0])


def parse_source(path: str, code: str) -> SourceFile:
    """Construye un ``SourceFile`` a partir de código escrito como cadena.

    Args:
        path: Ruta ficticia relativa a ``API/``; decide el módulo y los imports relativos.
        code: Código fuente; se le quita la sangría común.

    Returns:
        SourceFile: El fichero analizado.
    """
    return SourceFile(path, ast.parse(textwrap.dedent(code)))


@lru_cache(maxsize=1)
def load_source_files() -> tuple[SourceFile, ...]:
    """Analiza todos los ``.py`` de ``API/src/``; se cachea para toda la sesión de tests.

    Returns:
        tuple[SourceFile, ...]: Los ficheros, ordenados por ruta.
    """
    return tuple(
        SourceFile(path.relative_to(_API_ROOT).as_posix(), ast.parse(path.read_text(encoding="utf-8")))
        for path in sorted(_SRC_ROOT.rglob("*.py"))
    )


# ------------------------------------------------------------------ recorridos


def iter_scoped_nodes(node: ast.AST, scope: tuple = ()) -> Iterator[tuple[ast.AST, tuple]]:
    """Recorre un árbol entregando cada nodo junto a las funciones y clases que lo contienen.

    Args:
        node: Raíz del recorrido.
        scope: Cadena de ``FunctionDef``/``AsyncFunctionDef``/``ClassDef`` que envuelve
            a ``node``. Por defecto vacía (nivel de fichero).

    Yields:
        tuple[ast.AST, tuple]: Cada nodo descendiente y su cadena de contenedores.
    """
    for child in ast.iter_child_nodes(node):
        yield child, scope
        is_container = isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        yield from iter_scoped_nodes(child, scope + (child,) if is_container else scope)


def render_symbol(scope: tuple) -> str:
    """Nombre del símbolo que forma una cadena de contenedores (``Clase.método``).

    Args:
        scope: Cadena devuelta por ``iter_scoped_nodes``.

    Returns:
        str: Los nombres unidos por puntos, o ``<module>`` si la cadena está vacía.
    """
    return ".".join(container.name for container in scope) or "<module>"


def resolve_import_from(source: SourceFile, node: ast.ImportFrom) -> str:
    """Convierte el módulo de un ``from X import ...`` en su nombre absoluto.

    Args:
        source: Fichero donde está el import.
        node: El nodo del import, relativo (``from ..x``) o absoluto.

    Returns:
        str: El módulo absoluto (``src.modules.features.iris.services.scoring``).
    """
    if node.level == 0:
        return node.module or ""
    base = source.package.split(".")
    base = base[: len(base) - node.level + 1]
    return ".".join(base + ([node.module] if node.module else []))


def iter_import_targets(source: SourceFile) -> Iterator[tuple[str, str]]:
    """Recorre los imports de un fichero, incluidos los perezosos dentro de funciones.

    Args:
        source: Fichero a recorrer.

    Yields:
        tuple[str, str]: El destino absoluto de cada nombre importado
            (``import a.b`` → ``a.b``; ``from a import b`` → ``a.b``; ``from a import *`` → ``a``)
            y el nombre original importado (``b``; en ``import a.b``, ``a.b``).
    """
    for node in ast.walk(source.tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, alias.name
        elif isinstance(node, ast.ImportFrom):
            module = resolve_import_from(source, node)
            for alias in node.names:
                yield (module if alias.name == "*" else f"{module}.{alias.name}"), alias.name


def is_private_name(name: str) -> bool:
    """Indica si un nombre es privado: empieza por ``_`` y no es especial (``__x__``)."""
    return name.startswith("_") and not (name.startswith("__") and name.endswith("__"))


# ------------------------------------------------------------------ regla 1


def find_sql_outside_repository(source: SourceFile) -> set[tuple[str, str, str]]:
    """Regla 1: SQL ejecutado fuera de una clase ``*Repository`` (§ 4).

    Cuenta las llamadas a ``query``/``execute``/``add``/``add_all``/``delete``/``merge``/
    ``flush``/``get`` sobre un objeto llamado ``session`` o acabado en ``.session``, y las
    llamadas a ``select``/``update``/``delete``/``insert``/``text`` importadas de
    ``sqlalchemy`` en ese fichero. Quedan exentos ``src/modules/infrastructure/`` (es el
    propio mecanismo) y los ``model.py``, cuyo SQL declara el esquema —el ``where`` de
    un índice parcial— en vez de ejecutar consultas.

    Args:
        source: Fichero a revisar.

    Returns:
        set[tuple[str, str, str]]: Las violaciones; vacío si no hay ninguna.
    """
    if source.path.startswith("src/modules/infrastructure/") or source.path.endswith("/model.py"):
        return set()

    statement_names: set[str] = set()
    sqlalchemy_aliases: set[str] = set()
    for node in ast.walk(source.tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and (node.module or "").split(".")[0] == "sqlalchemy":
            statement_names |= {alias.asname or alias.name for alias in node.names if alias.name in _SQLALCHEMY_STATEMENTS}
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == "sqlalchemy":
                    sqlalchemy_aliases.add(alias.asname or "sqlalchemy")

    violations = set()
    for node, scope in iter_scoped_nodes(source.tree):
        if not isinstance(node, ast.Call):
            continue
        if any(isinstance(container, ast.ClassDef) and container.name.endswith("Repository") for container in scope):
            continue
        function = node.func
        is_sql = False
        if isinstance(function, ast.Name):
            is_sql = function.id in statement_names
        elif isinstance(function, ast.Attribute):
            receiver = ast.unparse(function.value)
            is_session_call = function.attr in _SESSION_METHODS and (receiver == "session" or receiver.endswith(".session"))
            is_sqlalchemy_call = function.attr in _SQLALCHEMY_STATEMENTS and receiver.split(".")[0] in sqlalchemy_aliases
            is_sql = is_session_call or is_sqlalchemy_call
        if is_sql:
            violations.add((RULE_SQL, source.path, render_symbol(scope)))
    return violations


# ------------------------------------------------------------------ regla 2


@dataclass
class _ClassGraph:
    """Grafo de herencia de las clases de un conjunto de ficheros.

    Attributes:
        class_nodes: Fichero y nodo ``ClassDef`` de cada clase, por ``(módulo, qualname)``.
        methods_by_class: Nombres de los métodos que declara cada clase.
        parents_by_class: Bases de cada clase resueltas dentro del conjunto.
        children_by_class: Relación inversa de ``parents_by_class``.
    """

    class_nodes: dict[tuple[str, str], tuple[SourceFile, ast.ClassDef]] = field(default_factory=dict)
    methods_by_class: dict[tuple[str, str], set[str]] = field(default_factory=dict)
    parents_by_class: dict[tuple[str, str], list[tuple[str, str]]] = field(default_factory=dict)
    children_by_class: dict[tuple[str, str], list[tuple[str, str]]] = field(default_factory=dict)

    def collect_related(self, key: tuple[str, str], edges: dict) -> set[tuple[str, str]]:
        """Clases alcanzables desde ``key`` siguiendo ``edges`` (ancestros o descendientes).

        Args:
            key: Clase de partida.
            edges: ``parents_by_class`` para ancestros o ``children_by_class`` para descendientes.

        Returns:
            set[tuple[str, str]]: Las clases alcanzadas, sin incluir ``key``.
        """
        related, pending = set(), list(edges.get(key, ()))
        while pending:
            current = pending.pop()
            if current not in related:
                related.add(current)
                pending.extend(edges.get(current, ()))
        return related


def _build_bindings(source: SourceFile) -> dict[str, tuple[str, Optional[str]]]:
    """Nombres locales que crean los imports de un fichero.

    Returns:
        dict: ``local → (módulo, nombre)`` para ``from módulo import nombre as local``,
            y ``local → (módulo, None)`` para ``import módulo as local``.
    """
    bindings: dict[str, tuple[str, Optional[str]]] = {}
    for node in ast.walk(source.tree):
        if isinstance(node, ast.ImportFrom):
            module = resolve_import_from(source, node)
            for alias in node.names:
                if alias.name != "*":
                    bindings[alias.asname or alias.name] = (module, alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    bindings[alias.asname] = (alias.name, None)
                else:
                    root = alias.name.split(".")[0]
                    bindings[root] = (root, None)
    return bindings


def build_class_graph(sources: tuple[SourceFile, ...]) -> _ClassGraph:
    """Construye el grafo de herencia resolviendo cada base por su nombre importado.

    Sigue las reexportaciones de los ``__init__.py`` (incluido ``import *``). Las bases
    que no se resuelven dentro de ``sources`` —librerías externas— se ignoran.

    Args:
        sources: Ficheros cuyas clases forman el grafo.

    Returns:
        _ClassGraph: El grafo.
    """
    files_by_module = {source.dotted: source for source in sources}
    bindings_by_module = {source.dotted: _build_bindings(source) for source in sources}
    star_modules_by_module = {
        source.dotted: [
            resolve_import_from(source, node)
            for node in ast.walk(source.tree)
            if isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names)
        ]
        for source in sources
    }
    graph = _ClassGraph()
    class_nodes = {}
    for source in sources:
        for node, scope in iter_scoped_nodes(source.tree):
            if isinstance(node, ast.ClassDef):
                key = (source.dotted, render_symbol(scope + (node,)))
                class_nodes[key] = (source, node)
                graph.methods_by_class[key] = {
                    item.name for item in node.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                }

    def resolve_class(module: str, name: str, seen: set) -> Optional[tuple[str, str]]:
        """Busca la clase ``name`` en ``module`` siguiendo reexportaciones; ``None`` si es externa."""
        if (module, name) in seen:
            return None
        seen.add((module, name))
        if (module, name) in class_nodes:
            return (module, name)
        if module not in files_by_module:
            return None
        binding = bindings_by_module[module].get(name)
        if binding and binding[1] is not None:
            return resolve_class(binding[0], binding[1], seen)
        for star_module in star_modules_by_module[module]:
            resolved = resolve_class(star_module, name, seen)
            if resolved:
                return resolved
        return None

    def resolve_base(source: SourceFile, expression: ast.expr) -> Optional[tuple[str, str]]:
        """Resuelve la expresión de una base (``Foo``, ``m.Foo``, ``Foo[T]``) a una clase del grafo."""
        if isinstance(expression, ast.Subscript):
            expression = expression.value
        bindings = bindings_by_module[source.dotted]
        if isinstance(expression, ast.Name):
            if (source.dotted, expression.id) in class_nodes:
                return (source.dotted, expression.id)
            binding = bindings.get(expression.id)
            return resolve_class(*binding, set()) if binding and binding[1] is not None else None
        if isinstance(expression, ast.Attribute):
            root, *rest = ast.unparse(expression.value).split(".")
            binding = bindings.get(root)
            if binding is None:
                return None
            module = binding[0] if binding[1] is None else f"{binding[0]}.{binding[1]}"
            return resolve_class(".".join([module, *rest]), expression.attr, set())
        return None

    for key, (source, node) in class_nodes.items():
        parents = [parent for parent in (resolve_base(source, base) for base in node.bases) if parent]
        graph.parents_by_class[key] = parents
        for parent in parents:
            graph.children_by_class.setdefault(parent, []).append(key)
    graph.class_nodes = class_nodes
    return graph


def _is_exempt_by_decorator(function: ast.FunctionDef) -> bool:
    """Indica si un método privado queda exento por su decorador.

    Lo está si es ``@abstractmethod`` (un gancho declarado) o una propiedad
    (``@property``, ``@cached_property`` o su ``.setter``/``.deleter``): una propiedad
    se lee como un atributo, y § 5.1 permite atributos privados.
    """
    exempt_names = {"abstractmethod", "property", "cached_property", "setter", "deleter"}
    for decorator in function.decorator_list:
        name = decorator.id if isinstance(decorator, ast.Name) else getattr(decorator, "attr", None)
        if name in exempt_names:
            return True
    return False


def find_private_methods(
    sources: tuple[SourceFile, ...], external_hooks: Optional[dict] = None
) -> set[tuple[str, str, str]]:
    """Regla 2: métodos ``_x`` que no son ganchos (§ 5.1).

    Un método privado es legítimo si es ``@abstractmethod``, si lo declara también un
    ancestro de su clase o una subclase (dentro de ``sources``), o si figura en
    ``external_hooks``.

    Args:
        sources: Ficheros a revisar; forman también el grafo de herencia.
        external_hooks: Ganchos de librerías externas, con la forma de
            ``EXTERNAL_HOOKS``. Por defecto, ninguno.

    Returns:
        set[tuple[str, str, str]]: Las violaciones; vacío si no hay ninguna.
    """
    external_hooks = external_hooks or {}
    graph = build_class_graph(sources)
    violations = set()
    for key, (source, node) in graph.class_nodes.items():
        related = graph.collect_related(key, graph.parents_by_class) | graph.collect_related(key, graph.children_by_class)
        inherited_names = set().union(*(graph.methods_by_class[other] for other in related))
        for item in node.body:
            if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) or not is_private_name(item.name):
                continue
            symbol = f"{key[1]}.{item.name}"
            if _is_exempt_by_decorator(item) or item.name in inherited_names or (source.path, symbol) in external_hooks:
                continue
            violations.add((RULE_PRIVATE_METHOD, source.path, symbol))
    return violations


# ------------------------------------------------------------------ reglas 3, 4 y 5


def find_module_internals_imports(source: SourceFile) -> set[tuple[str, str, str]]:
    """Regla 3: imports de los ``services``/``repositories`` de otro módulo (§ 3.3).

    Args:
        source: Fichero a revisar.

    Returns:
        set[tuple[str, str, str]]: Las violaciones, con el nombre importado como
            símbolo; vacío si no hay ninguna.
    """
    violations = set()
    for target, _ in iter_import_targets(source):
        target_owner = owner_module_of(target)
        if target_owner is None or target_owner == source.owner:
            continue
        if _MODULE_INTERNALS & set(target.split(".")):
            violations.add((RULE_MODULE_INTERNALS, source.path, target))
    return violations


def find_private_name_imports(source: SourceFile) -> set[tuple[str, str, str]]:
    """Regla 4: ``from X import _nombre`` dentro de ``src/`` (§ 5.4).

    Args:
        source: Fichero a revisar.

    Returns:
        set[tuple[str, str, str]]: Las violaciones, con el nombre importado como
            símbolo; vacío si no hay ninguna.
    """
    return {
        (RULE_PRIVATE_IMPORT, source.path, f"{resolve_import_from(source, node)}.{alias.name}")
        for node in ast.walk(source.tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
        if is_private_name(alias.name)
    }


def find_reverse_dependencies(source: SourceFile) -> set[tuple[str, str, str]]:
    """Regla 5: imports hacia un módulo de rango mayor que el propio (§ 3.4).

    Args:
        source: Fichero a revisar.

    Returns:
        set[tuple[str, str, str]]: Las violaciones, con el nombre importado como
            símbolo; vacío si no hay ninguna. Los ficheros o destinos sin rango
            no se evalúan (``test_every_module_has_a_rank`` los vigila).
    """
    source_rank = rank_of(source.owner) if source.owner else None
    if source_rank is None:
        return set()
    violations = set()
    for target, _ in iter_import_targets(source):
        target_owner = owner_module_of(target)
        if target_owner is None or (source.path, target_owner) in _AUTHORIZED_DIRECTION_EXCEPTIONS:
            continue
        target_rank = rank_of(target_owner)
        if target_rank is not None and target_rank > source_rank:
            violations.add((RULE_DIRECTION, source.path, target))
    return violations


def find_violations(sources: tuple[SourceFile, ...], external_hooks: Optional[dict] = None) -> set[tuple[str, str, str]]:
    """Aplica las cinco reglas a un conjunto de ficheros.

    Args:
        sources: Ficheros a revisar.
        external_hooks: Ganchos externos para la regla 2. Por defecto, ninguno.

    Returns:
        set[tuple[str, str, str]]: Todas las violaciones ``(regla, ruta, símbolo)``.
    """
    violations = find_private_methods(sources, external_hooks)
    for source in sources:
        violations |= find_sql_outside_repository(source)
        violations |= find_module_internals_imports(source)
        violations |= find_private_name_imports(source)
        violations |= find_reverse_dependencies(source)
    return violations


@lru_cache(maxsize=1)
def find_repository_violations() -> frozenset[tuple[str, str, str]]:
    """Violaciones del código real de ``src/``, cacheadas para toda la sesión de tests."""
    return frozenset(find_violations(load_source_files(), EXTERNAL_HOOKS))


# ------------------------------------------------------------------ tests sobre src/


@pytest.mark.parametrize("rule", ALL_RULES)
def test_rule_matches_known_violations(rule):
    """Cada regla encuentra exactamente las violaciones de ``KNOWN_VIOLATIONS``: ni más ni menos."""
    found = {violation for violation in find_repository_violations() if violation[0] == rule}
    known = {violation for violation in KNOWN_VIOLATIONS if violation[0] == rule}
    new_violations, fixed_violations = sorted(found - known), sorted(known - found)

    message = []
    if new_violations:
        message.append(f"Violaciones nuevas de «{rule}» — ver CONVENCIONES.md {_RULE_SECTIONS[rule]}:")
        message += [f"  {path} :: {symbol}" for _, path, symbol in new_violations]
    if fixed_violations:
        message.append(f"Violaciones de «{rule}» que ya no existen — borra su entrada de KNOWN_VIOLATIONS:")
        message += [f"  {path} :: {symbol}" for _, path, symbol in fixed_violations]
    assert not message, "\n".join(message)


def test_external_hooks_still_exist():
    """Cada entrada de ``EXTERNAL_HOOKS`` sigue siendo un método privado real; si no, sobra."""
    unhooked = find_private_methods(load_source_files())
    stale_hooks = sorted(hook for hook in EXTERNAL_HOOKS if (RULE_PRIVATE_METHOD, *hook) not in unhooked)
    assert not stale_hooks, f"Entradas de EXTERNAL_HOOKS que ya no existen: {stale_hooks}"


def test_every_module_has_a_rank():
    """Todo módulo de ``src/modules/`` figura en la tabla de rangos de la regla 5."""
    unranked = sorted({source.owner for source in load_source_files() if source.owner and rank_of(source.owner) is None})
    assert not unranked, f"Módulos sin rango en _MODULE_RANKS (CONVENCIONES.md § 11.2, regla 5): {unranked}"


# ------------------------------------------------------------------ tests del detector

_MANAGER_PATH = "src/modules/features/iris/managers/analysis.py"


class TestSqlDetector:
    """La regla 1 detecta SQL fuera de repositorios y solo eso."""

    def test_detects_session_call_in_manager(self):
        """Un ``uow.session.add`` dentro de un manager es violación."""
        source = parse_source(_MANAGER_PATH, """
            class FooManager:
                def create(self, uow, item):
                    uow.session.add(item)
        """)
        assert find_sql_outside_repository(source) == {(RULE_SQL, _MANAGER_PATH, "FooManager.create")}

    def test_detects_sqlalchemy_statement_in_function(self):
        """Un ``select`` importado de SQLAlchemy, aunque sea con alias, es violación."""
        source = parse_source(_MANAGER_PATH, """
            from sqlalchemy import select as build_select
            import sqlalchemy as sa

            def load(model):
                return build_select(model), sa.text("SELECT 1")
        """)
        assert find_sql_outside_repository(source) == {(RULE_SQL, _MANAGER_PATH, "load")}

    def test_ignores_repositories_foreign_text_and_infrastructure(self):
        """Ni un repositorio, ni un ``text`` que no es de SQLAlchemy, ni ``infrastructure/``."""
        source = parse_source(_MANAGER_PATH, """
            from sqlalchemy import update

            class FooRepository:
                def save(self, item):
                    self.session.add(item)
                    return update(item)

            def read(item, text):
                return item.findtext("x"), text("y"), item.session_count.get("z")
        """)
        infrastructure = parse_source("src/modules/infrastructure/session.py", "session.query(1)")
        model = parse_source("src/modules/accounts/model.py", """
            from sqlalchemy import Index, text

            class Plan:
                __table_args__ = (Index("ux_plan_default", postgresql_where=text("is_default")),)
        """)
        assert find_sql_outside_repository(source) == set()
        assert find_sql_outside_repository(infrastructure) == set()
        assert find_sql_outside_repository(model) == set()


class TestPrivateMethodDetector:
    """La regla 2 detecta métodos privados que no son ganchos."""

    def test_detects_plain_private_helper(self):
        """Un ``_método`` que nadie redefine es un helper, no un gancho."""
        source = parse_source(_MANAGER_PATH, """
            class FooManager:
                def run(self):
                    return self._helper()

                def _helper(self):
                    return 1
        """)
        assert find_private_methods((source,)) == {(RULE_PRIVATE_METHOD, _MANAGER_PATH, "FooManager._helper")}

    def test_ignores_abstract_overridden_dunder_and_external_hooks(self):
        """Abstractos, ganchos redefinidos entre ficheros, especiales y ganchos externos no cuentan."""
        base = parse_source("src/modules/features/themis/managers/scan.py", """
            from abc import ABC, abstractmethod

            class ScanManager(ABC):
                @abstractmethod
                def _build_command(self): ...

                def _parse(self): ...

                def __init__(self): ...

                @property
                def _session(self): ...
        """)
        package = parse_source("src/modules/features/themis/managers/__init__.py", """
            from .scan import ScanManager
        """)
        subclass = parse_source("src/modules/features/themis/managers/nmap.py", """
            from rq import SimpleWorker
            from src.modules.features.themis.managers import ScanManager

            class NmapScanManager(ScanManager):
                def _build_command(self): ...

                def _parse(self): ...

            class Worker(SimpleWorker):
                def _install_signal_handlers(self): ...
        """)
        hooks = {("src/modules/features/themis/managers/nmap.py", "Worker._install_signal_handlers"): "rq"}
        assert find_private_methods((base, package, subclass), hooks) == set()


class TestModuleInternalsDetector:
    """La regla 3 detecta imports de las tripas de otro módulo."""

    def test_detects_foreign_services_and_repositories(self):
        """Importar ``services`` o ``repositories`` de otro módulo es violación."""
        source = parse_source("src/modules/features/aegis/managers/pills.py", """
            from src.modules.users.services.secrets import hash_password
            from src.modules.features.themis import repositories
        """)
        assert find_module_internals_imports(source) == {
            (RULE_MODULE_INTERNALS, source.path, "src.modules.users.services.secrets.hash_password"),
            (RULE_MODULE_INTERNALS, source.path, "src.modules.features.themis.repositories"),
        }

    def test_ignores_own_internals_and_public_surface(self):
        """Los servicios propios (también por import relativo) y la superficie pública ajena valen."""
        source = parse_source(_MANAGER_PATH, """
            from ..services.scoring import score
            from ..repositories import IrisAnalysisRepository
            from src.modules.users import User
            from src.modules.system.taskqueue.outbox_repository import TaskDispatchRepository
        """)
        assert find_module_internals_imports(source) == set()


class TestPrivateImportDetector:
    """La regla 4 detecta ``_nombres`` importados fuera de su fichero."""

    def test_detects_private_name_import(self):
        """Un ``from .x import _nombre`` es violación aunque sea del mismo módulo."""
        source = parse_source(_MANAGER_PATH, "from .mailbox import _refresh_token")
        assert find_private_name_imports(source) == {
            (RULE_PRIVATE_IMPORT, _MANAGER_PATH, "src.modules.features.iris.managers.mailbox._refresh_token"),
        }

    def test_ignores_public_and_dunder_names(self):
        """Los nombres públicos, los especiales y los ficheros ``_x.py`` con nombres públicos valen."""
        source = parse_source(_MANAGER_PATH, """
            from __future__ import annotations
            from src.modules.shared._model import Base
            from .mailbox import __all__
        """)
        assert find_private_name_imports(source) == set()


class TestDirectionDetector:
    """La regla 5 detecta dependencias hacia un rango mayor."""

    def test_detects_transversal_importing_feature(self):
        """``users`` (rango 2) importando Acheron (rango 3) es violación."""
        source = parse_source("src/modules/users/__init__.py", "from src.modules.features.acheron import Vault")
        assert find_reverse_dependencies(source) == {
            (RULE_DIRECTION, source.path, "src.modules.features.acheron.Vault"),
        }

    def test_ignores_downward_imports_and_authorized_exception(self):
        """Importar hacia abajo vale, y ``config_reading`` → ``ScanType`` está autorizado."""
        feature = parse_source(_MANAGER_PATH, """
            from src.modules.users import User
            from src.modules.shared import is_private_target
            from src.modules.features.themis import ScanType
        """)
        config_reading = parse_source(
            "src/modules/system/config_reading.py", "from src.modules.features.themis.model import ScanType"
        )
        assert find_reverse_dependencies(feature) == set()
        assert find_reverse_dependencies(config_reading) == set()
