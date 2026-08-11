"""
Iris detection rules, grouped by category (one file per concern):

- ``auth_rules``: SPF, DKIM, DMARC, Domain Alignment.
- ``sender_identity_rules``: From header, display-name spoofing, lookalike
  domains, subdomain impersonation, misspelled brands, suspicious TLDs.
- ``reply_path_rules``: Reply-To / Return-Path mismatches and triangulation.
- ``thread_rules``: fake reply chains, self-referencing threading, Message-ID.
- ``recipient_rules``: undisclosed/BCC-only recipients.
- ``received_timing_rules``: Date header and Received-chain anomalies.
- ``content_trust_rules``: Content-Type reporting, List-Unsubscribe.
- ``body_content_rules``: Subject/body keyword, BEC, greeting, Unicode and
  encoded-word evasion checks.
- ``body_links_rules``: hyperlink cloaking/evasion and compromised domains.
- ``attachment_media_rules``: external image tracking, image-only email,
  suspicious attachments.

Importing this package triggers every rule module's ``@iris_rules.register``
decorators, populating the registry — see ``registry.py``.
"""

from ..registry import iris_rules, RuleResult

# Estas importaciones no tienen referencias directas más abajo -- su único
# propósito es el efecto colateral de importar el módulo: cada uno dispara
# sus decoradores @iris_rules.register al cargar, que es como se puebla el
# registro. Sin ellas `iris_rules.get_rules()` devuelve una lista vacía y
# el motor evalúa cero reglas (todo sale Legitimate) salvo que algún otro
# import fortuito de un módulo de reglas concreto lo rescate primero -- lo
# que un linter de "imports no usados" no puede distinguir de basura muerta.
from . import (
    attachment_media_rules,
    auth_rules,
    body_content_rules,
    body_links_rules,
    content_trust_rules,
    received_timing_rules,
    recipient_rules,
    reply_path_rules,
    sender_identity_rules,
    thread_rules,
)

__all__ = ["iris_rules", "RuleResult"]
