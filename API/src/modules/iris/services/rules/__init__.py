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
