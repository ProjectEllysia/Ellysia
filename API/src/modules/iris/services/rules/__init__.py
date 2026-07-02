from ..registry import iris_rules, RuleResult
from . import (
    spf, dkim, dmarc, domain_alignment, reply_to, reply_to_free_provider,
    return_path_mismatch, message_id_check, msgid_domain, content_type_check,
    from_header_check, alarming_keywords, display_name_spoof, lookalike_domain,
    suspicious_tld, url_in_subject, date_anomaly, misspelled_brands,
    fake_reply_chain, undisclosed_recipients, suspicious_attachments,
    list_unsubscribe, received_chain, body_links, body_content,
    display_name_email_mismatch, subdomain_impersonation,
    compromised_legitimate_domain, bare_url_bec_pattern, generic_greeting,
    reply_to_path_mismatch, image_only_email,
    received_chain_temporal_inconsistency, in_reply_to_self_reference,
    body_external_image_tracking, received_path_anomaly,
)

__all__ = ["iris_rules", "RuleResult"]
