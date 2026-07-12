"""
Repositories for the Aegis security awareness module.

Provides typed data access for AegisDocument and its related entities
(Tips, Alerts, Topics, quiz questions), and for the awareness-campaign
feature built on top of it (distribution lists, campaigns, per-recipient
tracking). All Aegis repositories live in this single file by convention.

Classes:
    AegisDocumentRepository: Repository for AegisDocument.
    AegisOrgProfileRepository: Repository for the per-user org profile.
    DistributionListRepository: CRUD for lists and their recipients.
    CampaignRepository: Campaign lifecycle, per-recipient tracking, and
        the public-quiz token lookup.

Usage:
    with UnitOfWork() as uow:
        repo = AegisDocumentRepository(uow)
        docs = repo.get_documents_by_user(user_id=1)
        doc = repo.get_by_id_with_details(42)
"""

from __future__ import annotations

from typing import List, Optional

from sqlalchemy.orm import Session

from src.modules.shared import utcnow_naive
from src.modules.aegis.model import (
    AegisDocument,
    AegisDocumentAlert,
    AegisOrgProfile,
    AegisQuizQuestion,
    AegisTip,
    Campaign,
    CampaignAnswer,
    CampaignRecipient,
    DistributionList,
    Recipient,
    Topic,
)
from src.modules.infrastructure import BaseRepository, UnitOfWork


class AegisDocumentRepository(BaseRepository[AegisDocument]):
    """
    Repository for the AegisDocument entity (security awareness pills).

    Inherits all generic CRUD and query operations from BaseRepository[AegisDocument]
    and adds domain-specific query methods.

    Attributes:
        _model:  AegisDocument (inherited from BaseRepository).
        _uow:    Active Unit of Work (inherited from BaseRepository).

    Example:
    >>> with UnitOfWork() as uow:
    ...     repo = AegisDocumentRepository(uow)
    ...     docs = repo.get_documents_by_user(user_id=1)
    ...     doc  = repo.get_by_id_with_details(42)
    ...     repo.delete(doc)
    """

    def __init__(self, uow: UnitOfWork | None = None, session: Session | None = None) -> None:
        super().__init__(AegisDocument, uow=uow, session=session)

    # =========================================================================
    # DOMAIN QUERIES
    # =========================================================================

    def get_documents_by_user(self, user_id: int, limit: int = 100) -> List[AegisDocument]:
        """
        Retrieve all documents for a user, ordered by generation date (desc).

        Args:
            user_id: Primary key of the user.
            limit: Maximum number of documents to return (default: 100).

        Returns:
            List of AegisDocument instances.
        """
        return (
            self._session.query(AegisDocument)
            .filter(AegisDocument.user_id == user_id)
            .order_by(AegisDocument.generated_at.desc())
            .limit(limit)
            .all()
        )

    def get_documents_by_topic(self, topic_id: int, limit: int = 50) -> List[AegisDocument]:
        """
        Retrieve all documents for a topic.

        Args:
            topic_id: Primary key of the topic.
            limit: Maximum number of documents to return (default: 50).

        Returns:
            List of AegisDocument instances.
        """
        return (
            self._session.query(AegisDocument)
            .filter(AegisDocument.topic_id == topic_id)
            .order_by(AegisDocument.generated_at.desc())
            .limit(limit)
            .all()
        )

    def get_documents_by_status(
        self, user_id: int, status: str, limit: int = 50
    ) -> List[AegisDocument]:
        """
        Retrieve documents by status for a specific user.

        Args:
            user_id: Primary key of the user.
            status: Document status ('pending', 'running', 'done', 'error').
            limit: Maximum number of documents to return (default: 50).

        Returns:
            List of AegisDocument instances.
        """
        return (
            self._session.query(AegisDocument)
            .filter(AegisDocument.user_id == user_id, AegisDocument.status == status)
            .order_by(AegisDocument.created_at.desc())
            .limit(limit)
            .all()
        )

    # =========================================================================
    # TOPIC QUERIES
    # =========================================================================

    def get_topics(self) -> List[Topic]:
        """
        Retrieve all topics ordered by title.

        Returns:
            List of Topic instances.
        """
        return (
            self._session.query(Topic)
            .order_by(Topic.title)
            .all()
        )

    def get_topic_by_id(self, topic_id: int) -> Optional[Topic]:
        """
        Retrieve a topic by its ID.

        Args:
            topic_id: Primary key of the topic.

        Returns:
            Topic instance or None if not found.
        """
        return self._session.get(Topic, topic_id)

    # =========================================================================
    # STATUS TRANSITIONS
    # =========================================================================

    def update_status(
        self,
        doc_id: int,
        status: str,
        title: str | None = None,
        filename: str | None = None,
        error: str | None = None,
    ) -> Optional[AegisDocument]:
        """
        Update document status with optional fields.

        Args:
            doc_id: Primary key of the document.
            status: New status ('pending', 'running', 'done', 'error').
            title: New title (truncated to 64 chars).
            filename: New filename (truncated to 128 chars).
            error: Error message for 'error' status (truncated to 50).

        Returns:
            Updated AegisDocument instance, or None if not found.
        """
        doc = self._session.get(AegisDocument, doc_id)
        if doc is None:
            return None

        doc.status = status
        if title:
            doc.title = title[:64]
        if filename:
            doc.filename = filename[:128]
        if status == "done":
            doc.generated_at = utcnow_naive()
        if error and status == "error":
            doc.title = f"[ERR{doc_id}] {error[:50]}"[:64]

        return doc

    # =========================================================================
    # CONTENT PERSISTENCE
    # =========================================================================

    def update_content_fields(
        self,
        doc_id: int,
        subtitle: str | None,
        intro: str | None,
        closing: str | None,
        contact_email: str | None,
        company: str | None,
    ) -> Optional[AegisDocument]:
        """
        Update the content fields of a document.

        Args:
            doc_id: Primary key of the document.
            subtitle: New subtitle.
            intro: New intro.
            closing: New closing.
            contact_email: New contact email.
            company: New company name.

        Returns:
            Updated AegisDocument instance, or None if not found.
        """
        doc = self._session.get(AegisDocument, doc_id)
        if doc is None:
            return None

        doc.subtitle = subtitle
        doc.intro = intro
        doc.closing = closing
        doc.contact_email = contact_email
        doc.company = company

        return doc

    def save_tips(self, doc_id: int, tips_data: list[dict]) -> None:
        """
        Replace all tips for a document with new ones.

        Deletes existing tips and inserts new tips in a single transaction.

        Args:
            doc_id: Primary key of the document.
            tips_data: List of tip dictionaries with keys: headline, body, links.
        """
        self._session.query(AegisTip).filter(AegisTip.document_id == doc_id).delete()
        self._session.flush()

        for i, tip_data in enumerate(tips_data, 1):
            links_value = tip_data.get("links")
            if links_value:
                links_value = [{"text": lk["text"], "url": lk["url"]} for lk in links_value]

            self._session.add(AegisTip(
                document_id=doc_id,
                position=i,
                headline=tip_data["headline"],
                body=tip_data["body"],
                links_json=links_value,
            ))

    def save_questions(self, doc_id: int, questions_data: list[dict]) -> None:
        """
        Replace all quiz questions for a document with new ones.

        Deletes existing questions and inserts new ones in a single
        transaction. Mirrors save_tips.

        Args:
            doc_id: Primary key of the document.
            questions_data: List of question dictionaries with keys:
                             prompt, options, correct_index.
        """
        self._session.query(AegisQuizQuestion).filter(
            AegisQuizQuestion.document_id == doc_id
        ).delete()
        self._session.flush()

        for i, q_data in enumerate(questions_data, 1):
            self._session.add(AegisQuizQuestion(
                document_id=doc_id,
                position=i,
                prompt=q_data["prompt"],
                options=q_data["options"],
                correct_index=q_data["correct_index"],
            ))

    def save_alerts(
        self,
        doc_id: int,
        alerts_data: list[dict],
    ) -> None:
        """
        Replace all alerts for a document with new ones.

        Deletes existing alerts and inserts new alerts in a single transaction.

        Args:
            doc_id: Primary key of the document.
            alerts_data: List of alert dictionaries with keys:
                          source, source_label, title, published, severity,
                          affected_brands, description, url.
        """
        self._session.query(AegisDocumentAlert).filter(
            AegisDocumentAlert.document_id == doc_id
        ).delete()
        self._session.flush()

        for i, alert_data in enumerate(alerts_data, 1):
            self._session.add(AegisDocumentAlert(
                document_id=doc_id,
                position=i,
                source=alert_data["source"],
                source_label=alert_data["source_label"],
                title=alert_data["title"][:256],
                published=alert_data.get("published"),
                severity=alert_data.get("severity"),
                affected_brands=alert_data.get("affected_brands"),
                description=alert_data.get("description", "")[:500] if alert_data.get("description") else None,
                url=alert_data["url"][:512],
            ))

    # =========================================================================
    # CREATE
    # =========================================================================

    def create_pending(
        self,
        topic_id: int,
        user_id: int,
    ) -> AegisDocument:
        """
        Create a new pending document.

        Args:
            topic_id: Primary key of the topic.
            user_id: Primary key of the user.

        Returns:
            Created AegisDocument instance.
        """
        ts = utcnow_naive().strftime("%Y%m%d_%H%M%S")
        placeholder = f"pending_{ts}_{user_id}_{topic_id}"

        doc = AegisDocument(
            title=placeholder[:64],
            filename=f"{placeholder}.json"[:128],
            status="pending",
            format="json",
            topic_id=topic_id,
            user_id=user_id,
            is_ai_generated=1,
        )

        self._session.add(doc)
        self._session.flush()
        self._session.refresh(doc)
        return doc


class AegisOrgProfileRepository(BaseRepository[AegisOrgProfile]):
    """
    Repository for AegisOrgProfile (stable per-user generation defaults).

    One row per user; inherits generic CRUD from BaseRepository.
    """

    def __init__(self, uow: UnitOfWork | None = None, session: Session | None = None) -> None:
        super().__init__(AegisOrgProfile, uow=uow, session=session)

    def get_by_user_id(self, user_id: int) -> Optional[AegisOrgProfile]:
        """Retrieve the org profile for a user, or None if not set up yet."""
        return self.get_by_field("user_id", user_id)


class DistributionListRepository(BaseRepository[DistributionList]):
    """Repository for DistributionList and its Recipient rows."""

    def __init__(self, uow: UnitOfWork | None = None, session: Session | None = None) -> None:
        super().__init__(DistributionList, uow=uow, session=session)

    def get_lists_by_user(self, user_id: int) -> List[DistributionList]:
        """Retrieve all distribution lists owned by a user, newest first."""
        return (
            self._session.query(DistributionList)
            .filter(DistributionList.user_id == user_id)
            .order_by(DistributionList.created_at.desc())
            .all()
        )

    def create_list(self, user_id: int, name: str) -> DistributionList:
        """Create a new, empty distribution list."""
        dist_list = DistributionList(user_id=user_id, name=name)
        self._session.add(dist_list)
        self._session.flush()
        self._session.refresh(dist_list)
        return dist_list

    def add_recipients(self, list_id: int, recipients_data: list[dict]) -> List[Recipient]:
        """
        Add recipients to a list, skipping emails already present.

        Args:
            list_id: Primary key of the DistributionList.
            recipients_data: List of dicts with keys: email, name.

        Returns:
            The newly created Recipient instances (excludes skipped duplicates).
        """
        existing_emails = {
            email for (email,) in
            self._session.query(Recipient.email).filter(Recipient.list_id == list_id).all()
        }

        created: list[Recipient] = []
        for data in recipients_data:
            email = data["email"].strip().lower()
            if email in existing_emails:
                continue
            recipient = Recipient(list_id=list_id, email=email, name=data.get("name") or None)
            self._session.add(recipient)
            existing_emails.add(email)
            created.append(recipient)

        self._session.flush()
        for recipient in created:
            self._session.refresh(recipient)
        return created

    def get_recipients(self, list_id: int) -> List[Recipient]:
        """Retrieve all recipients belonging to a list."""
        return (
            self._session.query(Recipient)
            .filter(Recipient.list_id == list_id)
            .order_by(Recipient.id)
            .all()
        )

    def remove_recipient(self, list_id: int, recipient_id: int) -> bool:
        """Remove a single recipient from a list. Returns False if not found."""
        recipient = (
            self._session.query(Recipient)
            .filter(Recipient.id == recipient_id, Recipient.list_id == list_id)
            .one_or_none()
        )
        if recipient is None:
            return False
        self._session.delete(recipient)
        self._session.flush()
        return True


class CampaignRepository(BaseRepository[Campaign]):
    """Repository for Campaign, CampaignRecipient, and CampaignAnswer."""

    def __init__(self, uow: UnitOfWork | None = None, session: Session | None = None) -> None:
        super().__init__(Campaign, uow=uow, session=session)

    # =========================================================================
    # CAMPAIGN
    # =========================================================================

    def get_campaigns_by_user(self, user_id: int) -> List[Campaign]:
        """Retrieve all campaigns owned by a user, newest first."""
        return (
            self._session.query(Campaign)
            .filter(Campaign.user_id == user_id)
            .order_by(Campaign.created_at.desc())
            .all()
        )

    def create_campaign(
        self, user_id: int, document_id: int, list_id: int, name: str,
    ) -> Campaign:
        """Create a new campaign in 'draft' status (not yet launched)."""
        campaign = Campaign(
            user_id=user_id,
            document_id=document_id,
            list_id=list_id,
            name=name,
            status="draft",
        )
        self._session.add(campaign)
        self._session.flush()
        self._session.refresh(campaign)
        return campaign

    def launch_campaign(
        self,
        campaign_id: int,
        questions_snapshot: list[dict],
        recipients: list[CampaignRecipient],
    ) -> Optional[Campaign]:
        """
        Mark a campaign as launched: attach the questions snapshot and the
        already-built CampaignRecipient rows (with their tokens), and set
        launched_at. Does not send any email — that's the RQ job's job.
        """
        campaign = self._session.get(Campaign, campaign_id)
        if campaign is None:
            return None

        campaign.questions_snapshot = questions_snapshot
        campaign.launched_at = utcnow_naive()
        campaign.status = "sending"
        for recipient in recipients:
            recipient.campaign_id = campaign_id
            self._session.add(recipient)

        self._session.flush()
        return campaign

    def mark_campaign_status(self, campaign_id: int, status: str) -> None:
        """Update a campaign's status (e.g. 'sending' -> 'sent')."""
        campaign = self._session.get(Campaign, campaign_id)
        if campaign is not None:
            campaign.status = status
            self._session.flush()

    # =========================================================================
    # CAMPAIGN RECIPIENT
    # =========================================================================

    def get_recipients(self, campaign_id: int) -> List[CampaignRecipient]:
        """Retrieve all tracking rows for a campaign."""
        return (
            self._session.query(CampaignRecipient)
            .filter(CampaignRecipient.campaign_id == campaign_id)
            .order_by(CampaignRecipient.id)
            .all()
        )

    def get_recipient_by_token(self, token: str) -> Optional[CampaignRecipient]:
        """
        Look up the sole identity of the public quiz page: the recipient
        row owning this opaque token. Returns None if the token is unknown.
        """
        return (
            self._session.query(CampaignRecipient)
            .filter(CampaignRecipient.token == token)
            .one_or_none()
        )

    def mark_sent(self, recipient_id: int) -> None:
        """Record the timestamp an email was actually dispatched."""
        recipient = self._session.get(CampaignRecipient, recipient_id)
        if recipient is not None:
            recipient.sent_at = utcnow_naive()
            self._session.flush()

    def mark_opened(self, recipient_id: int) -> None:
        """Mark the first GET on the public quiz page (idempotent)."""
        recipient = self._session.get(CampaignRecipient, recipient_id)
        if recipient is not None and recipient.status == "sent":
            recipient.status = "opened"
            recipient.opened_at = utcnow_naive()
            self._session.flush()

    def mark_completed(
        self, recipient_id: int, score: int, answers: list[dict],
    ) -> Optional[CampaignRecipient]:
        """
        Persist the graded answers and mark the recipient's quiz as
        completed. Callers MUST verify the recipient isn't already
        completed before calling this (the no-repeat rule lives in the
        manager/endpoint layer, which holds the authoritative status check).
        """
        recipient = self._session.get(CampaignRecipient, recipient_id)
        if recipient is None:
            return None

        for answer in answers:
            self._session.add(CampaignAnswer(
                campaign_recipient_id=recipient_id,
                question_position=answer["question_position"],
                selected_index=answer["selected_index"],
                is_correct=answer["is_correct"],
            ))

        recipient.status = "completed"
        recipient.completed_at = utcnow_naive()
        recipient.score = score

        self._session.flush()
        self._session.refresh(recipient)
        return recipient