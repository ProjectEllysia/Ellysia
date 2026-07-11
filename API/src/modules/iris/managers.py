"""
IrisManager — orchestrates email header analysis via TaskQueue background tasks.

Coordinates the analysis lifecycle:
1. Creates an IrisAnalysis record in the database.
2. Submits an analysis task to the TaskQueue (category: "iris.analyze").
3. The background task runs all registered rules, aggregates scores,
   determines a verdict, and persists results.
4. Provides status queries and cancellation support.
"""

from __future__ import annotations

import hashlib
import os
import re
import logging
from dataclasses import replace
from typing import Any, Dict, List, Optional

import src.modules.system.config_reading as CR
from src.modules.aegis.exceptions import DocumentNotFoundError
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import read_repo
from src.modules.shared import assert_owned, utcnow_naive, isoformat_utc
from src.modules.system.taskqueue import ITaskQueue, TaskQueue, TaskTrackingMixin, job_context

from .exceptions import (
    IrisAnalysisNotFoundError,
    IrisAnalysisNotReadyError,
    IrisExecutionError,
    IrisInvalidInputError,
    IrisInvalidStateError,
)
from .model import IrisAnalysis, IrisDocument, IrisRuleResult
from .repositories import IrisAnalysisRepository, IrisReportRepository, IrisRuleResultRepository
from .services.rules import iris_rules, RuleResult
from .services.shared import extract_domain, is_free_provider, url_host
from .services import parse_raw_message
from .services.parsers import build_path, parse_received_line
from .services.reports import IrisPDFCreator
from .services.ai_writer import IrisAIWriter


logger = logging.getLogger(__name__)

_CANCELLABLE_STATES = frozenset({"pending", "running"})

# Verdict severity ordering, worst last. Gating can only push a verdict
# toward a *worse* category, never improve it.
_VERDICT_ORDER = ["Legitimate", "Suspicious", "Phishing"]
_VERDICT_SEVERITY = {v: i for i, v in enumerate(_VERDICT_ORDER)}

# Subtractive risk model: an analysis starts from this clean ceiling and
# rules can only *subtract* from it. A passing rule contributes nothing; a
# failing rule subtracts its (negative) score. This removes the historical
# "authentication cushion", where dozens of small positive credits (SPF/DKIM/
# DMARC pass, etc.) buried a few strong phishing signals — a clean-auth BEC
# from Gmail used to net *positive* despite a -23 risk payload underneath.
_CEILING = 100.0


class IrisManager(TaskTrackingMixin):
    """Orchestrates the lifecycle of an Iris email-header analysis.

    Typical usage::

        manager = IrisManager()
        analysis_id = manager.analyze(raw_headers, user_id)   # submit
        status = manager.get_analysis_status(analysis_id)      # poll
        report = manager.get_analysis_results(analysis_id)     # finished
    """

    EXTERNAL_ID_PREFIX = "iris-analysis:"
    TASK_CATEGORY = "iris.analyze"
    _TOP_SIGNALS_LIMIT = 5

    def __init__(self, task_queue: ITaskQueue | None = None) -> None:
        self._tq: ITaskQueue = task_queue or TaskQueue.get_instance()

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def analyze(
        self,
        raw_headers: str | None,
        user_id: int,
        title: str | None = None,
        raw_message: str | None = None
    ) -> int:
        """Submit raw email headers (or a full message) for background analysis.

        Creates an IrisAnalysis record in ``pending`` state and enqueues
        a TaskQueue task (category ``"iris.analyze"``) that runs every
        registered rule, aggregates scores, and persists the results.

        Args:
            raw_headers: Headers-only block as plain text (legacy input).
            user_id:     Primary key of the requesting user.
            title:       Optional user-defined label for quick
                         identification in history.
            raw_message: Full raw ``.eml`` message as plain text (Fase 2).
                         Takes priority over ``raw_headers`` when both are
                         given, since it's a superset of the header data.
                         Rules that need body/links/attachments only see
                         them when this is provided.

        Returns:
            The new IrisAnalysis primary key (``analysis_id``).  The
            caller should store this to later poll status or fetch the
            full report.

        Raises:
            IrisInvalidInputError: If neither input is given, or the
                content contains fewer than the minimum required header
                lines (configurable via ``iris.min_headers`` in
                SecOpsConfig.json).
        """
        raw_input = raw_message or raw_headers
        if not raw_input:
            raise IrisInvalidInputError(
                "Debe proporcionar cabeceras de correo o un mensaje completo."
            )

        self._validate_headers_pre(raw_input)
        analysis_id = self._create_analysis_record(raw_input, user_id, title=title)
        logger.info(f"Iris analysis {analysis_id} created for user {user_id}")

        if self.TASK_CATEGORY is None:
            raise IrisExecutionError("Task category is not defined for IrisManager.")

        self._tq.submit(
            func=IrisManager.execute_iris_analysis,
            args=(analysis_id, raw_input),
            name=f"IrisAnalysis-{analysis_id}",
            category=self.TASK_CATEGORY,
            external_id=self.external_id_for(analysis_id),
        )

        return analysis_id

    def get_analysis(self, analysis_id: int) -> Optional[IrisAnalysis]:
        """Fetch the analysis ORM object by its primary key.

        Returns None (rather than raising) when the analysis does not
        exist, which lets callers distinguish "not found" from
        "not ready".
        """
        return read_repo(IrisAnalysisRepository).get_by_id(analysis_id)

    def get_analysis_status(self, analysis_id: int) -> Optional[str]:
        """Return the current lifecycle status string of an analysis.

        Checks the TaskQueue task first (fast path for running tasks) and
        falls back to the database record.  Returns None if the analysis
        ID is unknown.
        """
        status = self.task_status_of(analysis_id)
        if status is not None:
            return status

        analysis = self.get_analysis(analysis_id)
        if analysis:
            return analysis.status
        return None

    def get_analysis_progress(self, analysis_id: int) -> Optional[int]:
        """Return the progress percentage (0‑100) of a running analysis.

        Only meaningful for analyses in ``running`` state — returns None
        if no TaskQueue task is active (e.g. finished or pending).
        """
        return self.task_progress_of(analysis_id)

    def get_analysis_results(self, analysis_id: int) -> Dict[str, Any]:
        """Return the full analysis report for a finished analysis.

        The report includes the original headers, per-rule results,
        the total score, the textual verdict, and a flat list of
        actionable recommendations.

        Args:
            analysis_id: Primary key of the finished analysis.

        Returns:
            A dict with keys: analysisId, status, rawHeaders, totalScore,
            verdict, startedAt, finishedAt, user, rules, recommendations.

        Raises:
            IrisAnalysisNotFoundError: If *analysis_id* does not exist.
            IrisAnalysisNotReadyError: If the analysis is not yet
                ``finished`` (callers should poll ``/status`` first).
        """
        analysis = read_repo(IrisAnalysisRepository).get_by_id(analysis_id)
        if not analysis:
            raise IrisAnalysisNotFoundError(analysis_id)

        if analysis.status != "finished":
            raise IrisAnalysisNotReadyError(analysis_id, analysis.status)

        rules = read_repo(IrisRuleResultRepository).get_by_analysis(analysis_id)

        rules_data = [
            {
                "ruleName": r.rule_name,
                "category": r.category,
                "score": r.score,
                "verdict": r.verdict,
                "details": r.details,
                "recommendation": r.recommendation,
            }
            for r in rules
        ]

        recommendations = [
            r["recommendation"] for r in rules_data
            if r["recommendation"] is not None
        ]

        from src.modules.users import UserManager
        user = UserManager().get_user_by_id(analysis.user_id)
        username = user.username if user else "unknown"

        # Re-parsed on demand (same no-extra-column pattern as
        # get_analysis_path/get_analysis_iocs) purely to surface whether
        # this analysis unwrapped a "report phishing" forward — the
        # persisted rule results already reflect the unwrapped original.
        context = parse_raw_message(analysis.raw_headers or "")

        return {
            "analysisId": analysis.id,
            "title": analysis.title,
            "status": analysis.status,
            "rawHeaders": analysis.raw_headers,
            "totalScore": analysis.total_score,
            "verdict": analysis.verdict,
            "gateReasons": analysis.gate_reasons or [],
            "topSignals": self._top_signals(rules_data),
            "aiSummary": analysis.ai_summary,
            "unwrappedFromForward": context.unwrapped_from_forward,
            "wrapperFrom": context.wrapper_from or None,
            "wrapperSubject": context.wrapper_subject or None,
            "startedAt": isoformat_utc(analysis.started_at),
            "finishedAt": isoformat_utc(analysis.finished_at),
            "user": username,
            "rules": rules_data,
            "recommendations": recommendations,
        }

    @classmethod
    def _top_signals(cls, rules_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Rank the rules that contributed the most to the penalty.

        The subtractive model already stores a signed score per rule (0 or
        negative — see ``_run_analysis``'s clamp), so "most impactful" is
        simply "most negative". Surfaces the top N as ``{ruleName, category,
        score, index}`` so the report/UI can lead with what actually drove
        the verdict instead of making the analyst scan every rule. ``index``
        is the rule's position in ``rules_data`` so the UI can jump straight
        to its detail card.
        """
        negative = [
            (idx, r) for idx, r in enumerate(rules_data) if (r.get("score") or 0) < 0
        ]
        negative.sort(key=lambda pair: pair[1]["score"])
        return [
            {
                "ruleName": r["ruleName"],
                "category": r.get("category"),
                "score": r["score"],
                "index": idx,
            }
            for idx, r in negative[:cls._TOP_SIGNALS_LIMIT]
        ]

    def reanalyze(self, analysis_id: int, user_id: int) -> int:
        """Re-run analysis on a previously submitted email with the current ruleset.

        Rules added or changed after the original analysis never
        retroactively re-score it — this submits the *same* stored raw
        input (``analysis.raw_headers``, which holds the full ``.eml``
        text when one was originally provided, not just header lines) as
        a brand-new analysis. Deliberately not linked by a DB column back
        to the original (the ROADMAP marks that optional); the new
        title's suffix is the only trace of the relationship.

        Returns:
            The new IrisAnalysis primary key.
        """
        analysis = self.assert_analysis_ownership(analysis_id, user_id)
        title = f"{analysis.title} (reanálisis)" if analysis.title else f"Reanálisis de #{analysis_id}"
        return self.analyze(analysis.raw_headers, user_id, title=title)

    def get_analysis_path(self, analysis_id: int, user_id: int) -> Dict[str, Any]:
        """Return the parsed Received-chain path for an analysis.

        The path is derived on demand from ``raw_headers`` — no extra
        column is needed. Returns ``available: false`` for headers-only
        submissions (no full ``.eml`` means no Received chain to
        inspect).
        """
        analysis = self.assert_analysis_ownership(analysis_id, user_id)
        context = parse_raw_message(analysis.raw_headers or "")
        return {
            "analysisId": analysis.id,
            **build_path(context.received_headers),
        }

    _EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+")

    def get_analysis_iocs(self, analysis_id: int, user_id: int) -> Dict[str, Any]:
        """Extract Indicators of Compromise (IOCs) from an analysis.

        Derived on demand from ``raw_headers`` (same approach as
        ``get_analysis_path`` — no extra column needed) by re-parsing the
        message rather than scraping each rule's ad-hoc ``details`` dict:
        the parsed ``MessageContext`` already gives a uniform view of
        headers, body links and the Received chain regardless of which
        rules fired, so this stays correct as rules are added/changed.

        Returns:
            A dict with ``domains``, ``urls``, ``ips``, ``emails`` and
            ``hashes`` (SHA256 of every attachment, not just ones a rule
            flagged — an analyst pivoting to a threat-intel lookup wants
            the hash regardless of whether a heuristic fired) — each a
            sorted, deduplicated list of strings pivotable in an external
            tool (SIEM, threat-intel lookup, blocklist).
        """
        analysis = self.assert_analysis_ownership(analysis_id, user_id)
        context = parse_raw_message(analysis.raw_headers or "")

        domains: set[str] = set()
        emails: set[str] = set()
        urls: set[str] = set()
        ips: set[str] = set()
        hashes: set[str] = set()

        for header_name in ("from", "reply-to", "return-path"):
            raw_value = context.headers.get(header_name, "")
            domain = extract_domain(raw_value)
            if domain:
                domains.add(domain)
            email_match = self._EMAIL_RE.search(raw_value)
            if email_match:
                emails.add(email_match.group(0).lower())

        for link in context.links:
            href = (link.href or "").strip()
            if not href:
                continue
            urls.add(href)
            host = url_host(href)
            if host:
                domains.add(host)

        for line in context.received_headers:
            hop = parse_received_line(line)
            if hop.get("fromIp"):
                ips.add(hop["fromIp"])

        for att in context.attachments:
            if att.content:
                hashes.add(hashlib.sha256(att.content).hexdigest())

        return {
            "analysisId": analysis.id,
            "domains": sorted(domains),
            "urls": sorted(urls),
            "ips": sorted(ips),
            "emails": sorted(emails),
            "hashes": sorted(hashes),
        }

    def generate_ai_summary(self, analysis_id: int, user_id: int) -> None:
        """Trigger async generation of the AI executive narrative (IA1).

        Fire-and-forget: submits a TaskQueue job and returns immediately.
        The caller re-fetches ``get_analysis_results`` (``aiSummary``) to
        see the result once ``execute_ai_summary_generation`` finishes —
        there is no separate status to poll, matching how gate reasons
        and top signals are already just part of the main report.

        Raises:
            IrisAnalysisNotFoundError: If *analysis_id* does not exist or
                does not belong to *user_id*.
            IrisAnalysisNotReadyError: If the analysis is not ``finished``.
        """
        analysis = self.assert_analysis_ownership(analysis_id, user_id)
        if analysis.status != "finished":
            raise IrisAnalysisNotReadyError(analysis_id, analysis.status)

        self._tq.submit(
            func=IrisManager.execute_ai_summary_generation,
            args=(analysis_id,),
            name=f"AISummary-Analysis-{analysis_id}",
            category="iris.ai_summary",
            external_id=f"iris-ai-summary:{analysis_id}",
        )

    @staticmethod
    def execute_ai_summary_generation(analysis_id: int) -> None:
        """Entry point submitted to the TaskQueue for background AI narrative generation.

        Degrades cleanly on any failure (missing/misconfigured AI backend,
        circuit breaker open, malformed model response): logs the error
        and leaves ``ai_summary`` as ``NULL`` rather than failing the
        already-finished analysis it's attached to.
        """
        with job_context():
            try:
                report = IrisManager().get_analysis_results(analysis_id)
                summary = IrisAIWriter().generate(report)

                IrisManager()._update_analysis(analysis_id, ai_summary=summary)

                logger.info(f"AI summary generado para analysis {analysis_id}")
            except Exception as e:
                logger.error(f"Error generando AI summary para analysis {analysis_id}: {e}", exc_info=True)

    def cancel_analysis(self, analysis_id: int, user_id: int) -> bool:
        """Cancel a running or pending analysis.

        Signals the TaskQueue task to stop and marks the database record
        as ``cancelled``.

        Args:
            analysis_id: Primary key of the analysis to cancel.
            user_id:     Owner ID (must match the record's owner).

        Returns:
            True if the cancellation was successful.

        Raises:
            IrisAnalysisNotFoundError: If the analysis does not exist
                or does not belong to this user.
            IrisInvalidStateError: If the analysis is not in a
                cancellable state (``pending`` or ``running``).
        """
        analysis = self.assert_analysis_ownership(analysis_id, user_id)

        if analysis.status not in _CANCELLABLE_STATES:
            raise IrisInvalidStateError(
                f"Analysis {analysis_id} cannot be cancelled in state: {analysis.status}"
            )

        sq_task = self.find_task(analysis_id)
        if not sq_task:
            logger.warning(f"No active task found for analysis {analysis_id}")
            return False

        cancelled = self._tq.cancel(sq_task.id)
        if cancelled:
            self._update_analysis(analysis_id, status="cancelled", finished_at=utcnow_naive())
            logger.info(f"Analysis {analysis_id} cancelled by user {user_id}")
        return cancelled

    def delete_analysis(self, analysis_id: int) -> bool:
        """Permanently delete an analysis and its rule results.

        Cancels the analysis first if it is still running.

        Args:
            analysis_id: Primary key of the analysis to delete.

        Returns:
            True if the record was deleted.

        Raises:
            IrisAnalysisNotFoundError: If the analysis does not exist.
        """
        analysis = self.get_analysis(analysis_id)
        if not analysis:
            raise IrisAnalysisNotFoundError(analysis_id)

        if analysis.status in _CANCELLABLE_STATES:
            sq_task = self.find_task(analysis_id)
            if sq_task:
                self._tq.cancel(sq_task.id)

        with UnitOfWork() as uow:
            repo = IrisAnalysisRepository(uow)
            fresh = repo.get_by_id(analysis_id)
            if fresh:
                repo.delete(fresh)
                logger.info(f"Analysis {analysis_id} deleted")
                return True
        return False

    def get_analyses_for_user(self, user_id: int, page: int = 1, per_page: int = 10):
        """Return a paginated, formatted list of analyses for a user.

        Args:
            user_id:  Owner of the analyses.
            page:     1‑based page number.
            per_page: Items per page.

        Returns:
            Tuple of (formatted_results: list[dict], total_count: int).
        """
        items, total = read_repo(IrisAnalysisRepository).get_by_user_paginated(
            user_id, page, per_page
        )
        results = [
            {
                "analysisId": a.id,
                "title": a.title,
                "status": a.status,
                "totalScore": a.total_score,
                "verdict": a.verdict,
                "startedAt": isoformat_utc(a.started_at), # type: ignore
                "finishedAt": isoformat_utc(a.finished_at), # type: ignore
            }
            for a in items
        ]
        return results, total

    @classmethod
    def assert_analysis_ownership(cls, analysis_id: int, user_id: int) -> IrisAnalysis:
        """Verify that an analysis belongs to a given user.

        Raises IrisAnalysisNotFoundError when the analysis does not
        exist or the ownership check fails (same error for both cases
        to prevent ID enumeration).
        """
        return assert_owned(IrisAnalysisRepository, analysis_id, user_id, IrisAnalysisNotFoundError)

    # =========================================================================
    # INTERNAL
    # =========================================================================

    def _create_analysis_record(self, raw_headers: str, user_id: int, title: str | None = None) -> int:
        """Persist a new IrisAnalysis row in ``pending`` state."""
        analysis = IrisAnalysis(
            raw_headers=raw_headers,
            user_id=user_id,
            title=title.strip()[:120] if title and title.strip() else None,
            status="pending",
        )
        with UnitOfWork() as uow:
            repo = IrisAnalysisRepository(uow)
            repo.save(analysis)
            # Durable antes de encolar: el worker corre en otro proceso.
            uow.commit_for_handoff()
        return analysis.id # type: ignore

    @staticmethod
    def _validate_headers_pre(raw_headers: str) -> None:
        """Quick pre-check before creating a DB record.

        Counts lines that contain a colon — a rough proxy for valid
        header entries.  Rejects obviously non-header input early so
        we do not waste a DB row on garbage.
        """
        min_h = CR.get_iris_min_headers()
        count = sum(1 for line in raw_headers.split("\n") if ":" in line)
        if count < min_h:
            raise IrisInvalidInputError(
                "Se detectaron %d cabezeras v\u00e1lidas (m\u00ednimo: %d). "
                "El contenido no parece ser un bloque de cabeceras de correo v\u00e1lido." % (count, min_h)
            )

    @staticmethod
    def _validate_headers_parsed(parsed: dict) -> None:
        """Full validation after parsing — ensures the analysis runs on
        enough data to produce meaningful results."""
        min_h = CR.get_iris_min_headers()
        if len(parsed) < min_h:
            raise IrisInvalidInputError(
                "Tras parsear se obtuvieron %d cabeceras (m\u00ednimo: %d). "
                "El contenido no contiene suficientes cabeceras de correo v\u00e1lidas." % (len(parsed), min_h)
            )

    @staticmethod
    def execute_iris_analysis(analysis_id: int, raw_input: str) -> None:
        """Entry point submitted to the TaskQueue for background analysis."""
        IrisManager()._run_analysis(analysis_id, raw_input)

    def _run_analysis(self, analysis_id: int, raw_input: str) -> None:
        """Background task: execute all rules and persist results.

        This is the function submitted to the TaskQueue.  It:
        1. Marks the analysis as ``running``.
        2. Parses the raw text into both a flat headers dict (legacy
           rules) and a full ``MessageContext`` (body/links/attachments
           — Fase 2 rules). ``raw_input`` may be a headers-only block or
           a full ``.eml`` message; the context degrades gracefully to
           empty body/links/attachments in the former case.
        3. Iterates over every registered rule, dispatching ``headers``
           or ``context`` depending on each rule's ``needs_context`` flag,
           and collects RuleResults.
        4. Updates the TaskQueue task progress after each rule.
        5. Computes the total score and verdict.
        6. Persists the final state (``finished`` + score + verdict).

        If cancellation is detected between rule executions, the task
        exits early without saving results.
        """
        with job_context() as job:
            logger.info(f"Starting analysis {analysis_id}")

            try:
                self._update_analysis(analysis_id, status="running", started_at=utcnow_naive())
            except Exception as e:
                logger.error(f"Failed to mark analysis {analysis_id} as running: {e}", exc_info=True)
                self._fail_analysis(analysis_id)
                return

            # A single parse feeds both header-only and needs_context rules:
            # when raw_input is a "report phishing" forward (message/rfc822
            # attachment), context.headers already describes the *unwrapped
            # original*, not the forwarding envelope — a separate
            # parse_raw_headers(raw_input) here would silently re-introduce
            # the envelope's headers and analyze the wrong message.
            context = parse_raw_message(raw_input)
            headers = context.headers
            self._validate_headers_parsed(headers)

            rules_defs = iris_rules.get_rules()
            total_rules = len(rules_defs)
            results: List[RuleResult] = []
            named_results: Dict[str, RuleResult] = {}

            for idx, rule_def in enumerate(rules_defs):
                if job.cancelled():
                    logger.info(f"Analysis {analysis_id} was cancelled")
                    return

                try:
                    rule_input = context if rule_def.get("needs_context") else headers
                    result = rule_def["func"](rule_input)
                except Exception as e:
                    logger.error(f"Rule '{rule_def['name']}' failed for analysis {analysis_id}: {e}", exc_info=True)
                    result = RuleResult(
                        score=0, verdict="error",
                        details={"error": str(e)},
                        recommendation=f"La regla '{rule_def['name']}' falló durante la ejecución.",
                    )

                # Subtractive contract: a rule can only *subtract*. Whatever a
                # rule returns on a pass (historically +5/+3/+1 "credibility"
                # bonuses), the score it contributes — and the score shown in
                # the UI — is clamped to <= 0. Passing a rule means "no
                # deduction", never a bonus. The verdict/details are untouched.
                result = replace(result, score=min(0.0, float(result.score)))

                self._persist_rule_result(analysis_id, rule_def, result, idx)
                results.append(result)
                named_results[rule_def["name"]] = result

                progress = int(((idx + 1) / total_rules) * 100)
                sq_task = self.find_task(analysis_id)
                if sq_task:
                    job.progress(progress)

            total_score = self._aggregate_score(results)
            base_verdict = self._determine_verdict(total_score)
            verdict, gate_reasons = self._apply_verdict_gates(base_verdict, named_results)

            try:
                self._update_analysis(
                    analysis_id,
                    status="finished",
                    total_score=total_score,
                    verdict=verdict,
                    gate_reasons=gate_reasons,
                    finished_at=utcnow_naive(),
                )
            except Exception as e:
                logger.error(f"Failed to finalise analysis {analysis_id}: {e}", exc_info=True)
                self._fail_analysis(analysis_id)
                return

            logger.info(f"Analysis {analysis_id} completed: score={total_score}, verdict={verdict}")

    def _persist_rule_result(self, analysis_id: int, rule_def: dict,
                              result: RuleResult, position: int) -> None:
        """Save a single rule's outcome to the IrisRuleResult table.

        Failures are logged but do not interrupt the analysis — the
        rule is treated as a neutral (zero-score) result.
        """
        try:
            with UnitOfWork() as uow:
                repo = IrisRuleResultRepository(uow)
                result = IrisRuleResult(
                    analysis_id=analysis_id,
                    rule_name=rule_def["name"],
                    category=rule_def["category"],
                    score=result.score,
                    verdict=result.verdict,
                    details=result.details,
                    recommendation=result.recommendation,
                    position=position,
                )
                repo.save(result)
        except Exception as e:
            logger.error(f"Failed to persist rule result for analysis {analysis_id}: {e}", exc_info=True)

    @staticmethod
    def _aggregate_score(results: List[RuleResult]) -> float:
        """Combine per-rule results into a single 0–100 score.

        Subtractive model: start at :data:`_CEILING` and add only the
        *negative* part of each rule's score (``min(0, score)``), so passing
        a rule never inflates the total. Clamped to ``[0, _CEILING]``.
        """
        penalties = sum(min(0.0, r.score) for r in results)
        return max(0.0, _CEILING + penalties)

    def _determine_verdict(self, total_score: float) -> str:
        """Map a numeric 0–100 score to a textual verdict.

        Thresholds come from ``SecOpsConfig.json`` (0–100 subtractive scale):
            - ``iris.legitimate_threshold`` (default 80)
            - ``iris.suspicious_threshold``  (default 55)

        A clean message stays near 100; each failing rule subtracts. This is
        only the numeric baseline — high-confidence findings can still push
        the verdict to a worse category via :meth:`_apply_verdict_gates`.
        """
        legitimate = CR.get_iris_legitimate_threshold()
        suspicious = CR.get_iris_suspicious_threshold()

        if total_score >= legitimate:
            return "Legitimate"
        if total_score >= suspicious:
            return "Suspicious"
        return "Phishing"

    @staticmethod
    def _extract_verdict_signals(named_results: Dict[str, RuleResult]) -> Dict[str, Any]:
        """Reduce the per-rule results to the named booleans the gates need.

        Centralises all the ``named_results.get(...)`` lookups so
        :meth:`_evaluate_gates` can stay a pure boolean-combination function.
        """
        def res(name: str) -> Optional[RuleResult]:
            return named_results.get(name)

        def verdict_is(name: str, *verdicts: str) -> bool:
            r = res(name)
            return r is not None and r.verdict in verdicts

        # ARC (RFC 8617): a legitimate forwarding intermediary (mailing
        # list, forwarder) that validated ("cv=pass") the original
        # SPF/DKIM/DMARC results before its own relaying broke them.
        # Genuine ARC-validated forwards must not trip the SPF/DMARC/
        # alignment gates that exist to catch spoofing — that's exactly
        # what those three signals are suppressed for below. "cv=fail"
        # (the chain itself declares a prior hop broken) is its own gate,
        # see D7 in ROADMAP.md.
        arc = res("ARC Chain")
        arc_pass = arc is not None and arc.verdict == "pass"
        arc_fail = arc is not None and arc.verdict == "fail"

        spf_fail = verdict_is("SPF", "fail", "hardfail") and not arc_pass
        dmarc_fail = verdict_is("DMARC", "fail") and not arc_pass
        align_fail = verdict_is("Domain Alignment", "fail") and not arc_pass

        # D1 (quishing): a QR code that decodes to a suspicious URL is a
        # high-confidence signal on its own -- a QR is specifically a way
        # to smuggle a URL past every text/link-based check, so if one
        # still trips the same shared.analyze_url() heuristics as a real
        # body link would, that's deliberate evasion, not noise.
        qr_links = res("QR Code Links")
        qr_suspicious = qr_links is not None and qr_links.verdict == "fail"

        spoof = res("Display Name Spoofing")
        spoof_any = spoof is not None and spoof.verdict == "spoof"
        spoof_free = spoof_any and bool(spoof.details.get("is_free_provider"))

        bec = res("BEC Wire Transfer Pattern")
        bec_fail = bec is not None and bec.verdict == "fail"
        # A financial-action request whose sender (or reply target) sits on a
        # free webmail provider is the textbook CEO-fraud / payroll-diversion
        # pattern — it passes SPF/DKIM/DMARC trivially, so only the body and
        # the free-provider tell give it away.
        bec_free = bec_fail and (
            is_free_provider(bec.details.get("from_domain"))
            or is_free_provider(bec.details.get("reply_domain"))
        )

        body_links = res("Body Links")
        link_types = (body_links.details.get("types") or []) if body_links is not None else []
        body_links_failed = body_links is not None and body_links.verdict == "fail"
        cloaked_link_any = body_links_failed and "cloaked_link" in link_types
        link_impersonation = body_links_failed and "brand_impersonation" in link_types

        path_anomaly = res("Received Path Anomaly")
        path_anomaly_fail = path_anomaly is not None and path_anomaly.verdict == "fail"
        path_signals = (
            (path_anomaly.details.get("unique_signals") or [])
            if path_anomaly is not None else []
        )

        return {
            "spf_fail": spf_fail,
            "dmarc_fail": dmarc_fail,
            "align_fail": align_fail,
            "arc_fail": arc_fail,
            "qr_suspicious": qr_suspicious,
            "lookalike": verdict_is("Lookalike Sender Domain", "fail"),
            "attach": verdict_is("Suspicious Attachments", "fail"),
            "replyfree": verdict_is("Reply-To Free Provider", "fail"),
            "spoof_any": spoof_any,
            "spoof_free": spoof_free,
            "alarming_strong": verdict_is("Alarming Keywords", "alarming_high", "alarming_medium"),
            "cloaked_link_any": cloaked_link_any,
            "link_impersonation": link_impersonation,
            "body_links_fail": verdict_is("Body Links", "fail"),
            "body_content_fail": verdict_is("Body Content", "fail"),
            "received_chain_fail": verdict_is("Received Chain", "fail"),
            "path_tls_downgrade": path_anomaly_fail and "tls_downgrade" in path_signals,
            "path_long_chain": path_anomaly_fail and "long_chain" in path_signals,
            "auth_fail": spf_fail or dmarc_fail or align_fail,
            "bec_fail": bec_fail,
            "bec_free": bec_free,
        }

    @staticmethod
    def _evaluate_gates(base_verdict: str, signals: Dict[str, Any]) -> tuple[str, list[str]]:
        """Apply the high-confidence gates to ``signals`` and return the result.

        Pure function: given the extracted signals, raises ``base_verdict`` to
        a worse category whenever a gate fires, never improves it.

        Returns:
            Tuple of (final verdict, list of human-readable triggered reasons).
        """
        ceiling = _VERDICT_SEVERITY[base_verdict]
        triggered: list[str] = []

        def gate(condition: bool, level: str, reason: str) -> None:
            nonlocal ceiling
            if condition:
                triggered.append(reason)
                ceiling = max(ceiling, _VERDICT_SEVERITY[level])

        spf_fail = signals["spf_fail"]
        dmarc_fail = signals["dmarc_fail"]
        align_fail = signals["align_fail"]
        spoof_any = signals["spoof_any"]
        alarming_strong = signals["alarming_strong"]
        attach = signals["attach"]
        body_links_fail = signals["body_links_fail"]
        auth_fail = signals["auth_fail"]

        # Single high-confidence indicators.
        gate(signals["lookalike"], "Phishing", "lookalike sender domain")
        gate(signals["spoof_free"], "Phishing", "brand impersonation from free provider")
        gate(signals["cloaked_link_any"], "Phishing", "cloaked body link (visible domain differs from href)")
        gate(signals["link_impersonation"], "Phishing", "body link impersonates a brand/sender via subdomain trick")
        gate(signals["qr_suspicious"], "Phishing", "QR code decodes to a suspicious URL (quishing)")
        gate(spoof_any, "Suspicious", "display-name brand spoofing")
        gate(align_fail, "Suspicious", "SPF/DKIM not aligned with From")
        gate(attach, "Suspicious", "dangerous attachment")
        gate(spf_fail or dmarc_fail, "Suspicious", "SPF/DMARC failure")
        gate(signals["replyfree"], "Suspicious", "reply target is free webmail")
        gate(body_links_fail, "Suspicious", "suspicious body links")
        gate(signals["body_content_fail"], "Suspicious", "phishing phrasing or hidden text in body")
        gate(signals["received_chain_fail"], "Suspicious", "Received chain anomaly")
        gate(signals["bec_fail"], "Suspicious", "BEC financial-action request in body")
        gate(signals["arc_fail"], "Suspicious", "ARC chain declares a previous hop's authentication broken (cv=fail)")

        # Combinations that escalate to Phishing.
        gate(signals["bec_free"], "Phishing",
             "BEC financial-action request from a free-webmail sender/reply target")
        gate(auth_fail and (spoof_any or alarming_strong), "Phishing",
             "authentication failure combined with impersonation/urgency")
        gate(attach and (auth_fail or spoof_any), "Phishing",
             "dangerous attachment combined with authentication failure or spoofing")
        gate(body_links_fail and (auth_fail or spoof_any), "Phishing",
             "suspicious body links combined with authentication failure or spoofing")
        gate(signals["path_tls_downgrade"] and auth_fail, "Suspicious",
             "TLS downgrade in Received chain combined with authentication failure")
        gate(signals["path_long_chain"] and auth_fail, "Suspicious",
             "Unusually long Received chain combined with authentication failure")

        return _VERDICT_ORDER[ceiling], triggered

    @classmethod
    def _apply_verdict_gates(cls, base_verdict: str,
                             named_results: Dict[str, RuleResult]) -> tuple[str, list[str]]:
        """Override the additive verdict when high-confidence signals fire.

        The additive sum can be dominated by many small positive checks (and,
        historically, by a large authentication bonus), letting a few strong
        phishing indicators get "bought back" into a Legitimate verdict.  This
        gate enforces a *minimum severity* for those indicators: a verdict can
        only be pushed toward a worse category, never improved.

        Args:
            base_verdict: The verdict derived purely from the total score.
            named_results: Map of rule name -> its RuleResult.

        Returns:
            Tuple of (final verdict, human-readable triggered gate reasons).
            The reasons list is persisted with the analysis so the report can
            explain WHY the verdict is what it is.
        """
        signals = cls._extract_verdict_signals(named_results)
        final, triggered = cls._evaluate_gates(base_verdict, signals)

        if triggered and final != base_verdict:
            logger.info("Verdict gated %s -> %s (%s)", base_verdict, final, "; ".join(triggered))
        return final, triggered

    def _update_analysis(self, analysis_id: int, **fields: Any) -> bool:
        """Aplica ``fields`` sobre el IrisAnalysis si aún existe y persiste.

        Encapsula el patrón UnitOfWork + get_by_id + setattr + update que
        cada transición de estado del análisis (running/finished/failed/
        cancelled/ai_summary) repetía por separado. Devuelve True si el
        registro existía y se actualizó, False si ya no existe.
        """
        with UnitOfWork() as uow:
            repo = IrisAnalysisRepository(uow)
            fresh = repo.get_by_id(analysis_id)
            if fresh is None:
                return False
            for attr, value in fields.items():
                setattr(fresh, attr, value)
            repo.update(fresh)
            return True

    @classmethod
    def reconcile_orphaned_analyses(cls) -> int:
        """Marca como ``failed`` los análisis huérfanos tras un apagado abrupto.

        Espejo de ``ScanManager.reconcile_orphaned_scans`` (Themis): si el
        proceso se mata mientras un análisis está en pending/running, no queda
        tarea viva en TaskQueue que lo actualice tras reiniciar, y el registro
        se queda así para siempre. Se llama una vez al arrancar la API.

        Returns:
            Número de análisis marcados como failed.
        """
        tq = TaskQueue.get_instance()
        fixed = 0
        with UnitOfWork() as uow:
            repo = IrisAnalysisRepository(uow)
            for analysis in repo.get_active_analyses():
                external_id = f"{cls.EXTERNAL_ID_PREFIX}{analysis.id}"
                task = tq.get_task_by_external_id(external_id, cls.TASK_CATEGORY)
                if task is not None and str(task.status) == "pending":
                    continue
                analysis.status = "failed"
                analysis.finished_at = utcnow_naive()
                repo.update(analysis)
                fixed += 1
        return fixed

    def _fail_analysis(self, analysis_id: int) -> None:
        """Mark an analysis as ``failed`` with a finished timestamp."""
        try:
            self._update_analysis(analysis_id, status="failed", finished_at=utcnow_naive())
        except Exception as e:
            logger.error(f"Failed to mark analysis {analysis_id} as failed: {e}", exc_info=True)

    def _is_cancelled(self, analysis_id: int) -> bool:
        """Check whether the analysis has been cancelled since we started.

        Reads from both the TaskQueue state and the database; returns True
        if either indicates ``cancelled``.
        """
        if self.task_status_of(analysis_id) == "cancelled":
            return True
        try:
            with UnitOfWork() as uow:
                repo = IrisAnalysisRepository(uow)
                analysis = repo.get_by_id(analysis_id)
                if analysis and analysis.status == "cancelled":
                    return True
        except Exception as e:
            logger.warning(f"Error checking cancellation for analysis {analysis_id}", exc_info=True)
        return False # type: ignore


class IrisReportManager:
    """Manager for IrisDocument lifecycle and async PDF report generation.

    Mirrors ``ThemisReportManager``: creates an ``IrisDocument`` row in
    ``running`` state, submits a TaskQueue job (category ``"iris.report"``)
    that renders the PDF via :class:`IrisPDFCreator`, and exposes the
    CRUD/ownership operations the endpoints need.
    """

    def __init__(self, task_queue: ITaskQueue | None = None) -> None:
        self._tq: ITaskQueue = task_queue or TaskQueue.get_instance()

    @staticmethod
    def _create_document(analysis: IrisAnalysis) -> int:
        """Create an IrisDocument for a finished analysis and return its ID."""
        with UnitOfWork() as uow:
            document = IrisDocument(
                analysis_id=analysis.id,
                document_type="iris",
                filename="",
                format="pdf",
                status="running",
                user_id=analysis.user_id,
                verdict=analysis.verdict,
                is_ai_generated=0,
            )
            IrisReportRepository(uow).save(document)
            # Durable antes de encolar: el worker corre en otro proceso.
            uow.commit_for_handoff()
        return document.id  # type: ignore

    def get_document_by_id(self, document_id: int) -> Optional[IrisDocument]:
        """Retrieve an IrisDocument by its primary key."""
        return read_repo(IrisReportRepository).get_by_id(document_id)

    def get_latest_document_by_analysis_id(self, analysis_id: int) -> Optional[IrisDocument]:
        """Retrieve the most recently created document for an analysis."""
        return read_repo(IrisReportRepository).get_latest_document(analysis_id)

    def get_documents_for_user(self, user_id: int) -> List[IrisDocument]:
        """Retrieve all documents belonging to a user."""
        return read_repo(IrisReportRepository).get_documents_by_user(user_id)

    def get_documents_by_analysis_id(self, analysis_id: int) -> List[IrisDocument]:
        """Retrieve all documents generated for a specific analysis."""
        return read_repo(IrisReportRepository).get_documents_by_analysis(analysis_id)

    def delete_document(self, document_id: int) -> bool:
        """Delete a document and its associated file on disk.

        Raises:
            DocumentNotFoundError: If the document was not found.
        """
        with UnitOfWork() as uow:
            doc_repo = IrisReportRepository(uow)
            doc = doc_repo.get_by_id(document_id)
            if not doc:
                raise DocumentNotFoundError(document_id)

            if doc.filename and os.path.exists(doc.filename):  # type: ignore
                try:
                    os.remove(doc.filename)  # type: ignore
                except (OSError, IOError) as e:
                    logger.warning(f"No se pudo eliminar el archivo {doc.filename}: {e}", exc_info=True)

            doc_repo.delete(doc)
        return True

    def assert_document_ownership(self, document_id: int, user_id: int) -> IrisDocument:
        """Verify document ownership and return the document.

        Raises:
            DocumentNotFoundError: If document not found or not owned by
                user (same error for both cases to prevent ID enumeration).
        """
        return assert_owned(IrisReportRepository, document_id, user_id, DocumentNotFoundError)

    def generate_report(self, analysis_id: int, user_id: int) -> int:
        """Create an IrisDocument and start async PDF generation.

        Args:
            analysis_id: Primary key of the finished analysis.
            user_id:     Owner of the analysis (ownership is verified here).

        Returns:
            Primary key of the created IrisDocument.

        Raises:
            IrisAnalysisNotFoundError: If the analysis does not exist or
                is not owned by ``user_id``.
            IrisAnalysisNotReadyError: If the analysis is not ``finished``.
        """
        analysis = IrisManager.assert_analysis_ownership(analysis_id, user_id)
        if analysis.status != "finished":
            raise IrisAnalysisNotReadyError(analysis_id, analysis.status)

        doc_id = self._create_document(analysis)

        self._tq.submit(
            func=IrisReportManager.execute_report_generation,
            args=(doc_id, analysis_id),
            name=f"PDFGeneration-Analysis-{analysis_id}",
            category="iris.report",
            external_id=f"iris-doc:{doc_id}",
        )
        return doc_id  # type: ignore

    @staticmethod
    def execute_report_generation(doc_id: int, analysis_id: int) -> None:
        """Entry point submitted to the TaskQueue for background PDF generation."""
        with job_context():
            IrisReportManager()._generate_pdf_async(doc_id, analysis_id)

    def _generate_pdf_async(self, document_id: int, analysis_id: int) -> None:
        """Generate the PDF in a background thread and update document status."""
        try:
            report = IrisManager().get_analysis_results(analysis_id)

            analysis = read_repo(IrisAnalysisRepository).get_by_id(analysis_id)
            path = None
            if analysis is not None:
                context = parse_raw_message(analysis.raw_headers or "")
                path = {"analysisId": analysis_id, **build_path(context.received_headers)}

            pdf_creator = IrisPDFCreator(report=report, path=path)
            pdf_path = pdf_creator.print_pdf()

            with UnitOfWork() as uow:
                doc = IrisReportRepository(uow).get_by_id(document_id)
                if doc:
                    doc.filename = pdf_path  # type: ignore
                    doc.status = "done"  # type: ignore
                    doc.generated_at = utcnow_naive()  # type: ignore

            logger.info(f"PDF generado exitosamente para documento {document_id}")

        except Exception as e:
            logger.error(f"Error generando PDF para documento {document_id}: {e}", exc_info=True)
            self._update_document_status(document_id, "error")
            # Re-lanzar: sin esto el job termina "con éxito" y el callback de RQ
            # lo registra como COMPLETED pese a que el documento quedó en error.
            # Al propagar, RQ lo marca FAILED y estado de tarea y documento
            # coinciden.
            raise

    def _update_document_status(self, document_id: int, status: str) -> None:
        """Update document status in database."""
        try:
            with UnitOfWork() as uow:
                doc = IrisReportRepository(uow).get_by_id(document_id)
                if doc:
                    doc.status = status  # type: ignore
        except Exception:
            logger.exception(f"Error updating document status for document {document_id}")
