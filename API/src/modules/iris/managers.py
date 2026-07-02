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

import os
import logging
from dataclasses import replace
from datetime import datetime
from typing import Any, Dict, List, Optional

import src.modules.system.config_reading as CR
from src.modules.aegis.exceptions import DocumentNotFoundError
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import get_db_session
from src.modules.system.taskqueue import ITaskQueue, TaskQueue, TaskTrackingMixin, job_context

from .exceptions import (
    IrisAnalysisNotFoundError,
    IrisAnalysisNotReadyError,
    IrisInvalidInputError,
    IrisInvalidStateError,
)
from .model import IrisAnalysis, IrisDocument, IrisRuleResult
from .repositories import IrisAnalysisRepository, IrisReportRepository, IrisRuleResultRepository
from .services.rules import iris_rules, RuleResult
from .services.shared import is_free_provider
from .services import parse_raw_headers, parse_raw_message
from .services.parsers import build_path
from .services.reports import IrisPDFCreator


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
        session = get_db_session()
        return IrisAnalysisRepository(session=session).get_by_id(analysis_id)

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
        session = get_db_session()
        analysis = IrisAnalysisRepository(session=session).get_by_id(analysis_id)
        if not analysis:
            raise IrisAnalysisNotFoundError(analysis_id)

        if analysis.status != "finished":
            raise IrisAnalysisNotReadyError(analysis_id, analysis.status)

        rules_repo = IrisRuleResultRepository(session=session)
        rules = rules_repo.get_by_analysis(analysis_id)

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

        return {
            "analysisId": analysis.id,
            "title": analysis.title,
            "status": analysis.status,
            "rawHeaders": analysis.raw_headers,
            "totalScore": analysis.total_score,
            "verdict": analysis.verdict,
            "startedAt": analysis.started_at.isoformat() if analysis.started_at else None,
            "finishedAt": analysis.finished_at.isoformat() if analysis.finished_at else None,
            "user": username,
            "rules": rules_data,
            "recommendations": recommendations,
        }

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
            with UnitOfWork() as uow:
                repo = IrisAnalysisRepository(uow)
                fresh = repo.get_by_id(analysis_id)
                if fresh:
                    fresh.status = "cancelled"
                    fresh.finished_at = datetime.now()
                    repo.update(fresh)
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
        session = get_db_session()
        items, total = IrisAnalysisRepository(session=session).get_by_user_paginated(
            user_id, page, per_page
        )
        results = [
            {
                "analysisId": a.id,
                "title": a.title,
                "status": a.status,
                "totalScore": a.total_score,
                "verdict": a.verdict,
                "startedAt": a.started_at.isoformat() if a.started_at else None, # type: ignore
                "finishedAt": a.finished_at.isoformat() if a.finished_at else None, # type: ignore
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
        session = get_db_session()
        analysis = IrisAnalysisRepository(session=session).get_by_id(analysis_id)
        if not analysis or analysis.user_id != user_id:
            raise IrisAnalysisNotFoundError(analysis_id)
        return analysis

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
                with UnitOfWork() as uow:
                    repo = IrisAnalysisRepository(uow)
                    fresh = repo.get_by_id(analysis_id)
                    if fresh:
                        fresh.status = "running" # type: ignore
                        fresh.started_at = datetime.now() # type: ignore
                        repo.update(fresh)
            except Exception as e:
                logger.error(f"Failed to mark analysis {analysis_id} as running: {e}", exc_info=True)
                self._fail_analysis(analysis_id)
                return

            headers = parse_raw_headers(raw_input)
            self._validate_headers_parsed(headers)
            context = parse_raw_message(raw_input)

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
            verdict = self._apply_verdict_gates(base_verdict, named_results)

            try:
                with UnitOfWork() as uow:
                    repo = IrisAnalysisRepository(uow)
                    fresh = repo.get_by_id(analysis_id)
                    if fresh:
                        fresh.status = "finished" # type: ignore
                        fresh.total_score = total_score # type: ignore
                        fresh.verdict = verdict # type: ignore
                        fresh.finished_at = datetime.now() # type: ignore
                        repo.update(fresh)
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
                rr = IrisRuleResult(
                    analysis_id=analysis_id,
                    rule_name=rule_def["name"],
                    category=rule_def["category"],
                    score=result.score,
                    verdict=result.verdict,
                    details=result.details,
                    recommendation=result.recommendation,
                    position=position,
                )
                repo.save(rr)
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

        spf_fail = verdict_is("SPF", "fail", "hardfail")
        dmarc_fail = verdict_is("DMARC", "fail")
        align_fail = verdict_is("Domain Alignment", "fail")

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
        gate(spoof_any, "Suspicious", "display-name brand spoofing")
        gate(align_fail, "Suspicious", "SPF/DKIM not aligned with From")
        gate(attach, "Suspicious", "dangerous attachment")
        gate(spf_fail or dmarc_fail, "Suspicious", "SPF/DMARC failure")
        gate(signals["replyfree"], "Suspicious", "reply target is free webmail")
        gate(body_links_fail, "Suspicious", "suspicious body links")
        gate(signals["body_content_fail"], "Suspicious", "phishing phrasing or hidden text in body")
        gate(signals["received_chain_fail"], "Suspicious", "Received chain anomaly")
        gate(signals["bec_fail"], "Suspicious", "BEC financial-action request in body")

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
                             named_results: Dict[str, RuleResult]) -> str:
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
            The final verdict after applying all gates.
        """
        signals = cls._extract_verdict_signals(named_results)
        final, triggered = cls._evaluate_gates(base_verdict, signals)

        if triggered and final != base_verdict:
            logger.info("Verdict gated %s -> %s (%s)", base_verdict, final, "; ".join(triggered))
        return final

    def _fail_analysis(self, analysis_id: int) -> None:
        """Mark an analysis as ``failed`` with a finished timestamp."""
        try:
            with UnitOfWork() as uow:
                repo = IrisAnalysisRepository(uow)
                fresh = repo.get_by_id(analysis_id)
                if fresh:
                    fresh.status = "failed" # type: ignore
                    fresh.finished_at = datetime.now() # type: ignore
                    repo.update(fresh)
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

    Mirrors ``SentinelReportManager``: creates an ``IrisDocument`` row in
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
        return document.id  # type: ignore

    def get_document_by_id(self, document_id: int) -> Optional[IrisDocument]:
        """Retrieve an IrisDocument by its primary key."""
        session = get_db_session()
        return IrisReportRepository(session=session).get_by_id(document_id)

    def get_latest_document_by_analysis_id(self, analysis_id: int) -> Optional[IrisDocument]:
        """Retrieve the most recently created document for an analysis."""
        session = get_db_session()
        return IrisReportRepository(session=session).get_latest_document(analysis_id)

    def get_documents_for_user(self, user_id: int) -> List[IrisDocument]:
        """Retrieve all documents belonging to a user."""
        session = get_db_session()
        return IrisReportRepository(session=session).get_documents_by_user(user_id)

    def get_documents_by_analysis_id(self, analysis_id: int) -> List[IrisDocument]:
        """Retrieve all documents generated for a specific analysis."""
        session = get_db_session()
        return IrisReportRepository(session=session).get_documents_by_analysis(analysis_id)

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
        session = get_db_session()
        doc = IrisReportRepository(session=session).get_by_id(document_id)
        if not doc or doc.user_id != user_id:  # type: ignore
            raise DocumentNotFoundError(document_id)
        return doc

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
        IrisReportManager()._generate_pdf_async(doc_id, analysis_id)

    def _generate_pdf_async(self, document_id: int, analysis_id: int) -> None:
        """Generate the PDF in a background thread and update document status."""
        try:
            report = IrisManager().get_analysis_results(analysis_id)

            session = get_db_session()
            analysis = IrisAnalysisRepository(session=session).get_by_id(analysis_id)
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
                    doc.generated_at = datetime.utcnow()  # type: ignore

            logger.info(f"PDF generado exitosamente para documento {document_id}")

        except Exception as e:
            logger.error(f"Error generando PDF para documento {document_id}: {e}", exc_info=True)
            self._update_document_status(document_id, "error")

    def _update_document_status(self, document_id: int, status: str) -> None:
        """Update document status in database."""
        try:
            with UnitOfWork() as uow:
                doc = IrisReportRepository(uow).get_by_id(document_id)
                if doc:
                    doc.status = status  # type: ignore
        except Exception:
            logger.exception(f"Error updating document status for document {document_id}")
