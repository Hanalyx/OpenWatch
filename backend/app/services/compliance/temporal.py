"""
Temporal Compliance Service

Service for point-in-time compliance posture queries and drift detection.

Enables queries like: "What was the posture on March 14?"
Supports compliance drift detection over time.

Part of Phase 2: Temporal Compliance (Kensa Integration Plan)

OS Claim Enabled:
    "Compliance posture is queryable at any point in time"
"""

import json
import logging
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from sqlalchemy import and_, func, text
from sqlalchemy.orm import Session

from app.database import Host, PostureSnapshot, Scan, ScanResult
from app.schemas.posture_schemas import (
    DriftAnalysisResponse,
    DriftEvent,
    GroupDriftResponse,
    GroupDriftRuleSummary,
    PostureHistoryResponse,
    PostureResponse,
    RuleState,
    SeverityBreakdown,
    ValueDriftEvent,
)

logger = logging.getLogger(__name__)


class TemporalComplianceService:
    """
    Service for point-in-time compliance posture queries.

    Enables queries like: "What was the posture on March 14?"
    Supports compliance drift detection over time.

    Features:
        - Current posture from latest scan results
        - Historical posture from daily snapshots
        - Drift detection between time periods
        - Automatic daily snapshot creation

    Usage:
        service = TemporalComplianceService(db)
        posture = await service.get_posture(host_id)
        posture_march14 = await service.get_posture(host_id, as_of=date(2026, 3, 14))
    """

    def __init__(self, db: Session):
        """
        Initialize the Temporal Compliance Service.

        Args:
            db: SQLAlchemy database session
        """
        self._db = db

    def get_posture(
        self,
        host_id: UUID,
        as_of: Optional[date] = None,
        include_rule_states: bool = False,
    ) -> Optional[PostureResponse]:
        """
        Get compliance posture for a host.

        Args:
            host_id: Target host UUID
            as_of: Optional date for historical query (None = current)
            include_rule_states: Include per-rule state details

        Returns:
            PostureResponse with compliance scores and rule states
        """
        if as_of:
            return self._get_historical_posture(host_id, as_of, include_rule_states)
        return self._get_current_posture(host_id, include_rule_states)

    def _get_current_posture(
        self,
        host_id: UUID,
        include_rule_states: bool = False,
    ) -> Optional[PostureResponse]:
        """Get current posture from latest scan results."""
        # Find the latest completed scan for this host
        latest_scan = (
            self._db.query(Scan)
            .filter(
                and_(
                    Scan.host_id == host_id,
                    Scan.status == "completed",
                )
            )
            .order_by(Scan.completed_at.desc())
            .first()
        )

        if not latest_scan:
            logger.debug("No completed scans found for host %s", host_id)
            return None

        # Get scan results
        scan_result = self._db.query(ScanResult).filter(ScanResult.scan_id == latest_scan.id).first()

        if not scan_result:
            logger.debug("No scan results found for scan %s", latest_scan.id)
            return None

        # Build severity breakdown
        severity_breakdown = {
            "critical": SeverityBreakdown(
                passed=scan_result.severity_critical_passed or 0,
                failed=scan_result.severity_critical_failed or 0,
            ),
            "high": SeverityBreakdown(
                passed=scan_result.severity_high_passed or 0,
                failed=scan_result.severity_high_failed or 0,
            ),
            "medium": SeverityBreakdown(
                passed=scan_result.severity_medium_passed or 0,
                failed=scan_result.severity_medium_failed or 0,
            ),
            "low": SeverityBreakdown(
                passed=scan_result.severity_low_passed or 0,
                failed=scan_result.severity_low_failed or 0,
            ),
        }

        # Calculate compliance score
        total_rules = scan_result.total_rules or 0
        passed_rules = scan_result.passed_rules or 0
        compliance_score = (passed_rules / total_rules * 100) if total_rules > 0 else 0.0

        return PostureResponse(
            host_id=host_id,
            snapshot_date=latest_scan.completed_at or datetime.now(timezone.utc),
            is_current=True,
            total_rules=total_rules,
            passed=passed_rules,
            failed=scan_result.failed_rules or 0,
            error_count=scan_result.error_rules or 0,
            not_applicable=scan_result.not_applicable_rules or 0,
            compliance_score=round(compliance_score, 2),
            severity_breakdown=severity_breakdown,
            source_scan_id=latest_scan.id,
            rule_states=None,  # Would need to query scan findings for rule-level detail
        )

    def _get_historical_posture(
        self,
        host_id: UUID,
        as_of: date,
        include_rule_states: bool = False,
    ) -> Optional[PostureResponse]:
        """Get historical posture from snapshot table."""
        snapshot = (
            self._db.query(PostureSnapshot)
            .filter(
                and_(
                    PostureSnapshot.host_id == host_id,
                    func.date(PostureSnapshot.snapshot_date) == as_of,
                )
            )
            .first()
        )

        if not snapshot:
            logger.debug("No snapshot found for host %s on %s", host_id, as_of)
            return None

        # Build severity breakdown
        severity_breakdown = {
            "critical": SeverityBreakdown(
                passed=snapshot.severity_critical_passed or 0,
                failed=snapshot.severity_critical_failed or 0,
            ),
            "high": SeverityBreakdown(
                passed=snapshot.severity_high_passed or 0,
                failed=snapshot.severity_high_failed or 0,
            ),
            "medium": SeverityBreakdown(
                passed=snapshot.severity_medium_passed or 0,
                failed=snapshot.severity_medium_failed or 0,
            ),
            "low": SeverityBreakdown(
                passed=snapshot.severity_low_passed or 0,
                failed=snapshot.severity_low_failed or 0,
            ),
        }

        # Build rule states if requested
        rule_states = None
        if include_rule_states and snapshot.rule_states:
            rule_states = {
                rule_id: RuleState(
                    rule_id=rule_id,
                    status=state.get("status", "unknown"),
                    severity=state.get("severity", "unknown"),
                    title=state.get("title"),
                    category=state.get("category"),
                    actual=state.get("actual"),
                )
                for rule_id, state in snapshot.rule_states.items()
            }

        return PostureResponse(
            host_id=host_id,
            snapshot_date=snapshot.snapshot_date,
            is_current=False,
            total_rules=snapshot.total_rules,
            passed=snapshot.passed,
            failed=snapshot.failed,
            error_count=snapshot.error_count or 0,
            not_applicable=snapshot.not_applicable or 0,
            compliance_score=snapshot.compliance_score,
            severity_breakdown=severity_breakdown,
            source_scan_id=snapshot.source_scan_id,
            rule_states=rule_states,
        )

    def get_posture_history(
        self,
        host_id: UUID,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None,
        limit: int = 30,
    ) -> PostureHistoryResponse:
        """
        Get posture history for a host over a time range.

        Args:
            host_id: Target host UUID
            start_date: Start of date range (default: 30 days ago)
            end_date: End of date range (default: today)
            limit: Maximum number of snapshots to return

        Returns:
            PostureHistoryResponse with list of posture snapshots
        """
        if end_date is None:
            end_date = date.today()
        if start_date is None:
            start_date = end_date - timedelta(days=30)

        query = (
            self._db.query(PostureSnapshot)
            .filter(
                and_(
                    PostureSnapshot.host_id == host_id,
                    func.date(PostureSnapshot.snapshot_date) >= start_date,
                    func.date(PostureSnapshot.snapshot_date) <= end_date,
                )
            )
            .order_by(PostureSnapshot.snapshot_date.desc())
            .limit(limit)
        )

        snapshots = query.all()

        posture_list = []
        for snapshot in snapshots:
            severity_breakdown = {
                "critical": SeverityBreakdown(
                    passed=snapshot.severity_critical_passed or 0,
                    failed=snapshot.severity_critical_failed or 0,
                ),
                "high": SeverityBreakdown(
                    passed=snapshot.severity_high_passed or 0,
                    failed=snapshot.severity_high_failed or 0,
                ),
                "medium": SeverityBreakdown(
                    passed=snapshot.severity_medium_passed or 0,
                    failed=snapshot.severity_medium_failed or 0,
                ),
                "low": SeverityBreakdown(
                    passed=snapshot.severity_low_passed or 0,
                    failed=snapshot.severity_low_failed or 0,
                ),
            }

            posture_list.append(
                PostureResponse(
                    host_id=host_id,
                    snapshot_date=snapshot.snapshot_date,
                    is_current=False,
                    total_rules=snapshot.total_rules,
                    passed=snapshot.passed,
                    failed=snapshot.failed,
                    error_count=snapshot.error_count or 0,
                    not_applicable=snapshot.not_applicable or 0,
                    compliance_score=snapshot.compliance_score,
                    severity_breakdown=severity_breakdown,
                    source_scan_id=snapshot.source_scan_id,
                )
            )

        return PostureHistoryResponse(
            host_id=host_id,
            snapshots=posture_list,
            total_snapshots=len(posture_list),
            date_range={
                "start": datetime.combine(start_date, datetime.min.time()),
                "end": datetime.combine(end_date, datetime.max.time()),
            },
        )

    @staticmethod
    def _extract_actual(
        evidence: Optional[Any],
    ) -> Optional[Union[str, List[str]]]:
        """Extract the 'actual' field from evidence JSONB.

        Args:
            evidence: Evidence JSONB (list of dicts or None).

        Returns:
            Single string for one-check rules, list for compound checks,
            or None if no evidence.
        """
        if not evidence:
            return None

        # evidence is stored as a list of dicts
        if isinstance(evidence, str):
            try:
                evidence = json.loads(evidence)
            except (json.JSONDecodeError, TypeError):
                return None

        if not isinstance(evidence, list):
            return None

        actuals = []
        for item in evidence:
            if isinstance(item, dict) and item.get("actual") is not None:
                actuals.append(str(item["actual"]))

        if not actuals:
            return None
        if len(actuals) == 1:
            return actuals[0]
        return actuals

    def _build_rule_states(self, scan_id: UUID) -> Dict[str, Any]:
        """Build rule_states dict from scan_findings for a given scan.

        Queries scan_findings and assembles a dict keyed by rule_id with
        status, severity, title, category, and actual value from evidence.

        Args:
            scan_id: UUID of the source scan.

        Returns:
            Dict mapping rule_id to state dict with actual values.
        """
        result = self._db.execute(
            text(
                """
                SELECT rule_id, title, severity, status,
                       framework_section, evidence
                FROM scan_findings
                WHERE scan_id = :scan_id
                """
            ),
            {"scan_id": str(scan_id)},
        )
        findings = result.fetchall()

        rule_states: Dict[str, Any] = {}
        for f in findings:
            actual = self._extract_actual(f.evidence)
            state: Dict[str, Any] = {
                "status": f.status,
                "severity": f.severity,
                "title": f.title,
            }
            if f.framework_section:
                state["category"] = f.framework_section
            if actual is not None:
                state["actual"] = actual
            rule_states[f.rule_id] = state

        return rule_states

    def create_snapshot(
        self,
        host_id: UUID,
        snapshot_date: Optional[datetime] = None,
    ) -> Optional[PostureSnapshot]:
        """
        Create a posture snapshot for a host.

        Called by scheduled task at end of day or manually.

        Args:
            host_id: Target host UUID
            snapshot_date: Optional snapshot date (default: now)

        Returns:
            Created PostureSnapshot or None if no scan data available
        """
        if snapshot_date is None:
            snapshot_date = datetime.now(timezone.utc)

        # Get current posture
        current = self._get_current_posture(host_id)
        if not current:
            logger.info("No current posture available for host %s, skipping snapshot", host_id)
            return None

        # Check if snapshot already exists for this date
        existing = (
            self._db.query(PostureSnapshot)
            .filter(
                and_(
                    PostureSnapshot.host_id == host_id,
                    func.date(PostureSnapshot.snapshot_date) == snapshot_date.date(),
                )
            )
            .first()
        )

        if existing:
            logger.debug("Snapshot already exists for host %s on %s", host_id, snapshot_date.date())
            return existing

        # Build rule_states from scan_findings (includes actual values)
        rule_states: Dict[str, Any] = {}
        if current.source_scan_id:
            try:
                rule_states = self._build_rule_states(current.source_scan_id)
            except Exception as e:
                logger.warning(
                    "Failed to build rule_states for snapshot host=%s scan=%s: %s",
                    host_id,
                    current.source_scan_id,
                    e,
                )

        # Create new snapshot
        snapshot = PostureSnapshot(
            host_id=host_id,
            snapshot_date=snapshot_date,
            total_rules=current.total_rules,
            passed=current.passed,
            failed=current.failed,
            error_count=current.error_count,
            not_applicable=current.not_applicable,
            compliance_score=current.compliance_score,
            severity_critical_passed=current.severity_breakdown.get("critical", SeverityBreakdown()).passed,
            severity_critical_failed=current.severity_breakdown.get("critical", SeverityBreakdown()).failed,
            severity_high_passed=current.severity_breakdown.get("high", SeverityBreakdown()).passed,
            severity_high_failed=current.severity_breakdown.get("high", SeverityBreakdown()).failed,
            severity_medium_passed=current.severity_breakdown.get("medium", SeverityBreakdown()).passed,
            severity_medium_failed=current.severity_breakdown.get("medium", SeverityBreakdown()).failed,
            severity_low_passed=current.severity_breakdown.get("low", SeverityBreakdown()).passed,
            severity_low_failed=current.severity_breakdown.get("low", SeverityBreakdown()).failed,
            rule_states=rule_states,
            source_scan_id=current.source_scan_id,
        )

        self._db.add(snapshot)
        self._db.commit()
        self._db.refresh(snapshot)

        logger.info(
            "Created posture snapshot for host %s: score=%.2f%%",
            host_id,
            current.compliance_score,
        )

        return snapshot

    @staticmethod
    def _normalize_actual(value: Optional[Any]) -> Optional[str]:
        """Normalize an actual value to a comparable string.

        Args:
            value: Raw actual value (str, list, or None).

        Returns:
            Normalized string for comparison, or None.
        """
        if value is None:
            return None
        if isinstance(value, list):
            return "; ".join(str(v) for v in sorted(value))
        return str(value)

    def detect_drift(
        self,
        host_id: UUID,
        start_date: date,
        end_date: date,
        include_value_drift: bool = False,
    ) -> DriftAnalysisResponse:
        """
        Detect compliance drift between two dates.

        Returns list of rules that changed status and overall drift metrics.
        When include_value_drift is True, also detects rules where the actual
        value changed even if the status remained the same.

        Args:
            host_id: Target host UUID
            start_date: Start date for comparison
            end_date: End date for comparison
            include_value_drift: Include value-level drift events

        Returns:
            DriftAnalysisResponse with drift metrics and events
        """
        start_posture = self._get_historical_posture(host_id, start_date, include_rule_states=True)
        end_posture = self._get_historical_posture(host_id, end_date, include_rule_states=True)

        detected_at = datetime.combine(end_date, datetime.min.time())

        # Handle missing snapshots
        if not start_posture or not end_posture:
            return DriftAnalysisResponse(
                host_id=host_id,
                start_date=datetime.combine(start_date, datetime.min.time()),
                end_date=detected_at,
                start_score=start_posture.compliance_score if start_posture else 0.0,
                end_score=end_posture.compliance_score if end_posture else 0.0,
                score_delta=0.0,
                drift_magnitude=0.0,
                drift_type="unknown",
                rules_improved=0,
                rules_regressed=0,
                rules_unchanged=0,
                drift_events=[],
            )

        # Calculate score delta
        score_delta = end_posture.compliance_score - start_posture.compliance_score
        drift_magnitude = abs(score_delta)

        # Determine drift type based on thresholds
        if drift_magnitude >= 10.0:
            drift_type = "major" if score_delta < 0 else "improvement"
        elif drift_magnitude >= 5.0:
            drift_type = "minor" if score_delta < 0 else "improvement"
        else:
            drift_type = "stable"

        # Analyze rule-level changes
        drift_events: List[DriftEvent] = []
        value_drift_events: List[ValueDriftEvent] = []
        rules_improved = 0
        rules_regressed = 0
        rules_unchanged = 0

        start_rules = start_posture.rule_states or {}
        end_rules = end_posture.rule_states or {}

        # Compare rule states
        all_rule_ids = set(start_rules.keys()) | set(end_rules.keys())

        for rule_id in all_rule_ids:
            start_state = start_rules.get(rule_id)
            end_state = end_rules.get(rule_id)

            if not start_state or not end_state:
                continue

            # Extract and normalize actual values for comparison
            start_actual = self._normalize_actual(start_state.actual)
            end_actual = self._normalize_actual(end_state.actual)

            if start_state.status != end_state.status:
                # Status changed — determine direction
                if end_state.status == "pass" and start_state.status == "fail":
                    direction = "improvement"
                    rules_improved += 1
                elif end_state.status == "fail" and start_state.status == "pass":
                    direction = "regression"
                    rules_regressed += 1
                else:
                    direction = "change"

                drift_events.append(
                    DriftEvent(
                        rule_id=rule_id,
                        rule_title=end_state.title,
                        previous_status=start_state.status,
                        current_status=end_state.status,
                        severity=end_state.severity,
                        detected_at=detected_at,
                        direction=direction,
                        previous_value=start_actual,
                        current_value=end_actual,
                    )
                )

                # Also track as value drift if value changed
                if include_value_drift and start_actual != end_actual:
                    value_drift_events.append(
                        ValueDriftEvent(
                            rule_id=rule_id,
                            rule_title=end_state.title,
                            severity=end_state.severity,
                            status=end_state.status,
                            previous_value=start_actual,
                            current_value=end_actual,
                            status_changed=True,
                            detected_at=detected_at,
                        )
                    )
            else:
                rules_unchanged += 1

                # Value-only drift: status unchanged but actual value changed
                if (
                    include_value_drift
                    and start_actual is not None
                    and end_actual is not None
                    and start_actual != end_actual
                ):
                    value_drift_events.append(
                        ValueDriftEvent(
                            rule_id=rule_id,
                            rule_title=end_state.title,
                            severity=end_state.severity,
                            status=end_state.status,
                            previous_value=start_actual,
                            current_value=end_actual,
                            status_changed=False,
                            detected_at=detected_at,
                        )
                    )

        return DriftAnalysisResponse(
            host_id=host_id,
            start_date=datetime.combine(start_date, datetime.min.time()),
            end_date=detected_at,
            start_score=start_posture.compliance_score,
            end_score=end_posture.compliance_score,
            score_delta=round(score_delta, 2),
            drift_magnitude=round(drift_magnitude, 2),
            drift_type=drift_type,
            rules_improved=rules_improved,
            rules_regressed=rules_regressed,
            rules_unchanged=rules_unchanged,
            drift_events=drift_events,
            value_drift_events=value_drift_events if include_value_drift else [],
            rules_value_changed=len(value_drift_events) if include_value_drift else 0,
        )

    def detect_group_drift(
        self,
        group_id: int,
        start_date: date,
        end_date: date,
    ) -> GroupDriftResponse:
        """
        Detect compliance drift across all hosts in a host group.

        Aggregates per-host drift results by rule_id to show which rules
        drifted across the most hosts.

        Args:
            group_id: Host group ID
            start_date: Start date for comparison
            end_date: End date for comparison

        Returns:
            GroupDriftResponse with per-rule summaries across hosts
        """
        # Get group info
        group_row = self._db.execute(
            text("SELECT id, name FROM host_groups WHERE id = :gid"),
            {"gid": group_id},
        ).fetchone()

        group_name = group_row.name if group_row else f"Group {group_id}"

        # Get host IDs in group
        members = self._db.execute(
            text(
                """
                SELECT hgm.host_id, h.hostname
                FROM host_group_memberships hgm
                JOIN hosts h ON h.id = hgm.host_id
                WHERE hgm.group_id = :gid AND h.is_active = true
                """
            ),
            {"gid": group_id},
        ).fetchall()

        total_hosts = len(members)
        if total_hosts == 0:
            return GroupDriftResponse(
                group_id=group_id,
                group_name=group_name,
                start_date=datetime.combine(start_date, datetime.min.time()),
                end_date=datetime.combine(end_date, datetime.min.time()),
                total_hosts=0,
                hosts_with_drift=0,
                rule_summaries=[],
            )

        # Aggregate drift per rule across hosts
        rule_agg: Dict[str, Dict[str, Any]] = {}
        hosts_with_drift = 0

        for member in members:
            drift = self.detect_drift(member.host_id, start_date, end_date, include_value_drift=True)

            host_had_drift = False

            # Process status drift events
            for event in drift.drift_events:
                host_had_drift = True
                if event.rule_id not in rule_agg:
                    rule_agg[event.rule_id] = {
                        "rule_title": event.rule_title,
                        "severity": event.severity,
                        "hosts": set(),
                        "status_changes": 0,
                        "value_changes": 0,
                        "samples": [],
                    }
                agg = rule_agg[event.rule_id]
                agg["hosts"].add(str(member.host_id))
                agg["status_changes"] += 1
                if len(agg["samples"]) < 3:
                    agg["samples"].append(
                        {
                            "host_id": str(member.host_id),
                            "hostname": member.hostname,
                            "previous_status": event.previous_status,
                            "current_status": event.current_status,
                            "previous_value": event.previous_value,
                            "current_value": event.current_value,
                        }
                    )

            # Process value-only drift events
            for event in drift.value_drift_events:
                if event.status_changed:
                    continue  # Already counted above
                host_had_drift = True
                if event.rule_id not in rule_agg:
                    rule_agg[event.rule_id] = {
                        "rule_title": event.rule_title,
                        "severity": event.severity,
                        "hosts": set(),
                        "status_changes": 0,
                        "value_changes": 0,
                        "samples": [],
                    }
                agg = rule_agg[event.rule_id]
                agg["hosts"].add(str(member.host_id))
                agg["value_changes"] += 1
                if len(agg["samples"]) < 3:
                    agg["samples"].append(
                        {
                            "host_id": str(member.host_id),
                            "hostname": member.hostname,
                            "status": event.status,
                            "previous_value": event.previous_value,
                            "current_value": event.current_value,
                        }
                    )

            if host_had_drift:
                hosts_with_drift += 1

        # Build rule summaries sorted by affected host count descending
        rule_summaries = [
            GroupDriftRuleSummary(
                rule_id=rule_id,
                rule_title=data["rule_title"],
                severity=data["severity"],
                affected_host_count=len(data["hosts"]),
                total_host_count=total_hosts,
                status_changes=data["status_changes"],
                value_changes=data["value_changes"],
                sample_changes=data["samples"],
            )
            for rule_id, data in rule_agg.items()
        ]
        rule_summaries.sort(key=lambda s: s.affected_host_count, reverse=True)

        return GroupDriftResponse(
            group_id=group_id,
            group_name=group_name,
            start_date=datetime.combine(start_date, datetime.min.time()),
            end_date=datetime.combine(end_date, datetime.min.time()),
            total_hosts=total_hosts,
            hosts_with_drift=hosts_with_drift,
            rule_summaries=rule_summaries,
        )

    def create_daily_snapshots_for_all_hosts(self) -> Dict[str, Any]:
        """
        Create daily posture snapshots for all active hosts.

        Called by scheduled Celery task.

        Returns:
            Summary of snapshot creation results
        """
        hosts = self._db.query(Host).filter(Host.is_active == True).all()  # noqa: E712

        created = 0
        skipped = 0
        errors = 0

        for host in hosts:
            try:
                snapshot = self.create_snapshot(host.id)
                if snapshot:
                    created += 1
                else:
                    skipped += 1
            except Exception as e:
                logger.exception("Failed to create snapshot for host %s: %s", host.id, e)
                errors += 1

        logger.info(
            "Daily snapshot creation complete: %d created, %d skipped, %d errors",
            created,
            skipped,
            errors,
        )

        return {
            "total_hosts": len(hosts),
            "created": created,
            "skipped": skipped,
            "errors": errors,
        }

    def cleanup_old_snapshots(self, retention_days: int = 30) -> int:
        """
        Clean up snapshots older than retention period.

        For free tier users, snapshots older than 30 days are deleted.
        OpenWatch+ subscribers have unlimited retention.

        Args:
            retention_days: Number of days to retain snapshots

        Returns:
            Number of snapshots deleted
        """
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)

        result = (
            self._db.query(PostureSnapshot)
            .filter(PostureSnapshot.created_at < cutoff_date)
            .delete(synchronize_session=False)
        )

        self._db.commit()

        logger.info("Cleaned up %d old posture snapshots (older than %d days)", result, retention_days)

        return result


__all__ = ["TemporalComplianceService"]
