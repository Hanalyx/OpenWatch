"""
Audit Export Service

Manages export generation for audit queries in JSON, CSV, and PDF formats.

Part of Phase 6: Audit Queries (Kensa Integration Plan)

OS Claim 3.3: "Audits are queries over canonical evidence"
"""

import csv
import hashlib
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from math import ceil
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Row
from sqlalchemy.orm import Session

from ...schemas.audit_query_schemas import (
    AuditExportListResponse,
    AuditExportResponse,
    ExportStatsSummary,
    FindingResult,
    QueryDefinition,
)
from ...utils.mutation_builders import DeleteBuilder, InsertBuilder, UpdateBuilder
from ...utils.query_builder import QueryBuilder
from .audit_query import AuditQueryService

logger = logging.getLogger(__name__)

# Default export directory
EXPORT_DIR = os.environ.get("OPENWATCH_EXPORT_DIR", "/tmp/openwatch/exports")


class AuditExportService:
    """
    Service for managing audit exports.

    Provides:
    - Export creation and tracking
    - Export generation in JSON, CSV, PDF formats
    - Export cleanup for expired files
    """

    def __init__(self, db: Session):
        self.db = db
        self.query_service = AuditQueryService(db)

    # =========================================================================
    # Export Management
    # =========================================================================

    def create_export(
        self,
        requested_by: int,
        export_format: str,
        query_id: Optional[UUID] = None,
        query_definition: Optional[Dict[str, Any]] = None,
        expires_in_days: int = 7,
    ) -> Optional[AuditExportResponse]:
        """
        Create a new export request.

        Either query_id or query_definition must be provided.

        Args:
            requested_by: User ID requesting export
            export_format: Export format (json, csv, pdf)
            query_id: ID of saved query to export
            query_definition: Ad-hoc query definition
            expires_in_days: Days until export expires

        Returns:
            Created export or None if validation fails
        """
        # Validate: need either query_id or query_definition
        if not query_id and not query_definition:
            logger.warning("Export creation rejected: no query specified")
            return None

        # If query_id provided, fetch the query definition
        final_query_def: Dict[str, Any]
        if query_id:
            saved_query = self.query_service.get_query(query_id)
            if not saved_query:
                logger.warning(
                    "Export creation rejected: query %s not found",
                    query_id,
                )
                return None
            final_query_def = saved_query.query_definition
        else:
            final_query_def = query_definition  # type: ignore

        from uuid import uuid4

        export_id = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)

        builder = (
            InsertBuilder("audit_exports")
            .columns(
                "id",
                "query_id",
                "query_definition",
                "format",
                "status",
                "requested_by",
                "expires_at",
            )
            .values(
                export_id,
                query_id,
                final_query_def,
                export_format,
                "pending",
                requested_by,
                expires_at,
            )
            .returning("id")
        )

        query, params = builder.build()
        # Convert dict to JSON string
        params["v0_query_definition"] = json.dumps(params["v0_query_definition"])

        result = self.db.execute(text(query), params)
        self.db.commit()

        row = result.fetchone()
        if row:
            logger.info(
                "Export created: %s (%s) by user %d",
                export_id,
                export_format,
                requested_by,
            )
            return self.get_export(export_id)

        return None

    def get_export(self, export_id: UUID) -> Optional[AuditExportResponse]:
        """Get export by ID."""
        builder = QueryBuilder("audit_exports").where("id = :id", export_id, "id")
        query, params = builder.build()
        result = self.db.execute(text(query), params)
        row = result.fetchone()

        if row:
            return self._row_to_response(row)
        return None

    def list_exports(
        self,
        user_id: int,
        page: int = 1,
        per_page: int = 20,
        status: Optional[str] = None,
    ) -> AuditExportListResponse:
        """
        List exports for a user.

        Args:
            user_id: User ID
            page: Page number (1-indexed)
            per_page: Items per page
            status: Filter by status

        Returns:
            Paginated export list
        """
        builder = QueryBuilder("audit_exports")
        builder.where("requested_by = :user_id", user_id, "user_id")

        if status:
            builder.where("status = :status", status, "status")

        # Get total count
        count_query, count_params = builder.count_query()
        count_result = self.db.execute(text(count_query), count_params)
        total = count_result.scalar() or 0

        # Get paginated results
        builder.order_by("created_at", "DESC")
        builder.paginate(page, per_page)
        data_query, data_params = builder.build()
        result = self.db.execute(text(data_query), data_params)
        rows = result.fetchall()

        exports = [self._row_to_response(row) for row in rows]

        return AuditExportListResponse(
            items=exports,
            total=total,
            page=page,
            per_page=per_page,
            total_pages=ceil(total / per_page) if total > 0 else 1,
        )

    def get_stats(self, user_id: int) -> ExportStatsSummary:
        """Get export statistics for a user."""
        query = """
            SELECT
                COUNT(*) as total_exports,
                COUNT(*) FILTER (WHERE status = 'pending') as pending,
                COUNT(*) FILTER (WHERE status = 'processing') as processing,
                COUNT(*) FILTER (WHERE status = 'completed') as completed,
                COUNT(*) FILTER (WHERE status = 'failed') as failed
            FROM audit_exports
            WHERE requested_by = :user_id
        """
        result = self.db.execute(text(query), {"user_id": user_id})
        row = result.fetchone()

        if row:
            return ExportStatsSummary(
                total_exports=row.total_exports or 0,
                pending=row.pending or 0,
                processing=row.processing or 0,
                completed=row.completed or 0,
                failed=row.failed or 0,
            )

        return ExportStatsSummary()

    # =========================================================================
    # Export Generation
    # =========================================================================

    def generate_export(self, export_id: UUID) -> bool:
        """
        Generate export file.

        Called by Celery task. Updates export status through lifecycle:
        pending -> processing -> completed/failed

        Args:
            export_id: Export ID to generate

        Returns:
            True if successful, False otherwise
        """
        export = self.get_export(export_id)
        if not export:
            logger.error("Export generation failed: export %s not found", export_id)
            return False

        if export.status != "pending":
            logger.warning(
                "Export generation skipped: export %s status is %s",
                export_id,
                export.status,
            )
            return False

        # Update to processing
        self._update_export_status(export_id, "processing")

        try:
            # Parse query definition
            query_def = QueryDefinition.model_validate(export.query_definition)

            # Fetch all results (no pagination for export)
            all_findings = self._fetch_all_findings(query_def)

            # Generate file based on format
            if export.format == "json":
                file_path, file_size, checksum = self._generate_json(export_id, all_findings)
            elif export.format == "csv":
                file_path, file_size, checksum = self._generate_csv(export_id, all_findings)
            elif export.format == "pdf":
                file_path, file_size, checksum = self._generate_pdf(export_id, all_findings)
            else:
                raise ValueError(f"Unsupported format: {export.format}")

            # Update to completed
            self._update_export_completed(export_id, file_path, file_size, checksum)

            logger.info(
                "Export generated: %s -> %s (%d bytes)",
                export_id,
                file_path,
                file_size,
            )
            return True

        except Exception as e:
            logger.exception("Export generation failed: %s - %s", export_id, e)
            self._update_export_failed(export_id, str(e))
            return False

    def _fetch_all_findings(self, query_def: QueryDefinition, batch_size: int = 1000) -> List[FindingResult]:
        """Fetch all findings for export (paginated internally)."""
        all_findings: List[FindingResult] = []
        page = 1

        while True:
            result = self.query_service.execute_adhoc_query(query_def, page=page, per_page=batch_size)
            all_findings.extend(result.items)

            if len(result.items) < batch_size:
                break
            page += 1

        return all_findings

    def _generate_json(self, export_id: UUID, findings: List[FindingResult]) -> tuple[str, int, str]:
        """Generate JSON export file."""
        # Ensure export directory exists
        Path(EXPORT_DIR).mkdir(parents=True, exist_ok=True)

        file_path = os.path.join(EXPORT_DIR, f"{export_id}.json")

        # Build export data
        export_data = {
            "export_id": str(export_id),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "findings": [f.model_dump(mode="json") for f in findings],
        }

        # Write file
        with open(file_path, "w") as f:
            json.dump(export_data, f, indent=2, default=str)

        # Calculate size and checksum
        file_size = os.path.getsize(file_path)
        checksum = self._calculate_checksum(file_path)

        return file_path, file_size, checksum

    def _generate_csv(self, export_id: UUID, findings: List[FindingResult]) -> tuple[str, int, str]:
        """Generate CSV export file."""
        Path(EXPORT_DIR).mkdir(parents=True, exist_ok=True)

        file_path = os.path.join(EXPORT_DIR, f"{export_id}.csv")

        # Define CSV columns
        fieldnames = [
            "scan_id",
            "host_id",
            "hostname",
            "rule_id",
            "title",
            "severity",
            "status",
            "detail",
            "framework_section",
            "scanned_at",
        ]

        with open(file_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for finding in findings:
                writer.writerow(
                    {
                        "scan_id": str(finding.scan_id),
                        "host_id": str(finding.host_id),
                        "hostname": finding.hostname,
                        "rule_id": finding.rule_id,
                        "title": finding.title,
                        "severity": finding.severity,
                        "status": finding.status,
                        "detail": finding.detail or "",
                        "framework_section": finding.framework_section or "",
                        "scanned_at": finding.scanned_at.isoformat(),
                    }
                )

        file_size = os.path.getsize(file_path)
        checksum = self._calculate_checksum(file_path)

        return file_path, file_size, checksum

    def _generate_pdf(self, export_id: UUID, findings: List[FindingResult]) -> tuple[str, int, str]:
        """
        Generate PDF export file.

        Note: Full PDF generation requires reportlab or similar library.
        This is a simplified implementation that creates a text-based report.
        """
        Path(EXPORT_DIR).mkdir(parents=True, exist_ok=True)

        file_path = os.path.join(EXPORT_DIR, f"{export_id}.pdf")

        try:
            # Try to use reportlab if available
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import inch
            from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

            doc = SimpleDocTemplate(file_path, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []

            # Title
            title_style = ParagraphStyle(
                "Title",
                parent=styles["Heading1"],
                fontSize=18,
                spaceAfter=12,
            )
            story.append(Paragraph("Compliance Audit Report", title_style))
            story.append(Spacer(1, 0.25 * inch))

            # Summary
            summary_text = f"""
            <b>Export ID:</b> {export_id}<br/>
            <b>Generated:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}<br/>
            <b>Total Findings:</b> {len(findings)}
            """
            story.append(Paragraph(summary_text, styles["Normal"]))
            story.append(Spacer(1, 0.5 * inch))

            # Findings table (limited to first 100 for PDF)
            if findings:
                table_data = [["Host", "Rule", "Severity", "Status"]]
                for f in findings[:100]:
                    table_data.append(
                        [
                            f.hostname[:20],
                            f.rule_id[:30],
                            f.severity,
                            f.status,
                        ]
                    )

                table = Table(table_data, colWidths=[1.5 * inch, 3 * inch, 1 * inch, 1 * inch])
                table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 8),
                            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                            ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                            ("GRID", (0, 0), (-1, -1), 1, colors.black),
                        ]
                    )
                )
                story.append(table)

                if len(findings) > 100:
                    story.append(Spacer(1, 0.25 * inch))
                    story.append(
                        Paragraph(
                            f"<i>Note: Showing first 100 of {len(findings)} findings. "
                            f"Download CSV for complete data.</i>",
                            styles["Italic"],
                        )
                    )

            doc.build(story)

        except ImportError:
            # Fallback to simple text file if reportlab not available
            logger.warning("reportlab not available, generating text-based PDF placeholder")
            with open(file_path, "w") as f:
                f.write("COMPLIANCE AUDIT REPORT\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Export ID: {export_id}\n")
                f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")
                f.write(f"Total Findings: {len(findings)}\n\n")
                f.write("-" * 50 + "\n\n")

                for finding in findings[:100]:
                    f.write(f"Host: {finding.hostname}\n")
                    f.write(f"Rule: {finding.rule_id}\n")
                    f.write(f"Severity: {finding.severity}\n")
                    f.write(f"Status: {finding.status}\n")
                    f.write("-" * 30 + "\n")

        file_size = os.path.getsize(file_path)
        checksum = self._calculate_checksum(file_path)

        return file_path, file_size, checksum

    def _calculate_checksum(self, file_path: str) -> str:
        """Calculate SHA-256 checksum of file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    # =========================================================================
    # Status Updates
    # =========================================================================

    def _update_export_status(self, export_id: UUID, status: str) -> None:
        """Update export status."""
        builder = UpdateBuilder("audit_exports").set("status", status).where("id = :id", export_id, "id")

        if status == "processing":
            builder.set_raw("started_at", "CURRENT_TIMESTAMP")

        query, params = builder.build()
        self.db.execute(text(query), params)
        self.db.commit()

    def _update_export_completed(
        self,
        export_id: UUID,
        file_path: str,
        file_size: int,
        checksum: str,
    ) -> None:
        """Update export as completed."""
        builder = (
            UpdateBuilder("audit_exports")
            .set("status", "completed")
            .set("file_path", file_path)
            .set("file_size_bytes", file_size)
            .set("file_checksum", checksum)
            .set_raw("completed_at", "CURRENT_TIMESTAMP")
            .where("id = :id", export_id, "id")
        )

        query, params = builder.build()
        self.db.execute(text(query), params)
        self.db.commit()

    def _update_export_failed(self, export_id: UUID, error: str) -> None:
        """Update export as failed."""
        builder = (
            UpdateBuilder("audit_exports")
            .set("status", "failed")
            .set("error_message", error)
            .set_raw("completed_at", "CURRENT_TIMESTAMP")
            .where("id = :id", export_id, "id")
        )

        query, params = builder.build()
        self.db.execute(text(query), params)
        self.db.commit()

    # =========================================================================
    # Cleanup
    # =========================================================================

    def cleanup_expired_exports(self) -> int:
        """
        Delete expired export records and files.

        Returns:
            Number of exports cleaned up
        """
        now = datetime.now(timezone.utc)

        # Find expired exports with files
        query = """
            SELECT id, file_path FROM audit_exports
            WHERE expires_at <= :now
              AND status = 'completed'
              AND file_path IS NOT NULL
        """
        result = self.db.execute(text(query), {"now": now})
        expired = result.fetchall()

        deleted_count = 0
        for row in expired:
            # Delete file
            if row.file_path and os.path.exists(row.file_path):
                try:
                    os.remove(row.file_path)
                    logger.info("Deleted expired export file: %s", row.file_path)
                except OSError as e:
                    logger.warning(
                        "Failed to delete export file %s: %s",
                        row.file_path,
                        e,
                    )

            # Delete record
            delete_builder = DeleteBuilder("audit_exports").where("id = :id", row.id, "id")
            delete_query, delete_params = delete_builder.build()
            self.db.execute(text(delete_query), delete_params)
            deleted_count += 1

        self.db.commit()

        if deleted_count > 0:
            logger.info("Cleaned up %d expired exports", deleted_count)

        return deleted_count

    # =========================================================================
    # Private Helpers
    # =========================================================================

    def _row_to_response(self, row: Row[Any]) -> AuditExportResponse:
        """Convert database row to AuditExportResponse."""
        now = datetime.now(timezone.utc)
        is_ready = row.status == "completed" and row.file_path is not None
        is_expired = row.expires_at <= now if row.expires_at else False

        return AuditExportResponse(
            id=row.id,
            query_id=row.query_id,
            query_definition=row.query_definition,
            format=row.format,
            status=row.status,
            file_path=row.file_path,
            file_size_bytes=row.file_size_bytes,
            file_checksum=row.file_checksum,
            error_message=row.error_message,
            requested_by=row.requested_by,
            created_at=row.created_at,
            started_at=row.started_at,
            completed_at=row.completed_at,
            expires_at=row.expires_at,
            is_ready=is_ready,
            is_expired=is_expired,
        )


__all__ = ["AuditExportService"]
