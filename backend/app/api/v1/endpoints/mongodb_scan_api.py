"""
MongoDB-Integrated Scanning API Endpoints
Provides endpoints for scanning using MongoDB compliance rules
"""

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from ....auth import get_current_user
from ....constants import is_framework_supported
from ....database import User, get_db
from ....services.compliance_framework_reporting import ComplianceFrameworkReporter
from ....services.mongodb_scap_scanner import MongoDBSCAPScanner
from ....services.result_enrichment_service import ResultEnrichmentService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/mongodb-scans", tags=["MongoDB Scanning"])


class MongoDBScanRequest(BaseModel):
    """Request model for MongoDB-based scanning"""

    host_id: str = Field(..., description="Target host ID")
    hostname: str = Field(..., description="Target hostname or IP address")
    platform: str = Field(..., description="Target platform (rhel, ubuntu, etc.)")
    platform_version: str = Field(..., description="Platform version")
    framework: Optional[str] = Field(None, description="Compliance framework to use")
    severity_filter: Optional[List[str]] = Field(None, description="Filter by severity levels")
    rule_ids: Optional[List[str]] = Field(None, description="Specific rule IDs to scan (from wizard selection)")
    connection_params: Optional[Dict[str, Any]] = Field(None, description="SSH connection parameters")
    include_enrichment: bool = Field(True, description="Include result enrichment")
    generate_report: bool = Field(True, description="Generate compliance report")


class ScanStatusResponse(BaseModel):
    """Response model for scan status"""

    scan_id: str
    status: str
    progress: Optional[int] = None
    message: Optional[str] = None
    started_at: str
    estimated_completion: Optional[str] = None


class MongoDBScanResponse(BaseModel):
    """Response model for MongoDB scan results"""

    success: bool
    scan_id: str
    host_id: str
    scan_started: str
    scan_completed: Optional[str] = None
    rules_used: int
    mongodb_rules_selected: int
    platform: str
    framework: Optional[str] = None
    results_summary: Dict[str, Any] = {}
    enrichment_data: Optional[Dict[str, Any]] = None
    compliance_report: Optional[Dict[str, Any]] = None
    result_files: Dict[str, str] = {}


# Global scanner instance
mongodb_scanner = None
enrichment_service = None
compliance_reporter = None


async def get_mongodb_scanner(request: Request) -> MongoDBSCAPScanner:
    """Get or initialize MongoDB scanner"""
    global mongodb_scanner
    try:
        if not mongodb_scanner:
            logger.info("Initializing MongoDB scanner for the first time")
            # Get encryption service from app state
            encryption_service = getattr(request.app.state, "encryption_service", None)
            if not encryption_service:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Encryption service not available",
                )
            mongodb_scanner = MongoDBSCAPScanner(encryption_service=encryption_service)
            await mongodb_scanner.initialize()
            logger.info("MongoDB scanner initialized successfully")
        return mongodb_scanner
    except Exception as e:
        logger.error(f"Failed to initialize MongoDB scanner: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scanner initialization failed: {str(e)}",
        )


async def get_enrichment_service() -> ResultEnrichmentService:
    """Get or initialize enrichment service"""
    global enrichment_service
    if not enrichment_service:
        enrichment_service = ResultEnrichmentService()
        await enrichment_service.initialize()
    return enrichment_service


async def get_compliance_reporter() -> ComplianceFrameworkReporter:
    """Get or initialize compliance reporter"""
    global compliance_reporter
    if not compliance_reporter:
        compliance_reporter = ComplianceFrameworkReporter()
        await compliance_reporter.initialize()
    return compliance_reporter


@router.post("/start", response_model=MongoDBScanResponse)
async def start_mongodb_scan(
    scan_request: MongoDBScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    scanner: MongoDBSCAPScanner = Depends(get_mongodb_scanner),
):
    """
    Start a MongoDB rule-based SCAP scan

    This endpoint initiates a scan using rules selected from MongoDB based on
    the target platform and compliance framework requirements.

    Creates records in PostgreSQL scans and scan_results tables for UI integration.
    """
    logger.info(f"=== ENDPOINT CALLED: start_mongodb_scan for host {scan_request.hostname} ===")
    try:
        # Generate UUID for scan (compatible with PostgreSQL scans table)
        scan_uuid = uuid.uuid4()
        scan_id = f"mongodb_scan_{scan_uuid.hex[:8]}"
        logger.info(f"Starting MongoDB scan {scan_id} (UUID: {scan_uuid}) for host {scan_request.hostname}")

        # Log request details safely
        try:
            rule_count = len(scan_request.rule_ids) if scan_request.rule_ids else 0
            logger.info(
                f"Request: platform={scan_request.platform}, version={scan_request.platform_version}, framework={scan_request.framework}, rules={rule_count}"
            )
        except Exception as log_err:
            logger.warning(f"Could not log request details: {log_err}")

        # Validate framework using centralized constants
        if scan_request.framework and not is_framework_supported(scan_request.framework):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported framework: {scan_request.framework}. Framework must be one of the supported compliance frameworks.",
            )

        # Create initial PostgreSQL scan record (status: running)
        scan_name = f"MongoDB Scan - {scan_request.platform} {scan_request.platform_version} - {scan_request.framework or 'all frameworks'}"
        started_at = datetime.utcnow()

        try:
            insert_scan_query = text(
                """
                INSERT INTO scans (
                    id, name, host_id, profile_id, status, progress,
                    scan_options, started_by, started_at, remediation_requested, verification_scan, scan_metadata
                )
                VALUES (
                    :id, :name, :host_id, :profile_id, :status, :progress,
                    :scan_options, :started_by, :started_at, :remediation_requested, :verification_scan, :scan_metadata
                )
            """
            )
            db.execute(
                insert_scan_query,
                {
                    "id": str(scan_uuid),
                    "name": scan_name,
                    "host_id": scan_request.host_id,
                    "profile_id": scan_request.framework or "mongodb_custom",
                    "status": "running",
                    "progress": 0,
                    "scan_options": f'{{"platform": "{scan_request.platform}", "platform_version": "{scan_request.platform_version}", "framework": "{scan_request.framework}"}}',
                    "started_by": int(current_user.get("id")) if current_user.get("id") else None,
                    "started_at": started_at,
                    "remediation_requested": False,
                    "verification_scan": False,
                    "scan_metadata": f'{{"scan_type": "mongodb", "rule_count": {len(scan_request.rule_ids) if scan_request.rule_ids else 0}}}',
                },
            )
            db.commit()
            logger.info(f"Created PostgreSQL scan record {scan_uuid}")
        except Exception as db_error:
            logger.error(f"Failed to create scan record: {db_error}", exc_info=True)
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to create scan record: {str(db_error)}",
            )

        # Start the scan process
        logger.info(f"Calling scanner.scan_with_mongodb_rules for host {scan_request.host_id}")
        try:
            scan_result = await scanner.scan_with_mongodb_rules(
                host_id=scan_request.host_id,
                hostname=scan_request.hostname,
                platform=scan_request.platform,
                platform_version=scan_request.platform_version,
                framework=scan_request.framework,
                connection_params=scan_request.connection_params,
                severity_filter=scan_request.severity_filter,
                rule_ids=scan_request.rule_ids,
            )
        except Exception as scan_error:
            logger.error(f"Scanner failed: {scan_error}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Scanner error: {str(scan_error)}",
            )

        if not scan_result.get("success"):
            logger.error(f"Scan failed with result: {scan_result}")
            # Update PostgreSQL scan record to failed status
            try:
                update_scan_query = text(
                    """
                    UPDATE scans
                    SET status = :status, progress = :progress, completed_at = :completed_at, error_message = :error_message
                    WHERE id = :id
                """
                )
                db.execute(
                    update_scan_query,
                    {
                        "id": str(scan_uuid),
                        "status": "failed",
                        "progress": 100,
                        "completed_at": datetime.utcnow(),
                        "error_message": scan_result.get("error", "Unknown error"),
                    },
                )
                db.commit()
            except Exception as update_error:
                logger.error(f"Failed to update scan status to failed: {update_error}")
                db.rollback()

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Scan execution failed: {scan_result.get('error', 'Unknown error')}",
            )

        # Update PostgreSQL scan record to completed status
        completed_at = datetime.utcnow()
        try:
            update_scan_query = text(
                """
                UPDATE scans
                SET status = :status, progress = :progress, completed_at = :completed_at,
                    result_file = :result_file, report_file = :report_file
                WHERE id = :id
            """
            )
            db.execute(
                update_scan_query,
                {
                    "id": str(scan_uuid),
                    "status": "completed",
                    "progress": 100,
                    "completed_at": completed_at,
                    "result_file": scan_result.get("result_file", ""),
                    "report_file": scan_result.get("report_file", ""),
                },
            )

            # Create scan_results record
            # Parse XCCDF results to get pass/fail counts (simplified - you may want more detailed parsing)
            rules_used = scan_result.get("mongodb_rules_used", 0)
            insert_results_query = text(
                """
                INSERT INTO scan_results (
                    scan_id, total_rules, passed_rules, failed_rules, error_rules,
                    unknown_rules, not_applicable_rules, score,
                    severity_high, severity_medium, severity_low, created_at
                )
                VALUES (
                    :scan_id, :total_rules, :passed_rules, :failed_rules, :error_rules,
                    :unknown_rules, :not_applicable_rules, :score,
                    :severity_high, :severity_medium, :severity_low, :created_at
                )
            """
            )
            db.execute(
                insert_results_query,
                {
                    "scan_id": str(scan_uuid),
                    "total_rules": rules_used,
                    "passed_rules": 0,  # TODO: Parse XCCDF results for actual counts
                    "failed_rules": 0,  # TODO: Parse XCCDF results for actual counts
                    "error_rules": 0,
                    "unknown_rules": 0,
                    "not_applicable_rules": 0,
                    "score": "0%",  # TODO: Calculate actual score
                    "severity_high": 0,
                    "severity_medium": 0,
                    "severity_low": 0,
                    "created_at": completed_at,
                },
            )

            db.commit()
            logger.info(f"Updated PostgreSQL scan record {scan_uuid} to completed with results")
        except Exception as db_error:
            logger.error(f"Failed to update scan completion: {db_error}", exc_info=True)
            db.rollback()
            # Don't raise - scan succeeded, just logging failed

        # Prepare response data
        response_data = MongoDBScanResponse(
            success=True,
            scan_id=scan_id,
            host_id=scan_request.host_id,
            scan_started=datetime.utcnow().isoformat(),
            rules_used=scan_result.get("mongodb_rules_used", 0),
            mongodb_rules_selected=scan_result.get("mongodb_rules_used", 0),
            platform=scan_request.platform,
            framework=scan_request.framework,
            results_summary={
                "return_code": scan_result.get("return_code", -1),
                "scan_completed": scan_result.get("success", False),
            },
            result_files={
                "xml_results": scan_result.get("result_file", ""),
                "html_report": scan_result.get("report_file", ""),
            },
        )

        # Add background tasks for enrichment and reporting
        if scan_request.include_enrichment:
            background_tasks.add_task(
                enrich_scan_results_task,
                scan_id,
                scan_result.get("result_file"),
                scan_request.dict(),
                scan_request.generate_report,
            )

        logger.info(f"MongoDB scan {scan_id} completed successfully")
        return response_data

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start MongoDB scan: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan initialization failed: {str(e)}",
        )


async def enrich_scan_results_task(
    scan_id: str, result_file: str, scan_metadata: Dict[str, Any], generate_report: bool
):
    """Background task to enrich scan results and generate reports"""
    try:
        logger.info(f"Starting background enrichment for scan {scan_id}")

        # Get services
        enrichment_svc = await get_enrichment_service()

        # Enrich results
        enriched_results = await enrichment_svc.enrich_scan_results(
            result_file_path=result_file, scan_metadata=scan_metadata
        )

        # Generate compliance report if requested
        if generate_report:
            reporter = await get_compliance_reporter()
            target_frameworks = [scan_metadata.get("framework")] if scan_metadata.get("framework") else None

            compliance_report = await reporter.generate_compliance_report(
                enriched_results=enriched_results,
                target_frameworks=target_frameworks,
                report_format="json",
            )

            # Store report (in a real implementation, this would save to database)
            logger.info(f"Generated compliance report for scan {scan_id}")

        logger.info(f"Background enrichment completed for scan {scan_id}")

    except Exception as e:
        logger.error(f"Background enrichment failed for scan {scan_id}: {e}")


@router.get("/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str, current_user: User = Depends(get_current_user)):
    """Get status of a MongoDB scan"""
    try:
        # In a real implementation, this would query a database for scan status
        # For now, return a mock response
        return ScanStatusResponse(
            scan_id=scan_id,
            status="completed",  # Mock status
            progress=100,
            message="Scan completed successfully",
            started_at=datetime.utcnow().isoformat(),
        )

    except Exception as e:
        logger.error(f"Failed to get scan status for {scan_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get scan status: {str(e)}",
        )


@router.get("/{scan_id}/results")
async def get_scan_results(
    scan_id: str,
    include_enrichment: bool = True,
    include_report: bool = True,
    current_user: User = Depends(get_current_user),
):
    """Get detailed results from a MongoDB scan"""
    try:
        # In a real implementation, this would retrieve stored results
        # For now, return a mock response structure
        results = {
            "scan_id": scan_id,
            "status": "completed",
            "basic_results": {
                "rules_tested": 25,
                "rules_passed": 18,
                "rules_failed": 7,
                "overall_score": 72.0,
            },
        }

        if include_enrichment:
            results["enrichment"] = {
                "intelligence_data_available": True,
                "remediation_guidance_generated": True,
                "framework_mapping_completed": True,
            }

        if include_report:
            results["compliance_report"] = {
                "report_generated": True,
                "frameworks_analyzed": ["nist"],
                "executive_summary_available": True,
            }

        return results

    except Exception as e:
        logger.error(f"Failed to get scan results for {scan_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve scan results: {str(e)}",
        )


@router.get("/{scan_id}/report")
async def get_compliance_report(
    scan_id: str,
    format: str = "json",
    framework: Optional[str] = None,
    current_user: User = Depends(get_current_user),
):
    """Get compliance report for a scan"""
    try:
        if format not in ["json", "html", "pdf"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Format must be json, html, or pdf",
            )

        # In a real implementation, this would retrieve the stored report
        # For now, return mock report data
        mock_report = {
            "metadata": {
                "scan_id": scan_id,
                "report_generated": datetime.utcnow().isoformat(),
                "format": format,
                "framework": framework,
            },
            "executive_summary": {
                "overall_compliance_score": 72.0,
                "grade": "C",
                "critical_issues": 3,
                "recommendation": "Focus on high severity failures first",
            },
            "framework_analysis": {
                "nist": {
                    "compliance_rate": 72.0,
                    "grade": "C",
                    "critical_failures": 3,
                    "status": "needs_improvement",
                }
            },
        }

        return mock_report

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get compliance report for {scan_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve compliance report: {str(e)}",
        )


@router.get("/available-rules")
async def get_available_rules(
    platform: Optional[str] = None,
    framework: Optional[str] = None,
    severity: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    scanner: MongoDBSCAPScanner = Depends(get_mongodb_scanner),
):
    """Get available MongoDB rules for scanning"""
    try:
        # Get rules from MongoDB based on filters
        rules = await scanner.select_platform_rules(
            platform=platform or "rhel",
            platform_version="8",  # Default version
            framework=framework,
            severity_filter=[severity] if severity else None,
        )

        # Format rules for API response
        rule_summaries = []
        for rule in rules[:10]:  # Limit to first 10 for demo
            rule_summaries.append(
                {
                    "rule_id": rule.rule_id,
                    "name": rule.metadata.get("name", "Unknown"),
                    "description": rule.metadata.get("description", "No description"),
                    "severity": rule.severity,
                    "category": rule.category,
                    "frameworks": (list(rule.frameworks.keys()) if rule.frameworks else []),
                    "platforms": (list(rule.platform_implementations.keys()) if rule.platform_implementations else []),
                }
            )

        return {
            "success": True,
            "total_rules_available": len(rules),
            "rules_sample": rule_summaries,
            "filters_applied": {
                "platform": platform,
                "framework": framework,
                "severity": severity,
            },
        }

    except Exception as e:
        logger.error(f"Failed to get available rules: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve available rules: {str(e)}",
        )


@router.get("/scanner/health")
async def get_scanner_health(current_user: User = Depends(get_current_user)):
    """Get MongoDB scanner service health"""
    try:
        scanner = await get_mongodb_scanner()
        enrichment = await get_enrichment_service()
        reporter = await get_compliance_reporter()

        # Check actual MongoDB connection
        mongo_status = "unknown"
        mongo_details = {}
        try:
            from ....services.mongo_integration_service import get_mongo_service

            mongo_service = await get_mongo_service()
            mongo_health = await mongo_service.health_check()
            mongo_status = mongo_health.get("status", "unknown")
            if mongo_status == "healthy":
                mongo_details = {
                    "database": mongo_health.get("database"),
                    "collections": mongo_health.get("collections", []),
                    "document_count": mongo_health.get("document_count", {}),
                }
            else:
                mongo_details = {"error": mongo_health.get("message", "Unknown error")}
        except Exception as e:
            mongo_status = "error"
            mongo_details = {"error": str(e)}

        return {
            "status": "healthy" if mongo_status == "healthy" else "degraded",
            "components": {
                "mongodb_scanner": {
                    "status": ("initialized" if scanner._initialized else "not_initialized"),
                    "mongodb_connection": mongo_status,
                    "mongodb_details": mongo_details,
                },
                "enrichment_service": {
                    "status": ("initialized" if enrichment._initialized else "not_initialized"),
                    "stats": await enrichment.get_enrichment_statistics(),
                },
                "compliance_reporter": {
                    "status": ("initialized" if reporter._initialized else "not_initialized"),
                    "supported_frameworks": list(reporter.frameworks.keys()),
                },
            },
            "capabilities": {
                "platform_aware_scanning": True,
                "rule_inheritance_resolution": True,
                "result_enrichment": True,
                "compliance_reporting": True,
                "supported_platforms": ["rhel", "ubuntu", "centos"],
                "supported_frameworks": ["nist", "cis", "stig", "pci"],
            },
        }

    except Exception as e:
        logger.error(f"Failed to get scanner health: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Health check failed: {str(e)}",
        )
