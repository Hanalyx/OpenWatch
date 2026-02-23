"""
Kensa Framework Mapper Service

Maps Kensa rules to compliance framework controls (CIS, STIG, NIST).
Provides framework coverage statistics and control-to-rule lookups.

This service queries PostgreSQL tables (not MongoDB):
- kensa_rules: Rule metadata
- framework_mappings: Control mappings

Usage:
    from app.plugins.kensa.framework_mapper import FrameworkMapper

    mapper = FrameworkMapper(db)

    # Get rules for a framework
    rules = await mapper.get_rules_for_framework("cis", "rhel9_v2")

    # Get framework coverage
    coverage = await mapper.get_framework_coverage("stig", "rhel9_v2r7")

    # Get all frameworks for a rule
    refs = await mapper.get_rule_framework_refs("ssh-disable-root-login")
"""

import logging
from typing import Any, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class FrameworkMapper:
    """
    Maps Kensa rules to compliance framework controls.

    Supports:
    - CIS Benchmarks (RHEL 8/9/10)
    - DISA STIGs (RHEL 8/9)
    - NIST 800-53 Rev 5
    - PCI-DSS v4
    - SRG

    All data is queried from PostgreSQL (no MongoDB).
    """

    # Known framework versions
    FRAMEWORKS = {
        "cis": {
            "rhel8_v4": "CIS RHEL 8 v4.0.0",
            "rhel9_v2": "CIS RHEL 9 v2.0.0",
            "rhel10_v1": "CIS RHEL 10 v1.0.0",
        },
        "stig": {
            "rhel8_v2r6": "DISA STIG RHEL 8 V2R6",
            "rhel9_v2r7": "DISA STIG RHEL 9 V2R7",
        },
        "nist_800_53": {
            "r5": "NIST SP 800-53 Rev 5",
        },
        "pci_dss": {
            "v4": "PCI-DSS v4.0",
        },
        "fedramp": {
            "moderate": "FedRAMP Moderate",
        },
    }

    def __init__(self, db: Session):
        """
        Initialize framework mapper.

        Args:
            db: SQLAlchemy database session.
        """
        self.db = db

    async def get_rules_for_framework(
        self,
        framework: str,
        version: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get all Kensa rules mapped to a framework.

        Args:
            framework: Framework name (cis, stig, nist_800_53).
            version: Optional framework version (rhel9_v2, v2r7).
            severity: Optional severity filter (high, medium, low).
            category: Optional category filter.

        Returns:
            List of rules with their framework mappings.
        """
        params = {"framework": framework}
        version_clause = ""
        severity_clause = ""
        category_clause = ""

        if version:
            version_clause = "AND fm.framework_version = :version"
            params["version"] = version

        if severity:
            severity_clause = "AND kr.severity = :severity"
            params["severity"] = severity

        if category:
            category_clause = "AND kr.category = :category"
            params["category"] = category

        query = text(
            f"""
            SELECT DISTINCT
                kr.rule_id,
                kr.title,
                kr.description,
                kr.severity,
                kr.category,
                kr.tags,
                fm.control_id,
                fm.framework_version,
                fm.cis_section,
                fm.cis_level,
                fm.stig_id,
                fm.vuln_id,
                fm.severity as control_severity
            FROM kensa_rules kr
            INNER JOIN framework_mappings fm ON kr.rule_id = fm.kensa_rule_id
            WHERE fm.framework = :framework
            {version_clause}
            {severity_clause}
            {category_clause}
            ORDER BY kr.category, kr.rule_id
        """
        )

        result = self.db.execute(query, params).fetchall()

        rules = []
        for row in result:
            rules.append(
                {
                    "rule_id": row[0],
                    "title": row[1],
                    "description": row[2],
                    "severity": row[3],
                    "category": row[4],
                    "tags": row[5],
                    "control_id": row[6],
                    "framework_version": row[7],
                    "cis_section": row[8],
                    "cis_level": row[9],
                    "stig_id": row[10],
                    "vuln_id": row[11],
                    "control_severity": row[12],
                }
            )

        return rules

    async def get_framework_coverage(
        self,
        framework: str,
        version: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get coverage statistics for a framework.

        Args:
            framework: Framework name.
            version: Optional framework version.

        Returns:
            Coverage statistics including total controls, rules mapped.
        """
        params = {"framework": framework}
        version_clause = ""

        if version:
            version_clause = "AND framework_version = :version"
            params["version"] = version

        # Count distinct controls
        controls_query = text(
            f"""
            SELECT COUNT(DISTINCT control_id)
            FROM framework_mappings
            WHERE framework = :framework
            {version_clause}
        """
        )

        # Count distinct rules
        rules_query = text(
            f"""
            SELECT COUNT(DISTINCT kensa_rule_id)
            FROM framework_mappings
            WHERE framework = :framework
            {version_clause}
        """
        )

        # Breakdown by severity
        severity_query = text(
            f"""
            SELECT kr.severity, COUNT(DISTINCT kr.rule_id) as count
            FROM kensa_rules kr
            INNER JOIN framework_mappings fm ON kr.rule_id = fm.kensa_rule_id
            WHERE fm.framework = :framework
            {version_clause}
            GROUP BY kr.severity
        """
        )

        # Breakdown by category
        category_query = text(
            f"""
            SELECT kr.category, COUNT(DISTINCT kr.rule_id) as count
            FROM kensa_rules kr
            INNER JOIN framework_mappings fm ON kr.rule_id = fm.kensa_rule_id
            WHERE fm.framework = :framework
            {version_clause}
            GROUP BY kr.category
            ORDER BY count DESC
        """
        )

        controls_count = self.db.execute(controls_query, params).scalar()
        rules_count = self.db.execute(rules_query, params).scalar()
        severity_breakdown = self.db.execute(severity_query, params).fetchall()
        category_breakdown = self.db.execute(category_query, params).fetchall()

        return {
            "framework": framework,
            "version": version,
            "framework_name": self._get_framework_name(framework, version),
            "total_controls": controls_count,
            "total_rules": rules_count,
            "severity_breakdown": {row[0]: row[1] for row in severity_breakdown},
            "category_breakdown": {row[0]: row[1] for row in category_breakdown},
        }

    async def get_rule_framework_refs(
        self,
        rule_id: str,
    ) -> Dict[str, Any]:
        """
        Get all framework references for a specific rule.

        Args:
            rule_id: Kensa rule ID.

        Returns:
            Dict with framework mappings for the rule.
        """
        query = text(
            """
            SELECT
                framework,
                framework_version,
                control_id,
                cis_section,
                cis_level,
                cis_type,
                stig_id,
                vuln_id,
                cci,
                severity
            FROM framework_mappings
            WHERE kensa_rule_id = :rule_id
            ORDER BY framework, framework_version
        """
        )

        result = self.db.execute(query, {"rule_id": rule_id}).fetchall()

        refs = {
            "cis": {},
            "stig": {},
            "nist_800_53": [],
            "pci_dss": [],
            "srg": [],
        }

        for row in result:
            framework = row[0]
            version = row[1]
            control_id = row[2]

            if framework == "cis":
                refs["cis"][version] = {
                    "section": row[3],
                    "level": row[4],
                    "type": row[5],
                }
            elif framework == "stig":
                refs["stig"][version] = {
                    "stig_id": row[6],
                    "vuln_id": row[7],
                    "cci": row[8],
                    "severity": row[9],
                }
            elif framework == "nist_800_53":
                refs["nist_800_53"].append(control_id)
            elif framework == "pci_dss":
                refs["pci_dss"].append(control_id)
            elif framework == "srg":
                refs["srg"].append(control_id)

        return refs

    async def get_control_rules(
        self,
        framework: str,
        control_id: str,
        version: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get all rules that satisfy a specific control.

        Args:
            framework: Framework name.
            control_id: Control ID to look up.
            version: Optional framework version.

        Returns:
            List of rules for the control.
        """
        params = {"framework": framework, "control_id": control_id}
        version_clause = ""

        if version:
            version_clause = "AND fm.framework_version = :version"
            params["version"] = version

        query = text(
            f"""
            SELECT
                kr.rule_id,
                kr.title,
                kr.severity,
                kr.category,
                fm.framework_version
            FROM kensa_rules kr
            INNER JOIN framework_mappings fm ON kr.rule_id = fm.kensa_rule_id
            WHERE fm.framework = :framework
            AND fm.control_id = :control_id
            {version_clause}
        """
        )

        result = self.db.execute(query, params).fetchall()

        return [
            {
                "rule_id": row[0],
                "title": row[1],
                "severity": row[2],
                "category": row[3],
                "framework_version": row[4],
            }
            for row in result
        ]

    async def list_frameworks(self) -> List[Dict[str, Any]]:
        """
        List all available frameworks and their versions.

        Returns:
            List of framework info with rule counts.
        """
        query = text(
            """
            SELECT
                framework,
                framework_version,
                COUNT(DISTINCT control_id) as controls,
                COUNT(DISTINCT kensa_rule_id) as rules
            FROM framework_mappings
            GROUP BY framework, framework_version
            ORDER BY framework, framework_version
        """
        )

        result = self.db.execute(query).fetchall()

        frameworks = []
        for row in result:
            framework = row[0]
            version = row[1]
            frameworks.append(
                {
                    "framework": framework,
                    "version": version,
                    "name": self._get_framework_name(framework, version),
                    "controls": row[2],
                    "rules": row[3],
                }
            )

        return frameworks

    async def search_controls(
        self,
        search_term: str,
        framework: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Search for controls by ID or description.

        Args:
            search_term: Search term (partial match).
            framework: Optional framework filter.

        Returns:
            List of matching controls.
        """
        params = {"search": f"%{search_term}%"}
        framework_clause = ""

        if framework:
            framework_clause = "AND fm.framework = :framework"
            params["framework"] = framework

        query = text(
            f"""
            SELECT DISTINCT
                fm.framework,
                fm.framework_version,
                fm.control_id,
                fm.stig_id,
                fm.cis_section,
                kr.rule_id,
                kr.title
            FROM framework_mappings fm
            INNER JOIN kensa_rules kr ON fm.kensa_rule_id = kr.rule_id
            WHERE (
                fm.control_id ILIKE :search
                OR fm.stig_id ILIKE :search
                OR fm.cis_section ILIKE :search
                OR kr.title ILIKE :search
            )
            {framework_clause}
            ORDER BY fm.framework, fm.control_id
            LIMIT 50
        """
        )

        result = self.db.execute(query, params).fetchall()

        return [
            {
                "framework": row[0],
                "framework_version": row[1],
                "control_id": row[2],
                "stig_id": row[3],
                "cis_section": row[4],
                "rule_id": row[5],
                "rule_title": row[6],
            }
            for row in result
        ]

    def _get_framework_name(
        self,
        framework: str,
        version: Optional[str] = None,
    ) -> str:
        """Get human-readable framework name."""
        if framework in self.FRAMEWORKS:
            if version and version in self.FRAMEWORKS[framework]:
                return self.FRAMEWORKS[framework][version]
            return list(self.FRAMEWORKS[framework].values())[0]
        return framework.upper()


__all__ = ["FrameworkMapper"]
