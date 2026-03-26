"""
Scan Intelligence Service
Provides intelligent scanning capabilities including profile suggestion and optimization
"""

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.models.enums import ScanPriority

logger = logging.getLogger(__name__)


@dataclass
class HostInfo:
    """Host information for intelligent scanning decisions (internal use)"""

    id: str
    hostname: str
    ip_address: str
    operating_system: str
    environment: str
    tags: List[str]
    owner: Optional[str]
    port: int
    last_scan: Optional[str] = None
    compliance_score: Optional[float] = None


class RecommendedScanProfile(BaseModel):
    """
    Recommended scan profile with reasoning.

    Returned by ScanIntelligenceService to suggest the optimal
    compliance profile for a given host based on its characteristics.
    """

    profile_id: str = Field(..., description="XCCDF profile identifier")
    content_id: int = Field(..., description="SCAP content source ID")
    name: str = Field(..., description="Human-readable profile name")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score (0-1)")
    reasoning: List[str] = Field(..., description="List of reasons for this recommendation")
    estimated_duration: str = Field(..., description="Estimated scan duration")
    rule_count: int = Field(..., ge=0, description="Number of rules in profile")
    priority: ScanPriority = Field(..., description="Suggested scan priority")

    class Config:
        from_attributes = True


# Backward compatibility alias (deprecated - use RecommendedScanProfile)
ProfileSuggestion = RecommendedScanProfile


class ScanIntelligenceService:
    """Service for intelligent scan decision making"""

    # Default profile mappings by OS
    OS_DEFAULT_PROFILES = {
        "rhel": "xccdf_org.ssgproject.content_profile_cui",
        "centos": "xccdf_org.ssgproject.content_profile_cui",
        "fedora": "xccdf_org.ssgproject.content_profile_cui",
        "ubuntu": "xccdf_org.ssgproject.content_profile_cis_level1_server",
        "debian": "xccdf_org.ssgproject.content_profile_cis_level1_server",
        "sles": "xccdf_org.ssgproject.content_profile_stig",
        "windows": "xccdf_org.ssgproject.content_profile_cui",
    }

    # Compliance profiles by environment type
    ENVIRONMENT_PROFILES = {
        "production": {
            "federal": "xccdf_org.ssgproject.content_profile_stig",
            "healthcare": "xccdf_org.ssgproject.content_profile_hipaa",
            "financial": "xccdf_org.ssgproject.content_profile_pci",
            "default": "xccdf_org.ssgproject.content_profile_cui",
        },
        "staging": {"default": "xccdf_org.ssgproject.content_profile_cis_level1_server"},
        "development": {"default": "xccdf_org.ssgproject.content_profile_essential"},
        "test": {"default": "xccdf_org.ssgproject.content_profile_essential"},
    }

    # Tag-based profile mappings
    TAG_PROFILE_MAPPINGS = {
        "web": "xccdf_org.ssgproject.content_profile_cui",
        "database": "xccdf_org.ssgproject.content_profile_stig",
        "payment": "xccdf_org.ssgproject.content_profile_pci",
        "medical": "xccdf_org.ssgproject.content_profile_hipaa",
        "public": "xccdf_org.ssgproject.content_profile_cui",
        "dmz": "xccdf_org.ssgproject.content_profile_stig",
        "critical": "xccdf_org.ssgproject.content_profile_stig",
    }

    def __init__(self, db: Session):
        self.db = db

    async def suggest_scan_profile(self, host_id: str) -> RecommendedScanProfile:
        """
        Intelligently suggest the best scan profile for a host

        Args:
            host_id: UUID of the host to analyze

        Returns:
            RecommendedScanProfile with recommended profile and reasoning
        """
        try:
            # Get host information
            host_info = await self._get_host_info(host_id)

            if not host_info:
                raise ValueError(f"Host {host_id} not found")

            # Analyze host characteristics
            suggestions = []

            # 1. Environment-based suggestion
            env_suggestion = self._suggest_by_environment(host_info)
            if env_suggestion:
                suggestions.append(env_suggestion)

            # 2. Tag-based suggestion
            tag_suggestion = self._suggest_by_tags(host_info)
            if tag_suggestion:
                suggestions.append(tag_suggestion)

            # 3. Owner-based suggestion
            owner_suggestion = self._suggest_by_owner(host_info)
            if owner_suggestion:
                suggestions.append(owner_suggestion)

            # 4. OS-based fallback
            os_suggestion = self._suggest_by_os(host_info)
            suggestions.append(os_suggestion)

            # Select the best suggestion
            best_suggestion = self._select_best_suggestion(suggestions, host_info)

            # Enhance with content metadata
            enhanced_suggestion = await self._enhance_suggestion_with_content(best_suggestion)

            logger.info(
                f"Profile suggested for host {host_id}: {enhanced_suggestion.profile_id} (confidence: {enhanced_suggestion.confidence})"  # noqa: E501
            )
            return enhanced_suggestion

        except Exception as e:
            logger.error(f"Error suggesting profile for host {host_id}: {e}")
            # Return safe fallback
            return await self._get_fallback_suggestion(host_id)

    async def _get_host_info(self, host_id: str) -> Optional[HostInfo]:
        """Retrieve comprehensive host information"""
        try:
            result = self.db.execute(
                text("""
                SELECT
                    h.id, h.hostname, h.ip_address, h.operating_system,
                    h.environment, h.tags, h.owner, h.port,
                    s.started_at as last_scan,
                    sr.score as compliance_score
                FROM hosts h
                LEFT JOIN (
                    SELECT DISTINCT ON (host_id) host_id, started_at
                    FROM scans
                    WHERE status = 'completed'
                    ORDER BY host_id, started_at DESC
                ) s ON h.id = s.host_id
                LEFT JOIN scan_results sr ON sr.scan_id = (
                    SELECT id FROM scans
                    WHERE host_id = h.id AND status = 'completed'
                    ORDER BY started_at DESC LIMIT 1
                )
                WHERE h.id = :host_id AND h.is_active = true
            """),
                {"host_id": host_id},
            ).fetchone()

            if not result:
                return None

            # Parse tags
            tags = []
            if result.tags:
                tags = [tag.strip().lower() for tag in result.tags.split(",")]

            return HostInfo(
                id=result.id,
                hostname=result.hostname,
                ip_address=result.ip_address,
                operating_system=result.operating_system or "unknown",
                environment=result.environment or "production",
                tags=tags,
                owner=result.owner,
                port=result.port or 22,
                last_scan=result.last_scan.isoformat() if result.last_scan else None,
                compliance_score=result.compliance_score,
            )

        except Exception as e:
            logger.error(f"Error getting host info for {host_id}: {e}")
            return None

    def _suggest_by_environment(self, host_info: HostInfo) -> Optional[RecommendedScanProfile]:
        """Suggest profile based on environment and owner characteristics"""
        env = host_info.environment.lower()
        owner = (host_info.owner or "").lower()

        # Check for specific compliance requirements
        if env in self.ENVIRONMENT_PROFILES:
            env_profiles = self.ENVIRONMENT_PROFILES[env]

            # Check for federal/regulatory
            if "federal" in owner or "gov" in owner or "dod" in owner or "regulatory" in owner:
                if "federal" in env_profiles:
                    return RecommendedScanProfile(
                        profile_id=env_profiles["federal"],
                        content_id=1,  # Will be updated with actual content
                        name="STIG Compliance",
                        confidence=0.9,
                        reasoning=[
                            "Federal/regulatory owner detected",
                            f"Environment: {env}",
                        ],
                        estimated_duration="15-25 min",
                        rule_count=340,
                        priority=ScanPriority.HIGH,
                    )

            # Check for healthcare
            if any(keyword in owner for keyword in ["health", "medical", "hospital"]):
                if "healthcare" in env_profiles:
                    return RecommendedScanProfile(
                        profile_id=env_profiles["healthcare"],
                        content_id=1,
                        name="HIPAA Compliance",
                        confidence=0.85,
                        reasoning=[
                            "Healthcare organization detected",
                            f"Environment: {env}",
                        ],
                        estimated_duration="12-18 min",
                        rule_count=280,
                        priority=ScanPriority.HIGH,
                    )

            # Check for financial services
            if any(keyword in owner for keyword in ["bank", "financial", "payment", "finance"]):
                if "financial" in env_profiles:
                    return RecommendedScanProfile(
                        profile_id=env_profiles["financial"],
                        content_id=1,
                        name="PCI DSS Compliance",
                        confidence=0.85,
                        reasoning=[
                            "Financial services organization detected",
                            f"Environment: {env}",
                        ],
                        estimated_duration="10-15 min",
                        rule_count=250,
                        priority=ScanPriority.HIGH,
                    )

            # Use environment default
            return RecommendedScanProfile(
                profile_id=env_profiles["default"],
                content_id=1,
                name=f"{env.title()} Standard Scan",
                confidence=0.7,
                reasoning=[f"Environment-based selection: {env}"],
                estimated_duration="8-12 min",
                rule_count=180,
                priority=ScanPriority.NORMAL,
            )

        return None

    def _suggest_by_tags(self, host_info: HostInfo) -> Optional[RecommendedScanProfile]:
        """Suggest profile based on host tags"""
        for tag in host_info.tags:
            if tag in self.TAG_PROFILE_MAPPINGS:
                profile_id = self.TAG_PROFILE_MAPPINGS[tag]

                # Determine priority based on tag criticality
                priority = ScanPriority.NORMAL
                if tag in ["database", "payment", "medical", "critical", "dmz"]:
                    priority = ScanPriority.HIGH

                return RecommendedScanProfile(
                    profile_id=profile_id,
                    content_id=1,
                    name=f"{tag.title()} Optimized Scan",
                    confidence=0.8,
                    reasoning=[f"Host tagged as '{tag}'"],
                    estimated_duration="10-15 min",
                    rule_count=220,
                    priority=priority,
                )

        return None

    def _suggest_by_owner(self, host_info: HostInfo) -> Optional[RecommendedScanProfile]:
        """Suggest profile based on owner characteristics"""
        if not host_info.owner:
            return None

        owner = host_info.owner.lower()

        # Security team hosts get comprehensive scans
        if any(keyword in owner for keyword in ["security", "infosec", "cyber"]):
            return RecommendedScanProfile(
                profile_id="xccdf_org.ssgproject.content_profile_stig",
                content_id=1,
                name="Security Team Comprehensive Scan",
                confidence=0.75,
                reasoning=["Security team ownership detected"],
                estimated_duration="20-30 min",
                rule_count=380,
                priority=ScanPriority.HIGH,
            )

        return None

    def _suggest_by_os(self, host_info: HostInfo) -> RecommendedScanProfile:
        """Fallback suggestion based on operating system"""
        os_name = host_info.operating_system.lower()

        # Map OS variants
        for os_key in self.OS_DEFAULT_PROFILES:
            if os_key in os_name:
                return RecommendedScanProfile(
                    profile_id=self.OS_DEFAULT_PROFILES[os_key],
                    content_id=1,
                    name=f"{os_name.upper()} Standard Scan",
                    confidence=0.6,
                    reasoning=[f"Operating system: {host_info.operating_system}"],
                    estimated_duration="8-12 min",
                    rule_count=160,
                    priority=ScanPriority.NORMAL,
                )

        # Unknown OS fallback
        return RecommendedScanProfile(
            profile_id="xccdf_org.ssgproject.content_profile_cui",
            content_id=1,
            name="Universal Compliance Scan",
            confidence=0.4,
            reasoning=["Unknown OS - using universal profile"],
            estimated_duration="10-15 min",
            rule_count=180,
            priority=ScanPriority.NORMAL,
        )

    def _select_best_suggestion(
        self, suggestions: List[RecommendedScanProfile], host_info: HostInfo
    ) -> RecommendedScanProfile:
        """Select the best suggestion from multiple options"""
        if not suggestions:
            return self._suggest_by_os(host_info)

        # Sort by confidence and priority
        suggestions.sort(key=lambda s: (s.confidence, s.priority.value == "high"), reverse=True)

        best = suggestions[0]

        # Combine reasoning from top suggestions if they're close in confidence
        if len(suggestions) > 1 and suggestions[1].confidence >= best.confidence - 0.1:
            best.reasoning.extend(suggestions[1].reasoning)

        return best

    async def _enhance_suggestion_with_content(self, suggestion: RecommendedScanProfile) -> RecommendedScanProfile:
        """Enhance suggestion with actual SCAP content metadata"""
        try:
            # Find matching content and profile
            result = self.db.execute(
                text("""
                SELECT c.id, c.name, c.profiles
                FROM scap_content c
                WHERE c.profiles LIKE :profile_pattern
                ORDER BY c.created_at DESC
                LIMIT 1
            """),
                {"profile_pattern": f"%{suggestion.profile_id}%"},
            ).fetchone()

            if result:
                suggestion.content_id = result.id

                # Parse profiles to get accurate metadata
                try:
                    import json

                    profiles = json.loads(result.profiles or "[]")
                    for profile in profiles:
                        if profile.get("id") == suggestion.profile_id:
                            suggestion.name = profile.get("title", suggestion.name)
                            # Update rule count if available in profile metadata
                            break
                except Exception:
                    logger.debug("Ignoring exception during cleanup")

            return suggestion

        except Exception as e:
            logger.warning(f"Failed to enhance suggestion with content metadata: {e}")
            return suggestion

    async def _get_fallback_suggestion(self, host_id: str) -> RecommendedScanProfile:
        """Get a safe fallback suggestion when everything fails"""
        return RecommendedScanProfile(
            profile_id="xccdf_org.ssgproject.content_profile_cui",
            content_id=1,
            name="Quick Compliance Scan",
            confidence=0.3,
            reasoning=["Fallback suggestion - analysis failed"],
            estimated_duration="8-12 min",
            rule_count=150,
            priority=ScanPriority.NORMAL,
        )

    async def analyze_bulk_scan_feasibility(self, host_ids: List[str]) -> Dict[str, Any]:
        """Analyze the feasibility of scanning multiple hosts"""
        try:
            # Get host information for all hosts
            hosts_info = []
            for host_id in host_ids:
                host_info = await self._get_host_info(host_id)
                if host_info:
                    hosts_info.append(host_info)

            if not hosts_info:
                return {
                    "feasible": False,
                    "reason": "No valid hosts found",
                    "recommendations": [],
                }

            # Group by OS and environment for batching analysis
            os_groups: Dict[str, List[Any]] = {}
            env_groups: Dict[str, List[Any]] = {}

            for host in hosts_info:
                os_key = host.operating_system.lower()
                os_groups.setdefault(os_key, []).append(host)

                env_key = host.environment.lower()
                env_groups.setdefault(env_key, []).append(host)

            # Calculate estimated time and resource usage
            total_estimated_time = len(hosts_info) * 10  # Base 10 minutes per host
            max_parallel = min(5, len(hosts_info))  # Limit concurrent scans
            actual_time = total_estimated_time / max_parallel

            recommendations = []

            # OS diversity recommendation
            if len(os_groups) > 3:
                recommendations.append("Consider grouping by OS for better content optimization")

            # Environment mixing warning
            if "production" in env_groups and len(env_groups) > 1:
                recommendations.append("Production and non-production hosts mixed - consider separate scans")

            # Large batch warning
            if len(hosts_info) > 20:
                recommendations.append("Large batch detected - consider splitting into smaller groups")

            return {
                "feasible": True,
                "total_hosts": len(hosts_info),
                "estimated_time_minutes": int(actual_time),
                "max_parallel_scans": max_parallel,
                "os_groups": {k: len(v) for k, v in os_groups.items()},
                "environment_groups": {k: len(v) for k, v in env_groups.items()},
                "recommendations": recommendations,
            }

        except Exception as e:
            logger.error(f"Error analyzing bulk scan feasibility: {e}")
            return {
                "feasible": False,
                "reason": f"Analysis failed: {str(e)}",
                "recommendations": ["Review host selection and try again"],
            }
