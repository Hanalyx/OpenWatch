"""
Rule Association Service
Handles intelligent mapping between OpenWatch compliance rules and available remediation plugins.
Provides semantic matching, confidence scoring, and plugin recommendation capabilities.
"""
import asyncio
import logging
import uuid
from typing import Dict, List, Optional, Any, Tuple, Set
from datetime import datetime
from enum import Enum
from dataclasses import dataclass
import re
import json
from difflib import SequenceMatcher
import hashlib

from pydantic import BaseModel, Field, validator
from beanie import Document

from ..models.plugin_models import InstalledPlugin, PluginStatus
from .plugin_registry_service import PluginRegistryService
from .remediation_system_adapter import RemediationRule

logger = logging.getLogger(__name__)


# ============================================================================
# MODELS AND ENUMS
# ============================================================================

class MappingConfidence(str, Enum):
    """Confidence levels for rule-plugin mappings"""
    VERY_HIGH = "very_high"    # 90%+ confidence
    HIGH = "high"              # 70-89% confidence
    MEDIUM = "medium"          # 50-69% confidence
    LOW = "low"               # 25-49% confidence
    VERY_LOW = "very_low"     # <25% confidence


class MappingSource(str, Enum):
    """Source of the mapping"""
    MANUAL = "manual"          # Manually created by user
    SEMANTIC = "semantic"      # Created by semantic analysis
    FRAMEWORK = "framework"    # Framework-specific mapping (e.g., STIG)
    LEARNED = "learned"        # Machine learning based
    VERIFIED = "verified"      # Verified through execution results


class RulePluginMapping(Document):
    """Association between OpenWatch rule and remediation plugin"""
    mapping_id: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True)
    
    # Rule identification
    openwatch_rule_id: str = Field(..., description="OpenWatch rule identifier")
    openwatch_rule_title: Optional[str] = None
    openwatch_rule_description: Optional[str] = None
    framework: Optional[str] = None  # STIG, CIS, etc.
    
    # Plugin identification
    plugin_id: str = Field(..., description="Plugin identifier")
    plugin_rule_id: Optional[str] = None  # Plugin's internal rule ID
    plugin_rule_name: Optional[str] = None
    
    # Platform and context
    platform: str = Field(..., description="Target platform (rhel, ubuntu, etc.)")
    platform_version: Optional[str] = None
    
    # Mapping metadata
    confidence: MappingConfidence
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    mapping_source: MappingSource
    
    # Effectiveness tracking
    execution_count: int = Field(default=0, description="Times this mapping was used")
    success_count: int = Field(default=0, description="Successful executions")
    last_execution: Optional[datetime] = None
    effectiveness_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    
    # Context and configuration
    execution_context: Dict[str, Any] = Field(default_factory=dict)
    mapping_context: Dict[str, Any] = Field(default_factory=dict)
    
    # Validation status
    is_validated: bool = Field(default=False, description="Mapping has been validated through execution")
    validation_results: Dict[str, Any] = Field(default_factory=dict)
    
    # Metadata
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    tags: List[str] = Field(default_factory=list)

    class Settings:
        collection = "rule_plugin_mappings"
        indexes = [
            "mapping_id",
            "openwatch_rule_id",
            "plugin_id",
            "platform",
            "framework",
            "confidence",
            "mapping_source",
            ("openwatch_rule_id", "platform"),
            ("plugin_id", "platform")
        ]


class RuleMappingRecommendation(BaseModel):
    """Recommendation for rule-plugin mapping"""
    plugin_id: str
    plugin_name: str
    plugin_rule_id: Optional[str] = None
    plugin_rule_name: Optional[str] = None
    
    confidence: MappingConfidence
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    
    # Reasoning
    matching_factors: List[str] = Field(default_factory=list)
    semantic_similarity: float = Field(default=0.0, ge=0.0, le=1.0)
    framework_match: bool = Field(default=False)
    keyword_matches: List[str] = Field(default_factory=list)
    
    # Historical data
    historical_success_rate: Optional[float] = None
    usage_frequency: int = Field(default=0)
    
    # Context
    platform_compatibility: List[str] = Field(default_factory=list)
    estimated_execution_time: Optional[int] = None  # seconds
    risk_level: Optional[str] = None


@dataclass
class SemanticAnalysisResult:
    """Result of semantic analysis between rule and plugin"""
    similarity_score: float
    keyword_matches: List[str]
    framework_match: bool
    platform_compatibility: bool
    confidence_factors: List[str]


# ============================================================================
# RULE ASSOCIATION SERVICE
# ============================================================================

class RuleAssociationService:
    """
    Service for intelligent mapping between OpenWatch rules and remediation plugins
    
    Provides:
    - Semantic analysis for automatic mapping discovery
    - Confidence scoring based on multiple factors
    - Historical effectiveness tracking
    - Plugin recommendation system
    - Mapping validation and learning
    """
    
    def __init__(self):
        self.plugin_registry_service = PluginRegistryService()
        self._keyword_cache: Dict[str, Set[str]] = {}
        self._framework_mappings: Dict[str, Dict[str, str]] = self._load_framework_mappings()
    
    def _load_framework_mappings(self) -> Dict[str, Dict[str, str]]:
        """Load predefined framework-specific rule mappings"""
        # This would typically load from configuration files
        return {
            "stig": {
                "ssh-disable-root": "RHEL-08-010550",
                "password-complexity": "RHEL-08-020280",
                "firewall-enabled": "RHEL-08-040010"
            },
            "cis": {
                "ssh-disable-root": "5.2.8",
                "password-complexity": "5.3.1",
                "firewall-enabled": "3.4.1"
            }
        }
    
    async def create_mapping(
        self,
        openwatch_rule_id: str,
        plugin_id: str,
        platform: str,
        created_by: str,
        confidence: MappingConfidence = MappingConfidence.MEDIUM,
        mapping_source: MappingSource = MappingSource.MANUAL,
        plugin_rule_id: Optional[str] = None,
        execution_context: Dict[str, Any] = None
    ) -> RulePluginMapping:
        """Create a new rule-plugin mapping"""
        
        if execution_context is None:
            execution_context = {}
        
        # Calculate confidence score
        confidence_score = self._confidence_to_score(confidence)
        
        mapping = RulePluginMapping(
            openwatch_rule_id=openwatch_rule_id,
            plugin_id=plugin_id,
            plugin_rule_id=plugin_rule_id,
            platform=platform,
            confidence=confidence,
            confidence_score=confidence_score,
            mapping_source=mapping_source,
            execution_context=execution_context,
            created_by=created_by
        )
        
        await mapping.save()
        
        logger.info(f"Created rule mapping: {openwatch_rule_id} -> {plugin_id} ({platform}, {confidence.value})")
        return mapping
    
    async def get_mappings_for_rule(
        self,
        rule_id: str,
        platform: Optional[str] = None,
        framework: Optional[str] = None,
        min_confidence: MappingConfidence = MappingConfidence.LOW
    ) -> List[RulePluginMapping]:
        """Get all mappings for a specific OpenWatch rule"""
        query = {"openwatch_rule_id": rule_id}
        
        if platform:
            query["platform"] = platform
        if framework:
            query["framework"] = framework
        
        # Convert confidence to minimum score
        min_score = self._confidence_to_score(min_confidence)
        query["confidence_score"] = {"$gte": min_score}
        
        mappings = await RulePluginMapping.find(query).sort(
            -RulePluginMapping.confidence_score
        ).to_list()
        
        return mappings
    
    async def get_mappings_for_plugin(
        self,
        plugin_id: str,
        platform: Optional[str] = None,
        min_confidence: MappingConfidence = MappingConfidence.LOW
    ) -> List[RulePluginMapping]:
        """Get all mappings for a specific plugin"""
        query = {"plugin_id": plugin_id}
        
        if platform:
            query["platform"] = platform
        
        min_score = self._confidence_to_score(min_confidence)
        query["confidence_score"] = {"$gte": min_score}
        
        return await RulePluginMapping.find(query).sort(
            -RulePluginMapping.confidence_score
        ).to_list()
    
    async def discover_mappings_for_rule(
        self,
        rule_id: str,
        rule_title: Optional[str] = None,
        rule_description: Optional[str] = None,
        platform: str = "linux",
        framework: Optional[str] = None,
        limit: int = 10
    ) -> List[RuleMappingRecommendation]:
        """Discover potential plugin mappings for a rule using semantic analysis"""
        
        # Get all available plugins for the platform
        plugins = await self.plugin_registry_service.find_plugins({
            'status': PluginStatus.ACTIVE,
            'enabled_platforms': platform
        })
        
        recommendations = []
        
        for plugin in plugins:
            # Get plugin rules
            plugin_rules = await self._get_plugin_rules(plugin)
            
            # Analyze each plugin rule for compatibility
            for plugin_rule in plugin_rules:
                analysis = await self._perform_semantic_analysis(
                    rule_id=rule_id,
                    rule_title=rule_title,
                    rule_description=rule_description,
                    framework=framework,
                    plugin=plugin,
                    plugin_rule=plugin_rule,
                    platform=platform
                )
                
                if analysis.similarity_score > 0.2:  # Minimum threshold
                    # Get historical data
                    historical_data = await self._get_historical_effectiveness(
                        rule_id, plugin.plugin_id, platform
                    )
                    
                    recommendation = RuleMappingRecommendation(
                        plugin_id=plugin.plugin_id,
                        plugin_name=plugin.name,
                        plugin_rule_id=plugin_rule.get("id"),
                        plugin_rule_name=plugin_rule.get("name"),
                        confidence=self._score_to_confidence(analysis.similarity_score),
                        confidence_score=analysis.similarity_score,
                        matching_factors=analysis.confidence_factors,
                        semantic_similarity=analysis.similarity_score,
                        framework_match=analysis.framework_match,
                        keyword_matches=analysis.keyword_matches,
                        historical_success_rate=historical_data.get("success_rate"),
                        usage_frequency=historical_data.get("usage_count", 0),
                        platform_compatibility=[platform]
                    )
                    
                    recommendations.append(recommendation)
        
        # Sort by confidence score and limit results
        recommendations.sort(key=lambda x: x.confidence_score, reverse=True)
        return recommendations[:limit]
    
    async def recommend_plugins_for_rules(
        self,
        rule_ids: List[str],
        platform: str = "linux",
        framework: Optional[str] = None,
        prefer_existing_mappings: bool = True
    ) -> Dict[str, List[RuleMappingRecommendation]]:
        """Get plugin recommendations for multiple rules"""
        recommendations = {}
        
        for rule_id in rule_ids:
            # Check for existing mappings first
            if prefer_existing_mappings:
                existing_mappings = await self.get_mappings_for_rule(
                    rule_id, platform, framework, MappingConfidence.MEDIUM
                )
                
                if existing_mappings:
                    # Convert mappings to recommendations
                    rule_recommendations = []
                    for mapping in existing_mappings:
                        plugin = await self.plugin_registry_service.get_plugin(mapping.plugin_id)
                        if plugin:
                            recommendation = RuleMappingRecommendation(
                                plugin_id=plugin.plugin_id,
                                plugin_name=plugin.name,
                                plugin_rule_id=mapping.plugin_rule_id,
                                plugin_rule_name=mapping.plugin_rule_name,
                                confidence=mapping.confidence,
                                confidence_score=mapping.confidence_score,
                                matching_factors=["existing_mapping"],
                                historical_success_rate=mapping.effectiveness_score,
                                usage_frequency=mapping.execution_count,
                                platform_compatibility=[platform]
                            )
                            rule_recommendations.append(recommendation)
                    
                    recommendations[rule_id] = rule_recommendations
                    continue
            
            # Discover new mappings
            discovered = await self.discover_mappings_for_rule(
                rule_id, platform=platform, framework=framework
            )
            recommendations[rule_id] = discovered
        
        return recommendations
    
    async def validate_mapping(
        self,
        mapping_id: str,
        execution_result: Dict[str, Any],
        success: bool
    ) -> RulePluginMapping:
        """Update mapping based on execution results"""
        mapping = await RulePluginMapping.find_one(
            RulePluginMapping.mapping_id == mapping_id
        )
        
        if not mapping:
            raise ValueError(f"Mapping not found: {mapping_id}")
        
        # Update execution statistics
        mapping.execution_count += 1
        mapping.last_execution = datetime.utcnow()
        
        if success:
            mapping.success_count += 1
        
        # Calculate effectiveness score
        if mapping.execution_count > 0:
            mapping.effectiveness_score = mapping.success_count / mapping.execution_count
        
        # Update validation status
        if not mapping.is_validated and mapping.execution_count >= 3:
            mapping.is_validated = True
        
        # Update confidence based on effectiveness
        if mapping.effectiveness_score is not None:
            if mapping.effectiveness_score > 0.9:
                mapping.confidence = MappingConfidence.VERY_HIGH
            elif mapping.effectiveness_score > 0.7:
                mapping.confidence = MappingConfidence.HIGH
            elif mapping.effectiveness_score > 0.5:
                mapping.confidence = MappingConfidence.MEDIUM
            elif mapping.effectiveness_score > 0.3:
                mapping.confidence = MappingConfidence.LOW
            else:
                mapping.confidence = MappingConfidence.VERY_LOW
            
            mapping.confidence_score = mapping.effectiveness_score
        
        # Store validation results
        mapping.validation_results[str(datetime.utcnow())] = {
            "success": success,
            "execution_result": execution_result
        }
        
        mapping.updated_at = datetime.utcnow()
        await mapping.save()
        
        logger.info(f"Updated mapping validation: {mapping_id} (success: {success}, effectiveness: {mapping.effectiveness_score})")
        return mapping
    
    async def get_mapping_statistics(self) -> Dict[str, Any]:
        """Get statistics about rule-plugin mappings"""
        total_mappings = await RulePluginMapping.count()
        
        # Get mappings by confidence
        confidence_stats = {}
        for confidence in MappingConfidence:
            count = await RulePluginMapping.find(
                {"confidence": confidence}
            ).count()
            confidence_stats[confidence.value] = count
        
        # Get mappings by source
        source_stats = {}
        for source in MappingSource:
            count = await RulePluginMapping.find(
                {"mapping_source": source}
            ).count()
            source_stats[source.value] = count
        
        # Get effectiveness statistics
        validated_mappings = await RulePluginMapping.find(
            {"is_validated": True}
        ).to_list()
        
        if validated_mappings:
            avg_effectiveness = sum(
                m.effectiveness_score for m in validated_mappings 
                if m.effectiveness_score is not None
            ) / len(validated_mappings)
        else:
            avg_effectiveness = 0.0
        
        # Top performing mappings
        top_mappings = await RulePluginMapping.find(
            {"execution_count": {"$gt": 0}}
        ).sort(-RulePluginMapping.effectiveness_score).limit(10).to_list()
        
        return {
            "total_mappings": total_mappings,
            "confidence_distribution": confidence_stats,
            "source_distribution": source_stats,
            "validated_mappings": len(validated_mappings),
            "average_effectiveness": avg_effectiveness,
            "top_performing_mappings": [
                {
                    "mapping_id": m.mapping_id,
                    "rule_id": m.openwatch_rule_id,
                    "plugin_id": m.plugin_id,
                    "effectiveness": m.effectiveness_score,
                    "executions": m.execution_count
                }
                for m in top_mappings[:5]
            ]
        }
    
    async def bulk_import_mappings(
        self,
        mappings_data: List[Dict[str, Any]],
        created_by: str,
        source: MappingSource = MappingSource.FRAMEWORK
    ) -> List[RulePluginMapping]:
        """Bulk import rule-plugin mappings"""
        created_mappings = []
        
        for mapping_data in mappings_data:
            try:
                mapping = await self.create_mapping(
                    openwatch_rule_id=mapping_data["rule_id"],
                    plugin_id=mapping_data["plugin_id"],
                    platform=mapping_data.get("platform", "linux"),
                    created_by=created_by,
                    confidence=MappingConfidence(mapping_data.get("confidence", "medium")),
                    mapping_source=source,
                    plugin_rule_id=mapping_data.get("plugin_rule_id"),
                    execution_context=mapping_data.get("context", {})
                )
                created_mappings.append(mapping)
            except Exception as e:
                logger.error(f"Failed to create mapping for {mapping_data}: {e}")
        
        logger.info(f"Bulk imported {len(created_mappings)} rule mappings")
        return created_mappings
    
    async def _perform_semantic_analysis(
        self,
        rule_id: str,
        rule_title: Optional[str],
        rule_description: Optional[str],
        framework: Optional[str],
        plugin: InstalledPlugin,
        plugin_rule: Dict[str, Any],
        platform: str
    ) -> SemanticAnalysisResult:
        """Perform semantic analysis between rule and plugin rule"""
        
        # Combine rule text for analysis
        rule_text = " ".join(filter(None, [rule_id, rule_title, rule_description]))
        plugin_text = " ".join(filter(None, [
            plugin_rule.get("name", ""),
            plugin_rule.get("description", ""),
            plugin_rule.get("id", "")
        ]))
        
        # Calculate text similarity
        similarity_score = SequenceMatcher(None, rule_text.lower(), plugin_text.lower()).ratio()
        
        # Extract and match keywords
        rule_keywords = self._extract_keywords(rule_text)
        plugin_keywords = self._extract_keywords(plugin_text)
        keyword_matches = list(rule_keywords.intersection(plugin_keywords))
        
        # Check framework-specific mappings
        framework_match = False
        if framework and framework.lower() in self._framework_mappings:
            framework_rules = self._framework_mappings[framework.lower()]
            if rule_id in framework_rules:
                expected_rule = framework_rules[rule_id]
                if expected_rule in plugin_text:
                    framework_match = True
                    similarity_score = max(similarity_score, 0.8)  # Boost for framework match
        
        # Check platform compatibility
        platform_compatibility = platform in plugin.enabled_platforms
        
        # Calculate confidence factors
        confidence_factors = []
        if similarity_score > 0.7:
            confidence_factors.append("high_text_similarity")
        if len(keyword_matches) >= 2:
            confidence_factors.append("multiple_keyword_matches")
        if framework_match:
            confidence_factors.append("framework_mapping")
        if platform_compatibility:
            confidence_factors.append("platform_compatible")
        
        # Adjust similarity score based on factors
        if framework_match:
            similarity_score += 0.2
        if len(keyword_matches) >= 3:
            similarity_score += 0.1
        if not platform_compatibility:
            similarity_score *= 0.5
        
        similarity_score = min(similarity_score, 1.0)
        
        return SemanticAnalysisResult(
            similarity_score=similarity_score,
            keyword_matches=keyword_matches,
            framework_match=framework_match,
            platform_compatibility=platform_compatibility,
            confidence_factors=confidence_factors
        )
    
    def _extract_keywords(self, text: str) -> Set[str]:
        """Extract keywords from text for matching"""
        # Use cached keywords if available
        text_hash = hashlib.md5(text.encode()).hexdigest()
        if text_hash in self._keyword_cache:
            return self._keyword_cache[text_hash]
        
        # Common security/system keywords
        keywords = set()
        
        # Clean text
        text = re.sub(r'[^\w\s-]', ' ', text.lower())
        words = text.split()
        
        # Security-specific keywords
        security_keywords = {
            'ssh', 'password', 'authentication', 'firewall', 'encryption',
            'ssl', 'tls', 'certificate', 'audit', 'logging', 'permission',
            'access', 'control', 'policy', 'compliance', 'security',
            'hardening', 'configuration', 'service', 'daemon', 'user',
            'group', 'file', 'directory', 'network', 'port', 'protocol',
            'crypto', 'hash', 'key', 'disable', 'enable', 'configure',
            'kernel', 'system', 'root', 'admin', 'sudo', 'privilege'
        }
        
        for word in words:
            # Include security keywords
            if word in security_keywords:
                keywords.add(word)
            # Include longer technical terms
            elif len(word) > 4 and re.match(r'^[a-z][a-z0-9_-]*[a-z0-9]$', word):
                keywords.add(word)
        
        # Cache the result
        self._keyword_cache[text_hash] = keywords
        return keywords
    
    async def _get_plugin_rules(self, plugin: InstalledPlugin) -> List[Dict[str, Any]]:
        """Get rules/capabilities from a plugin"""
        # This would query the plugin for its available rules
        # For now, return mock data based on plugin metadata
        
        rules = []
        
        # Extract from plugin description or metadata
        if hasattr(plugin, 'applied_to_rules') and plugin.applied_to_rules:
            for rule_id in plugin.applied_to_rules:
                rules.append({
                    "id": rule_id,
                    "name": rule_id.replace('_', ' ').title(),
                    "description": f"Remediation rule for {rule_id}"
                })
        
        # If no specific rules, create generic entry
        if not rules:
            rules.append({
                "id": f"{plugin.plugin_id}_generic",
                "name": f"{plugin.name} Generic Rule",
                "description": plugin.description or f"Generic remediation using {plugin.name}"
            })
        
        return rules
    
    async def _get_historical_effectiveness(
        self,
        rule_id: str,
        plugin_id: str,
        platform: str
    ) -> Dict[str, Any]:
        """Get historical effectiveness data for a rule-plugin combination"""
        mappings = await RulePluginMapping.find({
            "openwatch_rule_id": rule_id,
            "plugin_id": plugin_id,
            "platform": platform
        }).to_list()
        
        if not mappings:
            return {"success_rate": None, "usage_count": 0}
        
        total_executions = sum(m.execution_count for m in mappings)
        total_successes = sum(m.success_count for m in mappings)
        
        success_rate = total_successes / total_executions if total_executions > 0 else None
        
        return {
            "success_rate": success_rate,
            "usage_count": total_executions
        }
    
    def _confidence_to_score(self, confidence: MappingConfidence) -> float:
        """Convert confidence enum to numeric score"""
        confidence_scores = {
            MappingConfidence.VERY_HIGH: 0.95,
            MappingConfidence.HIGH: 0.8,
            MappingConfidence.MEDIUM: 0.6,
            MappingConfidence.LOW: 0.4,
            MappingConfidence.VERY_LOW: 0.2
        }
        return confidence_scores.get(confidence, 0.5)
    
    def _score_to_confidence(self, score: float) -> MappingConfidence:
        """Convert numeric score to confidence enum"""
        if score >= 0.9:
            return MappingConfidence.VERY_HIGH
        elif score >= 0.7:
            return MappingConfidence.HIGH
        elif score >= 0.5:
            return MappingConfidence.MEDIUM
        elif score >= 0.25:
            return MappingConfidence.LOW
        else:
            return MappingConfidence.VERY_LOW


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

async def create_stig_mappings(service: RuleAssociationService, created_by: str) -> List[RulePluginMapping]:
    """Create common STIG rule mappings"""
    stig_mappings = [
        {
            "rule_id": "ssh-disable-root-login",
            "plugin_id": "aegis-remediation-plugin",
            "plugin_rule_id": "RHEL-08-010550",
            "platform": "rhel8",
            "confidence": "high"
        },
        {
            "rule_id": "password-complexity-requirements",
            "plugin_id": "aegis-remediation-plugin", 
            "plugin_rule_id": "RHEL-08-020280",
            "platform": "rhel8",
            "confidence": "high"
        },
        {
            "rule_id": "firewall-default-deny",
            "plugin_id": "aegis-remediation-plugin",
            "plugin_rule_id": "RHEL-08-040010",
            "platform": "rhel8",
            "confidence": "high"
        }
    ]
    
    return await service.bulk_import_mappings(
        stig_mappings, created_by, MappingSource.FRAMEWORK
    )


async def create_cis_mappings(service: RuleAssociationService, created_by: str) -> List[RulePluginMapping]:
    """Create common CIS benchmark mappings"""
    cis_mappings = [
        {
            "rule_id": "ssh-protocol-version",
            "plugin_id": "ansible-remediation-plugin",
            "plugin_rule_id": "5.2.4",
            "platform": "ubuntu20",
            "confidence": "high"
        },
        {
            "rule_id": "audit-log-configuration",
            "plugin_id": "ansible-remediation-plugin",
            "plugin_rule_id": "4.1.1",
            "platform": "ubuntu20", 
            "confidence": "medium"
        }
    ]
    
    return await service.bulk_import_mappings(
        cis_mappings, created_by, MappingSource.FRAMEWORK
    )