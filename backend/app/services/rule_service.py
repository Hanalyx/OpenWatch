"""
Enhanced Rule Service for OpenWatch
Provides advanced rule management with inheritance, platform detection, and dependency resolution
OW-REFACTOR-002: Migrating to Repository Pattern
"""
import asyncio
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime, timedelta
from enum import Enum
import logging

from backend.app.models.mongo_models import (
    ComplianceRule,
    RuleIntelligence,
    RemediationScript,
    PlatformImplementation
)
from backend.app.services.platform_capability_service import PlatformCapabilityService
from backend.app.services.rule_cache_service import RuleCacheService
# OW-REFACTOR-002: Import Repository Pattern and config
try:
    from backend.app.repositories import ComplianceRuleRepository
    from backend.app.config import get_settings
    REPOSITORY_AVAILABLE = True
except ImportError:
    REPOSITORY_AVAILABLE = False

logger = logging.getLogger(__name__)

class QueryPriority(Enum):
    """Query priority levels for performance optimization"""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4

class ParameterResolution(Enum):
    """Parameter conflict resolution strategies"""
    MOST_RESTRICTIVE = "most_restrictive"
    FRAMEWORK_SPECIFIC = "framework_specific" 
    PLATFORM_DEFAULT = "platform_default"
    EXPLICIT_OVERRIDE = "explicit_override"

class RuleService:
    """Enhanced Rule Service with advanced query capabilities"""
    
    def __init__(self, cache_service: Optional[RuleCacheService] = None):
        self.cache_service = cache_service or RuleCacheService()
        self.platform_service = PlatformCapabilityService()
        self.query_stats = {
            'total_queries': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'avg_response_time': 0.0
        }
        
    async def initialize(self):
        """Initialize the rule service and dependencies"""
        await self.cache_service.initialize()
        await self.platform_service.initialize()
        logger.info("RuleService initialized successfully")
    
    async def get_rules_by_platform(
        self,
        platform: str,
        platform_version: Optional[str] = None,
        framework: Optional[str] = None,
        framework_version: Optional[str] = None,
        severity_filter: Optional[List[str]] = None,
        category_filter: Optional[List[str]] = None,
        priority: QueryPriority = QueryPriority.NORMAL
    ) -> List[Dict[str, Any]]:
        """
        Get rules filtered by platform with comprehensive filtering
        
        Args:
            platform: Target platform (rhel, ubuntu, windows, etc.)
            platform_version: Specific platform version
            framework: Compliance framework (nist, cis, stig, etc.)
            framework_version: Specific framework version
            severity_filter: List of severities to include
            category_filter: List of categories to include
            priority: Query priority for caching strategy
        """
        start_time = datetime.utcnow()
        
        try:
            # Build cache key
            cache_key = self._build_cache_key(
                'platform_rules',
                platform=platform,
                version=platform_version,
                framework=framework,
                fw_version=framework_version,
                severities=severity_filter,
                categories=category_filter
            )
            
            # Try cache first (unless critical priority)
            if priority != QueryPriority.CRITICAL:
                cached_result = await self.cache_service.get(cache_key)
                if cached_result:
                    self._update_query_stats(start_time, cache_hit=True)
                    return cached_result
            
            # Build database query
            query_filter = await self._build_platform_query(
                platform, platform_version, framework, framework_version,
                severity_filter, category_filter
            )

            # Execute query with proper indexing
            # OW-REFACTOR-002: Use Repository Pattern if enabled
            settings = get_settings() if REPOSITORY_AVAILABLE else None
            if REPOSITORY_AVAILABLE and settings and settings.use_repository_pattern:
                logger.info(f"Using ComplianceRuleRepository for get_rules_by_platform ({platform})")
                repo = ComplianceRuleRepository()
                rules = await repo.find_many(query_filter)
            else:
                logger.debug(f"Using direct MongoDB find for get_rules_by_platform ({platform})")
                rules = await ComplianceRule.find(query_filter).to_list()

            # Resolve inheritance for each rule
            resolved_rules = []
            for rule in rules:
                resolved_rule = await self._resolve_rule_inheritance(rule)
                resolved_rules.append(resolved_rule)
            
            # Apply parameter overrides
            final_rules = []
            for rule_data in resolved_rules:
                final_rule = await self._apply_parameter_overrides(
                    rule_data, platform, platform_version, framework, framework_version
                )
                final_rules.append(final_rule)
            
            # Cache the result
            cache_ttl = self._get_cache_ttl(priority)
            await self.cache_service.set(cache_key, final_rules, ttl=cache_ttl)
            
            self._update_query_stats(start_time, cache_hit=False)
            logger.info(f"Retrieved {len(final_rules)} rules for platform {platform}")
            
            return final_rules
            
        except Exception as e:
            logger.error(f"Failed to retrieve rules for platform {platform}: {str(e)}")
            raise
    
    async def get_rule_with_dependencies(
        self,
        rule_id: str,
        resolve_depth: int = 3,
        include_conflicts: bool = True
    ) -> Dict[str, Any]:
        """
        Get a rule with its complete dependency chain
        
        Args:
            rule_id: Target rule identifier
            resolve_depth: Maximum dependency resolution depth
            include_conflicts: Whether to include conflicting rules
        """
        cache_key = f"rule_deps:{rule_id}:{resolve_depth}:{include_conflicts}"
        
        # Check cache
        cached = await self.cache_service.get(cache_key)
        if cached:
            return cached

        # Get base rule
        # OW-REFACTOR-002: Use Repository Pattern if enabled
        settings = get_settings() if REPOSITORY_AVAILABLE else None
        if REPOSITORY_AVAILABLE and settings and settings.use_repository_pattern:
            logger.info(f"Using ComplianceRuleRepository for get_rule_with_dependencies ({rule_id})")
            repo = ComplianceRuleRepository()
            rule = await repo.find_one({"rule_id": rule_id})
        else:
            logger.debug(f"Using direct MongoDB find_one for get_rule_with_dependencies ({rule_id})")
            rule = await ComplianceRule.find_one(ComplianceRule.rule_id == rule_id)

        if not rule:
            raise ValueError(f"Rule not found: {rule_id}")
        
        # Resolve dependencies
        dependency_graph = await self._build_dependency_graph(
            rule, resolve_depth, include_conflicts
        )
        
        result = {
            'rule': await self._resolve_rule_inheritance(rule),
            'dependencies': dependency_graph,
            'resolution_depth': resolve_depth,
            'total_dependencies': len(dependency_graph.get('requires', [])),
            'total_conflicts': len(dependency_graph.get('conflicts', [])),
            'resolution_time': datetime.utcnow().isoformat()
        }
        
        # Cache result
        await self.cache_service.set(cache_key, result, ttl=1800)  # 30 minutes
        
        return result
    
    async def detect_platform_capabilities(
        self,
        platform: str,
        platform_version: str,
        target_host: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Detect platform capabilities for rule applicability
        
        Args:
            platform: Platform name (rhel, ubuntu, etc.)
            platform_version: Platform version
            target_host: Optional target host for remote capability detection
        """
        return await self.platform_service.detect_capabilities(
            platform, platform_version, target_host
        )
    
    async def get_applicable_rules(
        self,
        platform: str,
        platform_version: str,
        detected_capabilities: Dict[str, Any],
        framework: Optional[str] = None,
        minimum_severity: str = "low"
    ) -> List[Dict[str, Any]]:
        """
        Get rules applicable to specific platform capabilities
        
        Args:
            platform: Target platform
            platform_version: Platform version  
            detected_capabilities: Capabilities detected on target system
            framework: Compliance framework filter
            minimum_severity: Minimum rule severity
        """
        # Get all potential rules
        severity_levels = ['info', 'low', 'medium', 'high', 'critical']
        severity_filter = severity_levels[severity_levels.index(minimum_severity):]
        
        candidate_rules = await self.get_rules_by_platform(
            platform=platform,
            platform_version=platform_version,
            framework=framework,
            severity_filter=severity_filter
        )
        
        # Filter by capabilities
        applicable_rules = []
        for rule in candidate_rules:
            if await self._is_rule_applicable(rule, detected_capabilities):
                applicable_rules.append(rule)
        
        return applicable_rules
    
    async def search_rules(
        self,
        search_query: str,
        platform_filter: Optional[str] = None,
        framework_filter: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        Full-text search across rules with advanced filtering
        
        Args:
            search_query: Text to search for
            platform_filter: Platform to filter by
            framework_filter: Framework to filter by  
            limit: Maximum results to return
            offset: Results offset for pagination
        """
        # Build search pipeline
        pipeline = []
        
        # Text search stage
        if search_query.strip():
            pipeline.append({
                "$match": {
                    "$text": {"$search": search_query}
                }
            })
            
            # Add text score for relevance
            pipeline.append({
                "$addFields": {
                    "search_score": {"$meta": "textScore"}
                }
            })
        
        # Platform filter
        if platform_filter:
            pipeline.append({
                "$match": {f"platform_implementations.{platform_filter}": {"$exists": True}}
            })
        
        # Framework filter
        if framework_filter:
            pipeline.append({
                "$match": {f"frameworks.{framework_filter}": {"$exists": True}}
            })
        
        # Sort by relevance and severity
        sort_stage = {"$sort": {}}
        if search_query.strip():
            sort_stage["$sort"]["search_score"] = {"$meta": "textScore"}
        sort_stage["$sort"]["severity_weight"] = -1
        sort_stage["$sort"]["updated_at"] = -1
        pipeline.append(sort_stage)
        
        # Pagination
        pipeline.extend([
            {"$skip": offset},
            {"$limit": limit}
        ])
        
        # Execute search
        collection = ComplianceRule.get_motor_collection()
        cursor = collection.aggregate(pipeline)
        results = await cursor.to_list(length=None)
        
        # Get total count for pagination
        count_pipeline = pipeline[:-2]  # Remove skip/limit
        count_pipeline.append({"$count": "total"})
        count_cursor = collection.aggregate(count_pipeline)
        count_result = await count_cursor.to_list(length=1)
        total_count = count_result[0]["total"] if count_result else 0
        
        return {
            'results': results,
            'total_count': total_count,
            'offset': offset,
            'limit': limit,
            'has_next': (offset + limit) < total_count,
            'has_prev': offset > 0
        }
    
    async def get_rule_statistics(self) -> Dict[str, Any]:
        """Get comprehensive rule statistics"""
        # Basic counts
        total_rules = await ComplianceRule.count()
        total_intelligence = await RuleIntelligence.count()
        total_scripts = await RemediationScript.count()
        
        # Severity distribution
        severity_pipeline = [
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        collection = ComplianceRule.get_motor_collection()
        severity_cursor = collection.aggregate(severity_pipeline)
        severity_stats = await severity_cursor.to_list(length=None)
        
        # Platform coverage
        platform_pipeline = [
            {"$unwind": {"path": "$platform_implementations", "preserveNullAndEmptyArrays": False}},
            {"$group": {"_id": "$platform_implementations.k", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        platform_cursor = collection.aggregate(platform_pipeline)
        platform_stats = await platform_cursor.to_list(length=None)
        
        # Framework coverage
        framework_pipeline = [
            {"$project": {"frameworks": {"$objectToArray": "$frameworks"}}},
            {"$unwind": "$frameworks"},
            {"$group": {"_id": "$frameworks.k", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        framework_cursor = collection.aggregate(framework_pipeline)
        framework_stats = await framework_cursor.to_list(length=None)
        
        return {
            'totals': {
                'rules': total_rules,
                'intelligence_records': total_intelligence,
                'remediation_scripts': total_scripts
            },
            'severity_distribution': {item['_id']: item['count'] for item in severity_stats},
            'platform_coverage': {item['_id']: item['count'] for item in platform_stats},
            'framework_coverage': {item['_id']: item['count'] for item in framework_stats},
            'query_performance': self.query_stats,
            'last_updated': datetime.utcnow().isoformat()
        }
    
    # Private helper methods
    
    def _build_cache_key(self, prefix: str, **kwargs) -> str:
        """Build cache key from parameters"""
        key_parts = [prefix]
        for k, v in sorted(kwargs.items()):
            if v is not None:
                if isinstance(v, list):
                    v = ",".join(sorted(v))
                key_parts.append(f"{k}:{v}")
        return ":".join(key_parts)
    
    async def _build_platform_query(
        self,
        platform: str,
        platform_version: Optional[str],
        framework: Optional[str],
        framework_version: Optional[str],
        severity_filter: Optional[List[str]],
        category_filter: Optional[List[str]]
    ) -> Dict[str, Any]:
        """Build optimized MongoDB query for platform rules"""
        query = {}
        
        # Platform implementation filter
        platform_key = f"platform_implementations.{platform}"
        query[platform_key] = {"$exists": True}
        
        # Platform version filter
        if platform_version:
            query[f"{platform_key}.versions"] = platform_version
        
        # Framework filter
        if framework:
            framework_key = f"frameworks.{framework}"
            if framework_version:
                query[f"{framework_key}.{framework_version}"] = {"$exists": True}
            else:
                query[framework_key] = {"$exists": True}
        
        # Severity filter
        if severity_filter:
            query["severity"] = {"$in": severity_filter}
        
        # Category filter  
        if category_filter:
            query["category"] = {"$in": category_filter}
        
        return query
    
    async def _resolve_rule_inheritance(self, rule: ComplianceRule) -> Dict[str, Any]:
        """Resolve rule inheritance chain
        OW-REFACTOR-002: Supports Repository Pattern
        """
        rule_data = rule.dict()

        # If rule doesn't inherit, return as-is
        if not rule.inherits_from:
            return rule_data

        # Get parent rule
        # OW-REFACTOR-002: Use Repository Pattern if enabled
        settings = get_settings() if REPOSITORY_AVAILABLE else None
        if REPOSITORY_AVAILABLE and settings and settings.use_repository_pattern:
            logger.debug(f"Using ComplianceRuleRepository for _resolve_rule_inheritance ({rule.inherits_from})")
            repo = ComplianceRuleRepository()
            parent_rule = await repo.find_one({"rule_id": rule.inherits_from})
        else:
            logger.debug(f"Using direct MongoDB find_one for _resolve_rule_inheritance ({rule.inherits_from})")
            parent_rule = await ComplianceRule.find_one(
                ComplianceRule.rule_id == rule.inherits_from
            )

        if not parent_rule:
            logger.warning(f"Parent rule not found: {rule.inherits_from}")
            return rule_data
        
        # Recursively resolve parent inheritance
        parent_data = await self._resolve_rule_inheritance(parent_rule)
        
        # Merge parent properties with child overrides
        resolved = self._merge_rule_properties(parent_data, rule_data)
        
        return resolved
    
    def _merge_rule_properties(self, parent: Dict[str, Any], child: Dict[str, Any]) -> Dict[str, Any]:
        """Merge parent and child rule properties"""
        merged = parent.copy()
        
        # Child properties override parent
        for key, value in child.items():
            if key in ['inherits_from', 'abstract']:
                continue  # Skip inheritance metadata
            
            if key == 'platform_implementations':
                # Merge platform implementations
                merged[key] = {**parent.get(key, {}), **value}
            elif key == 'frameworks':
                # Merge framework mappings
                merged[key] = self._merge_frameworks(parent.get(key, {}), value)
            elif key == 'dependencies':
                # Merge dependencies
                merged[key] = self._merge_dependencies(parent.get(key, {}), value)
            else:
                # Direct override
                merged[key] = value
        
        return merged
    
    def _merge_frameworks(self, parent_fw: Dict, child_fw: Dict) -> Dict[str, Any]:
        """Merge framework mappings from parent and child"""
        merged = parent_fw.copy()
        
        for framework, versions in child_fw.items():
            if framework in merged:
                # Merge versions
                if isinstance(versions, dict) and isinstance(merged[framework], dict):
                    merged[framework] = {**merged[framework], **versions}
                else:
                    merged[framework] = versions
            else:
                merged[framework] = versions
        
        return merged
    
    def _merge_dependencies(self, parent_deps: Dict, child_deps: Dict) -> Dict[str, List[str]]:
        """Merge dependency lists from parent and child"""
        merged = {
            'requires': list(set(parent_deps.get('requires', []) + child_deps.get('requires', []))),
            'conflicts': list(set(parent_deps.get('conflicts', []) + child_deps.get('conflicts', []))),
            'related': list(set(parent_deps.get('related', []) + child_deps.get('related', [])))
        }
        
        return merged
    
    async def _apply_parameter_overrides(
        self,
        rule_data: Dict[str, Any],
        platform: str,
        platform_version: Optional[str],
        framework: Optional[str],
        framework_version: Optional[str]
    ) -> Dict[str, Any]:
        """Apply parameter overrides based on context"""
        if not rule_data.get('parameter_overrides'):
            return rule_data
        
        # Build context key
        context_keys = []
        if platform and platform_version:
            context_keys.append(f"{platform}:{platform_version}")
        if platform:
            context_keys.append(platform)
        if framework and framework_version:
            context_keys.append(f"{framework}:{framework_version}")
        if framework:
            context_keys.append(framework)
        
        # Apply overrides in order of specificity (most specific last)
        overrides = rule_data.get('parameter_overrides', {})
        for context_key in reversed(context_keys):  # Apply in reverse order
            if context_key in overrides:
                rule_data = self._apply_override_values(rule_data, overrides[context_key])
        
        return rule_data
    
    def _apply_override_values(self, rule_data: Dict[str, Any], overrides: Dict[str, Any]) -> Dict[str, Any]:
        """Apply specific override values to rule data"""
        result = rule_data.copy()
        
        for key, value in overrides.items():
            if '.' in key:
                # Nested key (e.g., "check_content.expected_value")
                self._set_nested_value(result, key, value)
            else:
                # Direct key
                result[key] = value
        
        return result
    
    def _set_nested_value(self, data: Dict[str, Any], key_path: str, value: Any):
        """Set nested dictionary value using dot notation"""
        keys = key_path.split('.')
        current = data
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
    
    async def _build_dependency_graph(
        self,
        rule: ComplianceRule,
        max_depth: int,
        include_conflicts: bool,
        current_depth: int = 0,
        visited: Optional[Set[str]] = None
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Build dependency graph for a rule
        OW-REFACTOR-002: Supports Repository Pattern
        """
        if visited is None:
            visited = set()

        if current_depth >= max_depth or rule.rule_id in visited:
            return {'requires': [], 'conflicts': [], 'related': []}

        visited.add(rule.rule_id)
        dependencies = rule.dependencies or {}

        result = {
            'requires': [],
            'conflicts': [],
            'related': []
        }

        # OW-REFACTOR-002: Use Repository Pattern if enabled
        settings = get_settings() if REPOSITORY_AVAILABLE else None
        use_repo = REPOSITORY_AVAILABLE and settings and settings.use_repository_pattern
        repo = ComplianceRuleRepository() if use_repo else None

        # Process required dependencies
        for dep_id in dependencies.get('requires', []):
            if use_repo:
                dep_rule = await repo.find_one({"rule_id": dep_id})
            else:
                dep_rule = await ComplianceRule.find_one(ComplianceRule.rule_id == dep_id)

            if dep_rule:
                dep_data = await self._resolve_rule_inheritance(dep_rule)
                dep_graph = await self._build_dependency_graph(
                    dep_rule, max_depth, include_conflicts, current_depth + 1, visited
                )

                result['requires'].append({
                    'rule': dep_data,
                    'dependencies': dep_graph
                })

        # Process conflicts if requested
        if include_conflicts:
            for conflict_id in dependencies.get('conflicts', []):
                if use_repo:
                    conflict_rule = await repo.find_one({"rule_id": conflict_id})
                else:
                    conflict_rule = await ComplianceRule.find_one(ComplianceRule.rule_id == conflict_id)

                if conflict_rule:
                    conflict_data = await self._resolve_rule_inheritance(conflict_rule)
                    result['conflicts'].append({
                        'rule': conflict_data,
                        'reason': f"Conflicts with {rule.rule_id}"
                    })

        # Process related rules
        for related_id in dependencies.get('related', []):
            if use_repo:
                related_rule = await repo.find_one({"rule_id": related_id})
            else:
                related_rule = await ComplianceRule.find_one(ComplianceRule.rule_id == related_id)

            if related_rule:
                related_data = await self._resolve_rule_inheritance(related_rule)
                result['related'].append({
                    'rule': related_data,
                    'relationship': 'related'
                })

        visited.remove(rule.rule_id)
        return result
    
    async def _is_rule_applicable(
        self,
        rule: Dict[str, Any],
        capabilities: Dict[str, Any]
    ) -> bool:
        """Check if rule is applicable to detected capabilities"""
        rule_requirements = rule.get('platform_requirements', {})
        
        # Check required capabilities
        required = rule_requirements.get('required', {})
        for capability, expected in required.items():
            if capability not in capabilities:
                return False
            
            actual = capabilities[capability]
            if not self._capability_matches(actual, expected):
                return False
        
        # Check optional capabilities don't conflict
        optional = rule_requirements.get('optional', {})
        for capability, expected in optional.items():
            if capability in capabilities:
                actual = capabilities[capability]
                if not self._capability_matches(actual, expected):
                    return False
        
        return True
    
    def _capability_matches(self, actual: Any, expected: Any) -> bool:
        """Check if actual capability matches expected"""
        if isinstance(expected, dict):
            if 'min_version' in expected:
                return self._version_compare(actual, expected['min_version']) >= 0
            if 'max_version' in expected:
                return self._version_compare(actual, expected['max_version']) <= 0
            if 'exact_version' in expected:
                return actual == expected['exact_version']
        
        return actual == expected
    
    def _version_compare(self, version1: str, version2: str) -> int:
        """Compare version strings (simplified)"""
        try:
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]
            
            # Pad shorter version with zeros
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            for v1, v2 in zip(v1_parts, v2_parts):
                if v1 < v2:
                    return -1
                elif v1 > v2:
                    return 1
            
            return 0
        except:
            # Fall back to string comparison
            return -1 if version1 < version2 else (1 if version1 > version2 else 0)
    
    def _get_cache_ttl(self, priority: QueryPriority) -> int:
        """Get cache TTL based on query priority"""
        ttl_map = {
            QueryPriority.LOW: 3600,      # 1 hour
            QueryPriority.NORMAL: 1800,   # 30 minutes  
            QueryPriority.HIGH: 600,      # 10 minutes
            QueryPriority.CRITICAL: 0     # No cache
        }
        return ttl_map[priority]
    
    def _update_query_stats(self, start_time: datetime, cache_hit: bool):
        """Update query performance statistics"""
        duration = (datetime.utcnow() - start_time).total_seconds() * 1000  # ms
        
        self.query_stats['total_queries'] += 1
        if cache_hit:
            self.query_stats['cache_hits'] += 1
        else:
            self.query_stats['cache_misses'] += 1
        
        # Update rolling average response time
        total = self.query_stats['total_queries']
        current_avg = self.query_stats['avg_response_time']
        self.query_stats['avg_response_time'] = ((current_avg * (total - 1)) + duration) / total