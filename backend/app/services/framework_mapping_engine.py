"""
Framework Mapping Engine
Provides intelligent cross-framework control mapping and unified compliance orchestration
"""
import asyncio
from typing import Dict, List, Set, Optional, Tuple, Any
from datetime import datetime
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict
import json

from backend.app.models.unified_rule_models import (
    UnifiedComplianceRule, FrameworkMapping, Platform, PlatformImplementation
)


class MappingConfidence(str, Enum):
    """Confidence levels for framework mappings"""
    HIGH = "high"           # >90% confidence - direct mapping
    MEDIUM = "medium"       # 70-90% confidence - semantic mapping  
    LOW = "low"            # 50-70% confidence - conceptual mapping
    UNCERTAIN = "uncertain" # <50% confidence - needs review


class MappingType(str, Enum):
    """Types of framework control mappings"""
    DIRECT = "direct"                    # One-to-one mapping
    SUBSET = "subset"                    # Framework A is subset of Framework B
    SUPERSET = "superset"                # Framework A is superset of Framework B
    OVERLAP = "overlap"                  # Partial overlap between frameworks
    EQUIVALENT = "equivalent"            # Functionally equivalent controls
    DERIVED = "derived"                  # Framework B derived from Framework A
    COMPLEMENTARY = "complementary"      # Controls complement each other


@dataclass
class ControlMapping:
    """Mapping between controls in different frameworks"""
    source_framework: str
    source_control: str
    target_framework: str
    target_control: str
    mapping_type: MappingType
    confidence: MappingConfidence
    rationale: str
    evidence: List[str]
    implementation_notes: Optional[str] = None
    exceptions: List[str] = None
    created_at: datetime = None
    verified_by: Optional[str] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if self.exceptions is None:
            self.exceptions = []


@dataclass
class FrameworkRelationship:
    """Relationship analysis between two frameworks"""
    framework_a: str
    framework_b: str
    overlap_percentage: float
    common_controls: int
    framework_a_unique: int
    framework_b_unique: int
    relationship_type: str
    strength: float
    bidirectional_mappings: List[ControlMapping]
    implementation_synergies: List[str]
    conflict_areas: List[str]


@dataclass
class UnifiedImplementation:
    """Unified implementation that satisfies multiple frameworks"""
    implementation_id: str
    description: str
    frameworks_satisfied: List[str]
    control_mappings: Dict[str, List[str]]  # framework_id -> control_ids
    implementation_details: Dict[str, Any]
    platform_specifics: Dict[Platform, PlatformImplementation]
    exceeds_frameworks: List[str]  # Frameworks where this exceeds requirements
    compliance_justification: str
    risk_assessment: str
    effort_estimate: str


class FrameworkMappingEngine:
    """Engine for intelligent cross-framework control mapping and orchestration"""
    
    def __init__(self):
        """Initialize the framework mapping engine"""
        self.control_mappings: Dict[str, List[ControlMapping]] = defaultdict(list)
        self.framework_relationships: Dict[Tuple[str, str], FrameworkRelationship] = {}
        self.unified_implementations: Dict[str, UnifiedImplementation] = {}
        self.mapping_cache: Dict[str, Any] = {}
        
        # Framework hierarchies and inheritance patterns
        self.framework_hierarchies = {
            "srg_os": {
                "parent": None,
                "children": ["stig_rhel8", "stig_rhel9", "stig_ubuntu20", "stig_ubuntu22"]
            },
            "nist_800_53_r5": {
                "parent": None,
                "children": []
            },
            "cis_v8": {
                "parent": None,
                "children": []
            }
        }
        
        # Known framework relationships
        self.framework_affinities = {
            ("nist_800_53_r5", "iso_27001_2022"): 0.85,  # High affinity
            ("cis_v8", "nist_800_53_r5"): 0.75,          # Medium-high affinity
            ("pci_dss_v4", "iso_27001_2022"): 0.70,      # Medium affinity
            ("srg_os", "nist_800_53_r5"): 0.90,          # Very high affinity
        }
    
    async def load_predefined_mappings(self, mappings_file: str) -> int:
        """Load predefined control mappings from JSON file"""
        try:
            with open(mappings_file, 'r') as f:
                mappings_data = json.load(f)
            
            loaded_count = 0
            for mapping_data in mappings_data.get('mappings', []):
                control_mapping = ControlMapping(
                    source_framework=mapping_data['source_framework'],
                    source_control=mapping_data['source_control'],
                    target_framework=mapping_data['target_framework'],
                    target_control=mapping_data['target_control'],
                    mapping_type=MappingType(mapping_data['mapping_type']),
                    confidence=MappingConfidence(mapping_data['confidence']),
                    rationale=mapping_data['rationale'],
                    evidence=mapping_data.get('evidence', []),
                    implementation_notes=mapping_data.get('implementation_notes'),
                    exceptions=mapping_data.get('exceptions', [])
                )
                
                mapping_key = f"{control_mapping.source_framework}:{control_mapping.source_control}"
                self.control_mappings[mapping_key].append(control_mapping)
                loaded_count += 1
            
            return loaded_count
            
        except Exception as e:
            print(f"Error loading predefined mappings from {mappings_file}: {e}")
            return 0
    
    async def discover_control_mappings(
        self,
        source_framework: str,
        target_framework: str,
        unified_rules: List[UnifiedComplianceRule]
    ) -> List[ControlMapping]:
        """Discover potential control mappings between frameworks using unified rules"""
        discovered_mappings = []
        
        # Build control relationship matrix from unified rules
        control_relationships = defaultdict(lambda: defaultdict(set))
        
        for rule in unified_rules:
            source_controls = set()
            target_controls = set()
            
            for mapping in rule.framework_mappings:
                if mapping.framework_id == source_framework:
                    source_controls.update(mapping.control_ids)
                elif mapping.framework_id == target_framework:
                    target_controls.update(mapping.control_ids)
            
            # Create bidirectional relationships
            for source_control in source_controls:
                for target_control in target_controls:
                    control_relationships[source_control][target_control].add(rule.rule_id)
        
        # Analyze relationships and create mappings
        for source_control, target_mappings in control_relationships.items():
            for target_control, shared_rules in target_mappings.items():
                if len(shared_rules) > 0:
                    # Determine mapping characteristics
                    mapping_type, confidence = await self._analyze_mapping_characteristics(
                        source_framework, source_control,
                        target_framework, target_control,
                        shared_rules, unified_rules
                    )
                    
                    control_mapping = ControlMapping(
                        source_framework=source_framework,
                        source_control=source_control,
                        target_framework=target_framework,
                        target_control=target_control,
                        mapping_type=mapping_type,
                        confidence=confidence,
                        rationale=f"Mapped through {len(shared_rules)} shared unified rules",
                        evidence=[f"Unified rule: {rule_id}" for rule_id in list(shared_rules)[:3]],
                        implementation_notes=f"Implementation shared across {len(shared_rules)} rules"
                    )
                    
                    discovered_mappings.append(control_mapping)
        
        return discovered_mappings
    
    async def _analyze_mapping_characteristics(
        self,
        source_framework: str, source_control: str,
        target_framework: str, target_control: str,
        shared_rules: Set[str],
        unified_rules: List[UnifiedComplianceRule]
    ) -> Tuple[MappingType, MappingConfidence]:
        """Analyze characteristics of a control mapping"""
        
        # Count total rules for each control
        source_total_rules = 0
        target_total_rules = 0
        
        for rule in unified_rules:
            for mapping in rule.framework_mappings:
                if mapping.framework_id == source_framework and source_control in mapping.control_ids:
                    source_total_rules += 1
                elif mapping.framework_id == target_framework and target_control in mapping.control_ids:
                    target_total_rules += 1
        
        # Calculate overlap ratios
        shared_count = len(shared_rules)
        source_overlap = shared_count / source_total_rules if source_total_rules > 0 else 0
        target_overlap = shared_count / target_total_rules if target_total_rules > 0 else 0
        
        # Determine mapping type
        if source_overlap >= 0.9 and target_overlap >= 0.9:
            mapping_type = MappingType.EQUIVALENT
            confidence = MappingConfidence.HIGH
        elif source_overlap >= 0.8 and target_overlap >= 0.8:
            mapping_type = MappingType.DIRECT
            confidence = MappingConfidence.HIGH
        elif source_overlap >= 0.6 or target_overlap >= 0.6:
            if source_overlap > target_overlap:
                mapping_type = MappingType.SUPERSET
            else:
                mapping_type = MappingType.SUBSET
            confidence = MappingConfidence.MEDIUM
        elif shared_count >= 2:
            mapping_type = MappingType.OVERLAP
            confidence = MappingConfidence.MEDIUM
        else:
            mapping_type = MappingType.COMPLEMENTARY
            confidence = MappingConfidence.LOW
        
        # Adjust confidence based on framework affinity
        framework_pair = (source_framework, target_framework)
        reverse_pair = (target_framework, source_framework)
        
        if framework_pair in self.framework_affinities:
            affinity = self.framework_affinities[framework_pair]
        elif reverse_pair in self.framework_affinities:
            affinity = self.framework_affinities[reverse_pair]
        else:
            affinity = 0.5  # Default affinity
        
        # Boost confidence for high-affinity frameworks
        if affinity >= 0.8 and confidence == MappingConfidence.MEDIUM:
            confidence = MappingConfidence.HIGH
        elif affinity <= 0.6 and confidence == MappingConfidence.HIGH:
            confidence = MappingConfidence.MEDIUM
        
        return mapping_type, confidence
    
    async def analyze_framework_relationship(
        self,
        framework_a: str,
        framework_b: str,
        unified_rules: List[UnifiedComplianceRule]
    ) -> FrameworkRelationship:
        """Analyze the relationship between two frameworks"""
        
        # Discover mappings in both directions
        mappings_a_to_b = await self.discover_control_mappings(framework_a, framework_b, unified_rules)
        mappings_b_to_a = await self.discover_control_mappings(framework_b, framework_a, unified_rules)
        
        # Combine bidirectional mappings
        all_mappings = mappings_a_to_b + mappings_b_to_a
        
        # Get all controls for each framework
        framework_a_controls = set()
        framework_b_controls = set()
        
        for rule in unified_rules:
            for mapping in rule.framework_mappings:
                if mapping.framework_id == framework_a:
                    framework_a_controls.update(mapping.control_ids)
                elif mapping.framework_id == framework_b:
                    framework_b_controls.update(mapping.control_ids)
        
        # Calculate relationship metrics
        mapped_a_controls = set()
        mapped_b_controls = set()
        
        for mapping in all_mappings:
            if mapping.source_framework == framework_a:
                mapped_a_controls.add(mapping.source_control)
                mapped_b_controls.add(mapping.target_control)
            else:
                mapped_a_controls.add(mapping.target_control)
                mapped_b_controls.add(mapping.source_control)
        
        common_controls = len(mapped_a_controls.intersection(mapped_b_controls))
        framework_a_unique = len(framework_a_controls - mapped_a_controls)
        framework_b_unique = len(framework_b_controls - mapped_b_controls)
        
        total_controls = len(framework_a_controls.union(framework_b_controls))
        overlap_percentage = (common_controls / total_controls * 100) if total_controls > 0 else 0
        
        # Determine relationship type and strength
        if overlap_percentage >= 80:
            relationship_type = "highly_aligned"
            strength = 0.9
        elif overlap_percentage >= 60:
            relationship_type = "well_aligned"
            strength = 0.7
        elif overlap_percentage >= 40:
            relationship_type = "moderately_aligned"
            strength = 0.5
        elif overlap_percentage >= 20:
            relationship_type = "loosely_aligned"
            strength = 0.3
        else:
            relationship_type = "minimally_aligned"
            strength = 0.1
        
        # Identify implementation synergies
        synergies = await self._identify_implementation_synergies(all_mappings, unified_rules)
        
        # Identify conflict areas
        conflicts = await self._identify_conflict_areas(all_mappings, unified_rules)
        
        relationship = FrameworkRelationship(
            framework_a=framework_a,
            framework_b=framework_b,
            overlap_percentage=overlap_percentage,
            common_controls=common_controls,
            framework_a_unique=framework_a_unique,
            framework_b_unique=framework_b_unique,
            relationship_type=relationship_type,
            strength=strength,
            bidirectional_mappings=all_mappings,
            implementation_synergies=synergies,
            conflict_areas=conflicts
        )
        
        # Cache the relationship
        self.framework_relationships[(framework_a, framework_b)] = relationship
        
        return relationship
    
    async def _identify_implementation_synergies(
        self,
        mappings: List[ControlMapping],
        unified_rules: List[UnifiedComplianceRule]
    ) -> List[str]:
        """Identify implementation synergies between frameworks"""
        synergies = []
        
        # Group mappings by implementation patterns
        implementation_groups = defaultdict(list)
        
        for mapping in mappings:
            if mapping.mapping_type in [MappingType.EQUIVALENT, MappingType.DIRECT]:
                # Find unified rules that implement both controls
                for rule in unified_rules:
                    source_mapped = any(
                        mapping.source_control in fm.control_ids and fm.framework_id == mapping.source_framework
                        for fm in rule.framework_mappings
                    )
                    target_mapped = any(
                        mapping.target_control in fm.control_ids and fm.framework_id == mapping.target_framework
                        for fm in rule.framework_mappings
                    )
                    
                    if source_mapped and target_mapped:
                        implementation_groups[rule.category].append(mapping)
        
        # Generate synergy descriptions
        for category, category_mappings in implementation_groups.items():
            if len(category_mappings) >= 3:
                synergies.append(
                    f"Strong synergy in {category}: {len(category_mappings)} aligned controls "
                    f"can be implemented with unified approach"
                )
        
        # Identify exceeding compliance opportunities
        exceeding_patterns = defaultdict(int)
        for rule in unified_rules:
            for mapping in rule.framework_mappings:
                if mapping.implementation_status == "exceeds":
                    exceeding_patterns[mapping.framework_id] += 1
        
        for framework_id, count in exceeding_patterns.items():
            if count >= 5:
                synergies.append(
                    f"Exceeding compliance opportunity: {framework_id} has {count} rules "
                    f"that exceed baseline requirements"
                )
        
        return synergies
    
    async def _identify_conflict_areas(
        self,
        mappings: List[ControlMapping],
        unified_rules: List[UnifiedComplianceRule]
    ) -> List[str]:
        """Identify potential conflict areas between frameworks"""
        conflicts = []
        
        # Look for low-confidence mappings
        uncertain_mappings = [m for m in mappings if m.confidence == MappingConfidence.UNCERTAIN]
        if len(uncertain_mappings) >= 5:
            conflicts.append(
                f"Mapping uncertainty: {len(uncertain_mappings)} control mappings have low confidence "
                f"and may require manual review"
            )
        
        # Look for implementation conflicts
        conflicting_implementations = defaultdict(list)
        
        for rule in unified_rules:
            framework_statuses = {}
            for mapping in rule.framework_mappings:
                framework_statuses[mapping.framework_id] = mapping.implementation_status
            
            # Check for status conflicts
            unique_statuses = set(framework_statuses.values())
            if len(unique_statuses) > 2:  # More than just compliant/exceeds variation
                conflicting_implementations[rule.rule_id] = framework_statuses
        
        if conflicting_implementations:
            conflicts.append(
                f"Implementation conflicts: {len(conflicting_implementations)} rules have "
                f"conflicting implementation statuses across frameworks"
            )
        
        return conflicts
    
    async def generate_unified_implementation(
        self,
        control_objective: str,
        target_frameworks: List[str],
        platform: Platform,
        unified_rules: List[UnifiedComplianceRule]
    ) -> UnifiedImplementation:
        """Generate a unified implementation that satisfies multiple frameworks"""
        
        # Find rules that address the control objective
        relevant_rules = []
        for rule in unified_rules:
            if control_objective.lower() in rule.description.lower() or \
               control_objective.lower() in rule.title.lower():
                relevant_rules.append(rule)
        
        if not relevant_rules:
            # Create a new unified implementation
            implementation_id = f"unified_{control_objective.lower().replace(' ', '_')}"
            
            # Basic implementation template
            implementation = UnifiedImplementation(
                implementation_id=implementation_id,
                description=f"Unified implementation for {control_objective}",
                frameworks_satisfied=target_frameworks,
                control_mappings={fw: [] for fw in target_frameworks},
                implementation_details={
                    "objective": control_objective,
                    "approach": "unified_compliance",
                    "platforms": [platform.value]
                },
                platform_specifics={platform: PlatformImplementation(
                    implementation_type="configuration",
                    commands=[],
                    files_modified=[],
                    services_affected=[],
                    validation_commands=[]
                )},
                exceeds_frameworks=[],
                compliance_justification=f"Implements {control_objective} across {len(target_frameworks)} frameworks",
                risk_assessment="Low risk - standard implementation pattern",
                effort_estimate="Medium"
            )
            
            return implementation
        
        # Use existing rules to build unified implementation
        best_rule = relevant_rules[0]  # Select best matching rule
        
        # Extract framework mappings
        control_mappings = {}
        exceeds_frameworks = []
        
        for mapping in best_rule.framework_mappings:
            if mapping.framework_id in target_frameworks:
                control_mappings[mapping.framework_id] = mapping.control_ids
                if mapping.implementation_status == "exceeds":
                    exceeds_frameworks.append(mapping.framework_id)
        
        # Create unified implementation
        implementation = UnifiedImplementation(
            implementation_id=f"unified_{best_rule.rule_id}",
            description=best_rule.description,
            frameworks_satisfied=list(control_mappings.keys()),
            control_mappings=control_mappings,
            implementation_details={
                "base_rule": best_rule.rule_id,
                "category": best_rule.category,
                "security_function": best_rule.security_function,
                "platforms": [impl.platform.value for impl in best_rule.platform_implementations]
            },
            platform_specifics={
                impl.platform: impl for impl in best_rule.platform_implementations
                if impl.platform == platform
            },
            exceeds_frameworks=exceeds_frameworks,
            compliance_justification=f"Based on unified rule {best_rule.rule_id}: {best_rule.description}",
            risk_assessment=best_rule.risk_level,
            effort_estimate="Low"  # Since rule already exists
        )
        
        # Cache the implementation
        self.unified_implementations[implementation.implementation_id] = implementation
        
        return implementation
    
    async def get_framework_coverage_analysis(
        self,
        frameworks: List[str],
        unified_rules: List[UnifiedComplianceRule]
    ) -> Dict[str, Any]:
        """Analyze coverage across multiple frameworks"""
        
        # Count controls per framework
        framework_controls = defaultdict(set)
        framework_rules = defaultdict(set)
        
        for rule in unified_rules:
            for mapping in rule.framework_mappings:
                if mapping.framework_id in frameworks:
                    framework_controls[mapping.framework_id].update(mapping.control_ids)
                    framework_rules[mapping.framework_id].add(rule.rule_id)
        
        # Calculate coverage metrics
        coverage_analysis = {
            "frameworks_analyzed": frameworks,
            "framework_details": {},
            "cross_framework_analysis": {},
            "coverage_gaps": [],
            "optimization_opportunities": []
        }
        
        # Per-framework details
        for framework in frameworks:
            controls = framework_controls[framework]
            rules = framework_rules[framework]
            
            coverage_analysis["framework_details"][framework] = {
                "total_controls": len(controls),
                "total_rules": len(rules),
                "controls": list(controls),
                "coverage_percentage": len(rules) / len(controls) * 100 if controls else 0
            }
        
        # Cross-framework analysis
        all_controls = set()
        for controls in framework_controls.values():
            all_controls.update(controls)
        
        framework_pairs = []
        for i, fw_a in enumerate(frameworks):
            for fw_b in frameworks[i+1:]:
                if (fw_a, fw_b) in self.framework_relationships:
                    relationship = self.framework_relationships[(fw_a, fw_b)]
                    framework_pairs.append({
                        "framework_a": fw_a,
                        "framework_b": fw_b,
                        "overlap_percentage": relationship.overlap_percentage,
                        "relationship_type": relationship.relationship_type,
                        "common_controls": relationship.common_controls
                    })
        
        coverage_analysis["cross_framework_analysis"] = {
            "total_unique_controls": len(all_controls),
            "framework_relationships": framework_pairs
        }
        
        # Identify coverage gaps
        for framework in frameworks:
            controls = framework_controls[framework]
            rules = framework_rules[framework]
            
            if len(rules) < len(controls) * 0.8:  # Less than 80% coverage
                coverage_analysis["coverage_gaps"].append({
                    "framework": framework,
                    "gap_percentage": (len(controls) - len(rules)) / len(controls) * 100,
                    "missing_controls": len(controls) - len(rules)
                })
        
        # Identify optimization opportunities
        if len(framework_pairs) > 0:
            high_overlap_pairs = [
                pair for pair in framework_pairs 
                if pair["overlap_percentage"] > 70
            ]
            
            if high_overlap_pairs:
                coverage_analysis["optimization_opportunities"].append({
                    "type": "high_overlap_consolidation",
                    "description": f"High overlap between {len(high_overlap_pairs)} framework pairs",
                    "pairs": high_overlap_pairs
                })
        
        return coverage_analysis
    
    async def export_mapping_data(self, format: str = 'json') -> str:
        """Export framework mapping data in specified format"""
        
        if format == 'json':
            export_data = {
                "control_mappings": [
                    {
                        "source_framework": mapping.source_framework,
                        "source_control": mapping.source_control,
                        "target_framework": mapping.target_framework,
                        "target_control": mapping.target_control,
                        "mapping_type": mapping.mapping_type.value,
                        "confidence": mapping.confidence.value,
                        "rationale": mapping.rationale,
                        "evidence": mapping.evidence
                    }
                    for mappings in self.control_mappings.values()
                    for mapping in mappings
                ],
                "framework_relationships": [
                    {
                        "framework_a": rel.framework_a,
                        "framework_b": rel.framework_b,
                        "overlap_percentage": rel.overlap_percentage,
                        "relationship_type": rel.relationship_type,
                        "strength": rel.strength,
                        "common_controls": rel.common_controls
                    }
                    for rel in self.framework_relationships.values()
                ],
                "unified_implementations": [
                    {
                        "implementation_id": impl.implementation_id,
                        "description": impl.description,
                        "frameworks_satisfied": impl.frameworks_satisfied,
                        "exceeds_frameworks": impl.exceeds_frameworks
                    }
                    for impl in self.unified_implementations.values()
                ]
            }
            
            return json.dumps(export_data, indent=2)
        
        elif format == 'csv':
            # Generate CSV for control mappings
            lines = ["Source_Framework,Source_Control,Target_Framework,Target_Control,Mapping_Type,Confidence"]
            
            for mappings in self.control_mappings.values():
                for mapping in mappings:
                    lines.append(
                        f"{mapping.source_framework},{mapping.source_control},"
                        f"{mapping.target_framework},{mapping.target_control},"
                        f"{mapping.mapping_type.value},{mapping.confidence.value}"
                    )
            
            return '\n'.join(lines)
        
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def clear_cache(self):
        """Clear mapping cache"""
        self.mapping_cache.clear()