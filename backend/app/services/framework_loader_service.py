"""
Framework Definition Loader Service
Loads framework control definitions from JSON files into MongoDB
"""
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

from backend.app.models.enhanced_mongo_models import FrameworkControlDefinition


logger = logging.getLogger(__name__)


class FrameworkLoaderService:
    """Service for loading framework control definitions into MongoDB"""
    
    def __init__(self):
        self.framework_definitions_path = Path(__file__).parent.parent / "data" / "framework_definitions"
        self.loaded_frameworks = {}
        
    async def load_all_frameworks(self) -> Dict[str, int]:
        """Load all framework definitions from JSON files"""
        logger.info("Loading all framework definitions...")
        
        results = {}
        
        # Find all JSON files in framework_definitions directory
        if not self.framework_definitions_path.exists():
            logger.error(f"Framework definitions directory not found: {self.framework_definitions_path}")
            return results
            
        for json_file in self.framework_definitions_path.glob("*.json"):
            try:
                framework_id = json_file.stem
                count = await self.load_framework_from_file(json_file)
                results[framework_id] = count
                logger.info(f"Loaded {count} controls for framework {framework_id}")
            except Exception as e:
                logger.error(f"Failed to load framework from {json_file}: {str(e)}")
                results[json_file.stem] = 0
                
        return results
    
    async def load_framework_from_file(self, file_path: Path) -> int:
        """Load framework definition from a JSON file"""
        logger.info(f"Loading framework from {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                framework_data = json.load(f)
                
            framework_info = framework_data.get('framework_info', {})
            framework_id = framework_info.get('id')
            
            if not framework_id:
                raise ValueError(f"Framework ID not found in {file_path}")
                
            # Process controls
            controls = framework_data.get('controls', [])
            loaded_count = 0
            
            for control_data in controls:
                try:
                    control_def = await self._create_control_definition(framework_id, control_data, framework_info)
                    
                    # Upsert the control definition
                    await FrameworkControlDefinition.find_one(
                        FrameworkControlDefinition.framework_id == framework_id,
                        FrameworkControlDefinition.control_id == control_def.control_id
                    ).upsert(
                        {"$set": control_def.dict()},
                        on_insert=control_def
                    )
                    
                    loaded_count += 1
                    
                except Exception as e:
                    logger.error(f"Failed to load control {control_data.get('control_id', 'unknown')}: {str(e)}")
                    
            self.loaded_frameworks[framework_id] = {
                'info': framework_info,
                'control_count': loaded_count,
                'loaded_at': datetime.utcnow()
            }
            
            return loaded_count
            
        except Exception as e:
            logger.error(f"Failed to load framework from {file_path}: {str(e)}")
            raise
    
    async def _create_control_definition(self, framework_id: str, control_data: Dict[str, Any], framework_info: Dict[str, Any]) -> FrameworkControlDefinition:
        """Create a FrameworkControlDefinition from control data"""
        
        control_id = control_data.get('control_id')
        if not control_id:
            raise ValueError("Control ID is required")
            
        # Extract external references
        external_references = {}
        
        # For NIST controls, extract CIS and ISO mappings
        if framework_id.startswith('nist'):
            external_references = control_data.get('external_references', {})
            
        # For CIS controls, extract NIST and ISO mappings  
        elif framework_id.startswith('cis'):
            external_references = control_data.get('external_references', {})
            
        # Handle different control structures
        title = control_data.get('title', '')
        description = control_data.get('description', '')
        family = control_data.get('family', control_data.get('asset_type', ''))
        priority = control_data.get('priority', control_data.get('implementation_groups', ['']))
        
        # Handle priority/baseline formatting
        if isinstance(priority, list):
            priority = ', '.join(str(p) for p in priority)
        
        # Extract related controls
        related_controls = control_data.get('related_controls', [])
        
        # Handle supplemental guidance
        supplemental_guidance = control_data.get('supplemental_guidance', '')
        if not supplemental_guidance and 'safeguards' in control_data:
            # For CIS controls, use safeguards as supplemental guidance
            safeguards = control_data.get('safeguards', [])
            if safeguards:
                safeguard_titles = [s.get('title', '') for s in safeguards[:3]]  # First 3 safeguards
                supplemental_guidance = f"Key safeguards: {', '.join(safeguard_titles)}"
        
        return FrameworkControlDefinition(
            framework_id=framework_id,
            control_id=control_id,
            title=title,
            description=description,
            family=family,
            priority=str(priority) if priority else None,
            supplemental_guidance=supplemental_guidance,
            related_controls=related_controls,
            external_references=external_references
        )
    
    async def get_framework_summary(self) -> Dict[str, Any]:
        """Get summary of loaded frameworks"""
        summary = {}
        
        for framework_id, data in self.loaded_frameworks.items():
            control_count = await FrameworkControlDefinition.count(
                FrameworkControlDefinition.framework_id == framework_id
            )
            
            summary[framework_id] = {
                'name': data['info'].get('name', framework_id),
                'version': data['info'].get('version', 'unknown'),
                'organization': data['info'].get('organization', 'unknown'),
                'control_count': control_count,
                'loaded_at': data['loaded_at']
            }
            
        return summary
    
    async def validate_framework_integrity(self, framework_id: str) -> Dict[str, Any]:
        """Validate the integrity of a loaded framework"""
        logger.info(f"Validating framework integrity for {framework_id}")
        
        # Count controls in database
        db_count = await FrameworkControlDefinition.count(
            FrameworkControlDefinition.framework_id == framework_id
        )
        
        # Load original file to compare
        json_file = self.framework_definitions_path / f"{framework_id}.json"
        file_count = 0
        
        if json_file.exists():
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    framework_data = json.load(f)
                    file_count = len(framework_data.get('controls', []))
            except Exception as e:
                logger.error(f"Failed to read framework file {json_file}: {str(e)}")
        
        # Check for missing cross-references
        controls = await FrameworkControlDefinition.find(
            FrameworkControlDefinition.framework_id == framework_id
        ).to_list()
        
        missing_references = []
        for control in controls:
            if control.external_references:
                for ref_framework, ref_control in control.external_references.items():
                    # Check if referenced control exists
                    ref_exists = await FrameworkControlDefinition.count(
                        FrameworkControlDefinition.framework_id == ref_framework,
                        FrameworkControlDefinition.control_id == ref_control
                    )
                    if not ref_exists:
                        missing_references.append({
                            'control': control.control_id,
                            'missing_reference': f"{ref_framework}:{ref_control}"
                        })
        
        return {
            'framework_id': framework_id,
            'db_control_count': db_count,
            'file_control_count': file_count,
            'count_match': db_count == file_count,
            'missing_references': missing_references,
            'integrity_score': 1.0 if (db_count == file_count and not missing_references) else 0.8
        }
    
    async def update_cross_references(self) -> Dict[str, int]:
        """Update cross-references between frameworks"""
        logger.info("Updating cross-references between frameworks...")
        
        updated_counts = {}
        
        # Get all frameworks
        frameworks = await FrameworkControlDefinition.distinct("framework_id")
        
        for framework_id in frameworks:
            updated_count = 0
            controls = await FrameworkControlDefinition.find(
                FrameworkControlDefinition.framework_id == framework_id
            ).to_list()
            
            for control in controls:
                if control.external_references:
                    # Verify and update external references
                    verified_refs = {}
                    
                    for ref_framework, ref_control in control.external_references.items():
                        # Check if referenced control exists
                        ref_control_exists = await FrameworkControlDefinition.find_one(
                            FrameworkControlDefinition.framework_id == ref_framework,
                            FrameworkControlDefinition.control_id == ref_control
                        )
                        
                        if ref_control_exists:
                            verified_refs[ref_framework] = ref_control
                        else:
                            logger.warning(f"Referenced control {ref_framework}:{ref_control} not found for {control.control_id}")
                    
                    # Update the control with verified references
                    if verified_refs != control.external_references:
                        control.external_references = verified_refs
                        await control.save()
                        updated_count += 1
            
            updated_counts[framework_id] = updated_count
            
        return updated_counts