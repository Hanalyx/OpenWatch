"""
Framework Loader Service
Handles loading and validation of framework control definitions from JSON files
"""
import json
import asyncio
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

from backend.app.models.enhanced_mongo_models import FrameworkControlDefinition


class FrameworkLoaderService:
    """Service for loading framework control definitions into MongoDB"""
    
    def __init__(self):
        """Initialize the framework loader service"""
        self.framework_definitions_path = Path(__file__).parent.parent / "data" / "framework_definitions"
        self.loaded_frameworks = {}
    
    async def load_framework_from_file(self, file_path: Path) -> int:
        """
        Load framework controls from a JSON file
        
        Args:
            file_path: Path to the framework definition JSON file
            
        Returns:
            Number of controls loaded
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                framework_data = json.load(f)
            
            framework_info = framework_data["framework_info"]
            framework_id = framework_info["id"]
            controls = framework_data["controls"]
            
            control_count = 0
            
            for control_data in controls:
                control_def = await self._create_control_definition(
                    framework_id, control_data, framework_info
                )
                
                # Upsert the control definition
                existing = await FrameworkControlDefinition.find_one(
                    FrameworkControlDefinition.framework_id == framework_id,
                    FrameworkControlDefinition.control_id == control_data["control_id"]
                )
                
                if existing:
                    # Update existing control
                    for field, value in control_def.__dict__.items():
                        if not field.startswith('_'):
                            setattr(existing, field, value)
                    existing.updated_at = datetime.utcnow()
                    await existing.save()
                else:
                    # Insert new control
                    await control_def.save()
                
                control_count += 1
            
            # Track loaded framework
            self.loaded_frameworks[framework_id] = {
                "info": framework_info,
                "loaded_at": datetime.utcnow().isoformat(),
                "control_count": control_count
            }
            
            return control_count
            
        except Exception as e:
            raise Exception(f"Failed to load framework from {file_path}: {str(e)}")
    
    async def _create_control_definition(
        self, 
        framework_id: str, 
        control_data: Dict[str, Any], 
        framework_info: Dict[str, Any]
    ) -> FrameworkControlDefinition:
        """
        Create a FrameworkControlDefinition from control data
        
        Args:
            framework_id: ID of the framework
            control_data: Control data from JSON
            framework_info: Framework metadata
            
        Returns:
            FrameworkControlDefinition instance
        """
        if "control_id" not in control_data:
            raise ValueError("Control ID is required")
        
        # Extract common fields
        control_def = FrameworkControlDefinition(
            framework_id=framework_id,
            control_id=control_data["control_id"],
            title=control_data.get("title", ""),
            description=control_data.get("description", ""),
            framework_version=framework_info.get("version", ""),
            framework_organization=framework_info.get("organization", ""),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        # Handle framework-specific fields
        if framework_id == "nist_800_53_r5":
            control_def.family = control_data.get("family", "")
            control_def.priority = control_data.get("priority", "")
            control_def.supplemental_guidance = control_data.get("supplemental_guidance", "")
            control_def.related_controls = control_data.get("related_controls", [])
            control_def.external_references = control_data.get("external_references", {})
            
        elif framework_id == "cis_v8":
            control_def.family = control_data.get("asset_type", "")
            control_def.priority = ", ".join(control_data.get("implementation_groups", []))
            control_def.external_references = control_data.get("external_references", {})
            # Store CIS-specific fields as additional data
            control_def.asset_type = control_data.get("asset_type", "")
            control_def.implementation_groups = control_data.get("implementation_groups", [])
            control_def.safeguards = control_data.get("safeguards", [])
            
        elif framework_id == "srg_os":
            control_def.family = "Security Requirements"
            control_def.priority = control_data.get("severity", "")
            control_def.supplemental_guidance = control_data.get("vulnerability_discussion", "")
            control_def.related_controls = control_data.get("related_controls", [])
            control_def.external_references = {
                "nist": ", ".join(control_data.get("nist_controls", [])) if control_data.get("nist_controls") else None,
                "cci": ", ".join(control_data.get("cci", [])) if control_data.get("cci") else None
            }
            # Store SRG-specific fields
            control_def.severity = control_data.get("severity", "")
            control_def.check_text = control_data.get("check_text", "")
            control_def.fix_text = control_data.get("fix_text", "")
            control_def.cci = control_data.get("cci", [])
            control_def.nist_controls = control_data.get("nist_controls", [])
            control_def.requirement_source = control_data.get("requirement_source", "")
            
        elif framework_id == "stig_rhel9":
            control_def.family = "STIG Implementation"
            control_def.priority = control_data.get("severity", "")
            control_def.supplemental_guidance = control_data.get("vulnerability_discussion", "")
            control_def.related_controls = control_data.get("related_controls", [])
            control_def.external_references = {
                "srg": control_data.get("srg_requirement", ""),
                "nist": ", ".join(control_data.get("nist_controls", [])) if control_data.get("nist_controls") else None,
                "cci": ", ".join(control_data.get("cci", [])) if control_data.get("cci") else None
            }
            # Store STIG-specific fields
            control_def.severity = control_data.get("severity", "")
            control_def.check_text = control_data.get("check_text", "")
            control_def.fix_text = control_data.get("fix_text", "")
            control_def.cci = control_data.get("cci", [])
            control_def.nist_controls = control_data.get("nist_controls", [])
            control_def.srg_requirement = control_data.get("srg_requirement", "")
            control_def.implementation_details = control_data.get("implementation_details", {})
            control_def.target_platform = framework_info.get("target_platform", "")
            
        elif framework_id == "iso_27001_2022":
            control_def.family = control_data.get("category", "")
            control_def.priority = control_data.get("implementation_level", "")
            control_def.supplemental_guidance = control_data.get("implementation_guidance", "")
            control_def.related_controls = control_data.get("related_controls", [])
            control_def.external_references = control_data.get("external_references", {})
            # Store ISO-specific fields
            control_def.category = control_data.get("category", "")
            control_def.implementation_level = control_data.get("implementation_level", "")
            control_def.implementation_guidance = control_data.get("implementation_guidance", "")
            control_def.objective = control_data.get("objective", "")
            control_def.compliance_evidence = control_data.get("compliance_evidence", [])
            
        elif framework_id == "pci_dss_v4":
            control_def.family = control_data.get("category", "")
            control_def.priority = control_data.get("validation_level", "")
            control_def.supplemental_guidance = control_data.get("guidance", "")
            control_def.related_controls = control_data.get("related_controls", [])
            control_def.external_references = control_data.get("external_references", {})
            # Store PCI-specific fields
            control_def.requirement = control_data.get("requirement", "")
            control_def.requirement_title = control_data.get("requirement_title", "")
            control_def.category = control_data.get("category", "")
            control_def.validation_level = control_data.get("validation_level", "")
            control_def.testing_procedures = control_data.get("testing_procedures", [])
            control_def.guidance = control_data.get("guidance", "")
            control_def.customization = control_data.get("customization", "")
            control_def.compliance_evidence = control_data.get("compliance_evidence", [])
        
        return control_def
    
    async def load_all_frameworks(self) -> Dict[str, int]:
        """
        Load all available framework definitions
        
        Returns:
            Dictionary mapping framework IDs to control counts
        """
        results = {}
        
        # Define framework files to load
        framework_files = [
            "nist_800_53_r5.json",
            "cis_v8.json", 
            "srg_os.json",
            "stig_rhel9.json",
            "iso_27001_2022.json",
            "pci_dss_v4.json"
        ]
        
        for filename in framework_files:
            file_path = self.framework_definitions_path / filename
            if file_path.exists():
                try:
                    count = await self.load_framework_from_file(file_path)
                    framework_id = filename.replace(".json", "")
                    results[framework_id] = count
                except Exception as e:
                    print(f"Error loading {filename}: {str(e)}")
                    results[filename] = 0
        
        return results
    
    async def get_framework_summary(self) -> Dict[str, Any]:
        """
        Get summary of loaded frameworks
        
        Returns:
            Dictionary with framework summaries
        """
        summary = {}
        
        for framework_id, info in self.loaded_frameworks.items():
            # Get current count from database
            db_count = await FrameworkControlDefinition.count(
                FrameworkControlDefinition.framework_id == framework_id
            )
            
            summary[framework_id] = {
                "name": info["info"].get("name", framework_id),
                "version": info["info"].get("version", ""),
                "organization": info["info"].get("organization", ""),
                "loaded_at": info["loaded_at"],
                "control_count": db_count
            }
        
        return summary
    
    async def validate_framework_integrity(self, framework_id: str) -> Dict[str, Any]:
        """
        Validate the integrity of a loaded framework
        
        Args:
            framework_id: ID of the framework to validate
            
        Returns:
            Validation results
        """
        # Get database count
        db_count = await FrameworkControlDefinition.count(
            FrameworkControlDefinition.framework_id == framework_id
        )
        
        # Get file count if file exists
        file_path = self.framework_definitions_path / f"{framework_id}.json"
        file_count = 0
        if file_path.exists():
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    file_count = len(data.get("controls", []))
            except Exception:
                file_count = 0
        
        # Check for missing external references
        controls = await FrameworkControlDefinition.find(
            FrameworkControlDefinition.framework_id == framework_id
        ).to_list()
        
        missing_references = []
        for control in controls:
            if control.external_references:
                for ref_framework, ref_control in control.external_references.items():
                    if ref_control and ref_framework != framework_id:
                        # Check if referenced control exists
                        ref_exists = await FrameworkControlDefinition.count(
                            FrameworkControlDefinition.framework_id == ref_framework,
                            FrameworkControlDefinition.control_id == ref_control
                        )
                        if ref_exists == 0:
                            missing_references.append({
                                "control": control.control_id,
                                "missing_reference": f"{ref_framework}:{ref_control}"
                            })
        
        # Calculate integrity score
        integrity_score = 1.0
        if file_count > 0 and db_count != file_count:
            integrity_score -= 0.2
        if missing_references:
            integrity_score -= min(0.2, len(missing_references) * 0.05)
        
        return {
            "framework_id": framework_id,
            "db_control_count": db_count,
            "file_control_count": file_count,
            "count_match": db_count == file_count,
            "missing_references": missing_references,
            "integrity_score": max(0.0, integrity_score)
        }
    
    async def update_cross_references(self) -> Dict[str, int]:
        """
        Update cross-references between frameworks
        
        Returns:
            Number of controls updated per framework
        """
        results = {}
        
        # Get all framework IDs
        framework_ids = await FrameworkControlDefinition.distinct("framework_id")
        
        for framework_id in framework_ids:
            updated_count = 0
            controls = await FrameworkControlDefinition.find(
                FrameworkControlDefinition.framework_id == framework_id
            ).to_list()
            
            for control in controls:
                if control.external_references:
                    # Verify each external reference
                    verified_refs = {}
                    for ref_framework, ref_control in control.external_references.items():
                        if ref_control and ref_framework in framework_ids:
                            # Check if reference exists
                            ref_exists = await FrameworkControlDefinition.find_one(
                                FrameworkControlDefinition.framework_id == ref_framework,
                                FrameworkControlDefinition.control_id == ref_control
                            )
                            if ref_exists:
                                verified_refs[ref_framework] = ref_control
                    
                    # Update control with verified references only
                    if verified_refs != control.external_references:
                        control.external_references = verified_refs
                        control.updated_at = datetime.utcnow()
                        await control.save()
                        updated_count += 1
            
            results[framework_id] = updated_count
        
        return results