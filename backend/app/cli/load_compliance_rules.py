#!/usr/bin/env python3
"""
OpenWatch Compliance Rules Loader
Loads JSON compliance rules into MongoDB for the OpenWatch platform

Usage:
    python -m backend.app.cli.load_compliance_rules load --source /path/to/rules
    python -m backend.app.cli.load_compliance_rules validate
    python -m backend.app.cli.load_compliance_rules stats
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import argparse

from ..models.mongo_models import ComplianceRule, mongo_manager
from ..services.mongo_integration_service import MongoIntegrationService

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ComplianceRulesLoader:
    """Loads OpenWatch compliance rules into MongoDB"""
    
    def __init__(self):
        self.mongo_service = None
        self.loaded_count = 0
        self.error_count = 0
        self.skipped_count = 0
    
    async def initialize_mongodb(self):
        """Initialize MongoDB connection"""
        try:
            # Initialize MongoDB connection
            mongodb_url = "mongodb://localhost:27017"
            await mongo_manager.initialize(mongodb_url, "openwatch_rules")
            
            # Initialize mongo service
            self.mongo_service = MongoIntegrationService()
            
            logger.info("MongoDB connection initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize MongoDB: {e}")
            return False
    
    async def load_rules_from_directory(self, rules_dir: Path, replace_existing: bool = False) -> Dict[str, int]:
        """Load all JSON rules from directory"""
        logger.info(f"Loading compliance rules from: {rules_dir}")
        
        if not rules_dir.exists():
            raise FileNotFoundError(f"Rules directory not found: {rules_dir}")
        
        # Find all JSON files
        json_files = list(rules_dir.glob("*.json"))
        total_files = len(json_files)
        
        logger.info(f"Found {total_files} JSON rule files")
        
        for i, json_file in enumerate(json_files, 1):
            try:
                await self._load_single_rule(json_file, replace_existing)
                self.loaded_count += 1
                
                if i % 100 == 0:
                    logger.info(f"Processed {i}/{total_files} files ({self.loaded_count} loaded, {self.error_count} errors, {self.skipped_count} skipped)")
                    
            except Exception as e:
                logger.error(f"Error loading {json_file}: {e}")
                self.error_count += 1
        
        logger.info(f"Loading complete: {self.loaded_count} loaded, {self.error_count} errors, {self.skipped_count} skipped")
        
        return {
            "loaded": self.loaded_count,
            "errors": self.error_count,
            "skipped": self.skipped_count,
            "total": total_files
        }
    
    async def _load_single_rule(self, json_file: Path, replace_existing: bool = False):
        """Load a single JSON rule into MongoDB"""
        
        # Load JSON data
        with open(json_file, 'r', encoding='utf-8') as f:
            rule_data = json.load(f)
        
        rule_id = rule_data.get('rule_id')
        if not rule_id:
            raise ValueError(f"Rule missing rule_id in {json_file}")
        
        # Check if rule already exists
        existing_rule = await ComplianceRule.find_one({"rule_id": rule_id})
        if existing_rule and not replace_existing:
            logger.debug(f"Rule {rule_id} already exists, skipping")
            self.skipped_count += 1
            return
        
        # Transform JSON to MongoDB model format
        compliance_rule_data = self._transform_to_mongodb_format(rule_data)
        
        if existing_rule and replace_existing:
            # Update existing rule
            for key, value in compliance_rule_data.items():
                setattr(existing_rule, key, value)
            existing_rule.updated_at = datetime.utcnow()
            await existing_rule.save()
            logger.debug(f"Updated rule: {rule_id}")
        else:
            # Create new rule
            compliance_rule = ComplianceRule(**compliance_rule_data)
            await compliance_rule.save()
            logger.debug(f"Created rule: {rule_id}")
    
    def _transform_to_mongodb_format(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform JSON rule data to MongoDB model format"""
        
        # Extract and transform frameworks
        frameworks_data = rule_data.get('frameworks', {})
        
        # Transform to the MongoDB FrameworkVersions format
        from ..models.mongo_models import FrameworkVersions
        frameworks = FrameworkVersions()
        
        if 'nist' in frameworks_data:
            frameworks.nist = frameworks_data['nist']
        if 'cis' in frameworks_data:
            frameworks.cis = frameworks_data['cis']
        if 'stig' in frameworks_data:
            frameworks.stig = frameworks_data['stig']
        if 'pci_dss' in frameworks_data:
            frameworks.pci_dss = frameworks_data['pci_dss']
        if 'iso27001' in frameworks_data:
            frameworks.iso27001 = frameworks_data['iso27001']
        if 'hipaa' in frameworks_data:
            frameworks.hipaa = frameworks_data['hipaa']
        
        # Transform platform implementations
        platform_impls = {}
        for platform, impl_data in rule_data.get('platform_implementations', {}).items():
            from ..models.mongo_models import PlatformImplementation
            platform_impls[platform] = PlatformImplementation(**impl_data)
        
        # Prepare the MongoDB document
        mongodb_data = {
            'rule_id': rule_data['rule_id'],
            'scap_rule_id': rule_data.get('scap_rule_id'),
            'parent_rule_id': rule_data.get('parent_rule_id'),
            'metadata': rule_data.get('metadata', {}),
            'abstract': rule_data.get('abstract', False),
            'severity': rule_data.get('severity', 'medium'),
            'category': rule_data.get('category', 'system'),
            'security_function': rule_data.get('security_function'),
            'tags': rule_data.get('tags', []),
            'frameworks': frameworks,
            'platform_implementations': platform_impls,
            'platform_requirements': rule_data.get('platform_requirements'),
            'check_type': rule_data.get('check_type', 'custom'),
            'check_content': rule_data.get('check_content', {}),
            'fix_available': rule_data.get('fix_available', False),
            'fix_content': rule_data.get('fix_content'),
            'manual_remediation': rule_data.get('manual_remediation'),
            'remediation_complexity': rule_data.get('remediation_complexity', 'medium'),
            'remediation_risk': rule_data.get('remediation_risk', 'low'),
            'dependencies': rule_data.get('dependencies', {"requires": [], "conflicts": [], "related": []}),
            'source_file': rule_data.get('source_file', 'unknown'),
            'source_hash': rule_data.get('source_hash', 'unknown'),
            'version': rule_data.get('version', '1.0.0'),
            'imported_at': datetime.fromisoformat(rule_data.get('imported_at', datetime.utcnow().isoformat().replace('+00:00', 'Z')).replace('Z', '+00:00')),
            'updated_at': datetime.utcnow()
        }
        
        return mongodb_data
    
    async def validate_loaded_rules(self) -> Dict[str, Any]:
        """Validate loaded rules in MongoDB"""
        logger.info("Validating loaded compliance rules...")
        
        # Get basic statistics
        total_rules = await ComplianceRule.count()
        
        # Count rules by severity
        severity_counts = {}
        for severity in ['low', 'medium', 'high', 'critical']:
            count = await ComplianceRule.find({"severity": severity}).count()
            severity_counts[severity] = count
        
        # Count rules by category
        category_pipeline = [
            {"$group": {"_id": "$category", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        category_results = await ComplianceRule.aggregate(category_pipeline).to_list()
        
        # Count framework mappings
        framework_counts = {}
        for framework in ['nist', 'cis', 'stig', 'pci_dss', 'iso27001']:
            count = await ComplianceRule.find({f"frameworks.{framework}": {"$exists": True, "$ne": {}}}).count()
            framework_counts[framework] = count
        
        # Count platform implementations
        platform_counts = {}
        for platform in ['rhel', 'ubuntu', 'windows', 'centos']:
            count = await ComplianceRule.find({f"platform_implementations.{platform}": {"$exists": True}}).count()
            platform_counts[platform] = count
        
        validation_results = {
            "total_rules": total_rules,
            "severity_distribution": severity_counts,
            "top_categories": category_results,
            "framework_coverage": framework_counts,
            "platform_coverage": platform_counts
        }
        
        logger.info(f"Validation complete: {total_rules} total rules loaded")
        return validation_results
    
    async def get_platform_statistics(self) -> Dict[str, Any]:
        """Generate platform statistics for the frontend"""
        logger.info("Generating platform statistics...")
        
        platform_stats = []
        
        # Analyze each major platform
        platforms = [
            {"name": "RHEL", "key": "rhel", "versions": ["8", "9"]},
            {"name": "Ubuntu", "key": "ubuntu", "versions": ["20.04", "22.04", "24.04"]},
            {"name": "Windows", "key": "windows", "versions": ["2019", "2022"]}
        ]
        
        for platform_info in platforms:
            platform_key = platform_info["key"]
            
            # Count total rules for this platform
            rule_count = await ComplianceRule.find({
                f"platform_implementations.{platform_key}": {"$exists": True}
            }).count()
            
            if rule_count == 0:
                continue
            
            # Get category breakdown
            category_pipeline = [
                {"$match": {f"platform_implementations.{platform_key}": {"$exists": True}}},
                {"$group": {"_id": "$category", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}}
            ]
            category_results = await ComplianceRule.aggregate(category_pipeline).to_list()
            
            # Calculate percentages
            categories = []
            for cat_result in category_results:
                categories.append({
                    "name": cat_result["_id"].replace("_", " ").title(),
                    "count": cat_result["count"],
                    "percentage": round((cat_result["count"] / rule_count) * 100, 1)
                })
            
            # Get framework support
            frameworks = []
            for framework in ['nist', 'cis', 'stig']:
                count = await ComplianceRule.find({
                    f"platform_implementations.{platform_key}": {"$exists": True},
                    f"frameworks.{framework}": {"$exists": True, "$ne": {}}
                }).count()
                if count > 0:
                    frameworks.append(framework)
            
            # Calculate coverage (simplified)
            coverage = min(95, 60 + (rule_count / 50))  # Simplified calculation
            
            platform_stat = {
                "name": platform_info["name"],
                "version": platform_info["versions"][-1],  # Latest version
                "ruleCount": rule_count,
                "categories": categories[:6],  # Top 6 categories
                "frameworks": frameworks,
                "coverage": round(coverage, 1)
            }
            
            platform_stats.append(platform_stat)
        
        result = {
            "platforms": platform_stats,
            "total_platforms": len(platform_stats),
            "total_rules_analyzed": await ComplianceRule.count(),
            "source": "mongodb_loaded"
        }
        
        logger.info(f"Generated statistics for {len(platform_stats)} platforms")
        return result

async def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(description='OpenWatch Compliance Rules Loader')
    parser.add_argument('command', choices=['load', 'validate', 'stats'],
                       help='Command to execute')
    parser.add_argument('--source', default='/home/rracine/hanalyx/openwatch/data/compliance_rules',
                       help='Source directory containing JSON rule files')
    parser.add_argument('--replace', action='store_true',
                       help='Replace existing rules if they exist')
    
    args = parser.parse_args()
    
    loader = ComplianceRulesLoader()
    
    # Initialize MongoDB
    if not await loader.initialize_mongodb():
        logger.error("Failed to initialize MongoDB connection")
        return 1
    
    try:
        if args.command == 'load':
            source_path = Path(args.source)
            results = await loader.load_rules_from_directory(source_path, args.replace)
            
            print(f"\n=== Loading Results ===")
            print(f"Successfully loaded: {results['loaded']}")
            print(f"Errors: {results['errors']}")
            print(f"Skipped (already exist): {results['skipped']}")
            print(f"Total processed: {results['total']}")
            
        elif args.command == 'validate':
            results = await loader.validate_loaded_rules()
            
            print(f"\n=== Validation Results ===")
            print(f"Total rules in database: {results['total_rules']}")
            print(f"\nSeverity distribution:")
            for severity, count in results['severity_distribution'].items():
                print(f"  {severity}: {count}")
            print(f"\nFramework coverage:")
            for framework, count in results['framework_coverage'].items():
                print(f"  {framework}: {count}")
            print(f"\nPlatform coverage:")
            for platform, count in results['platform_coverage'].items():
                print(f"  {platform}: {count}")
            
        elif args.command == 'stats':
            results = await loader.get_platform_statistics()
            
            print(f"\n=== Platform Statistics ===")
            print(f"Total platforms: {results['total_platforms']}")
            print(f"Total rules analyzed: {results['total_rules_analyzed']}")
            
            for platform in results['platforms']:
                print(f"\n{platform['name']} {platform['version']}:")
                print(f"  Rules: {platform['ruleCount']}")
                print(f"  Coverage: {platform['coverage']}%")
                print(f"  Frameworks: {', '.join(platform['frameworks'])}")
                print(f"  Top categories: {', '.join([cat['name'] for cat in platform['categories'][:3]])}")
    
    except Exception as e:
        logger.error(f"Command failed: {e}")
        return 1
    
    finally:
        # Close MongoDB connection
        await mongo_manager.close()
    
    return 0

if __name__ == '__main__':
    exit_code = asyncio.run(main())
    exit(exit_code)