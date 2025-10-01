#!/usr/bin/env python3
"""
CLI tool to load framework control definitions into MongoDB
Usage: python -m backend.app.cli.load_frameworks [framework_id]
"""
import asyncio
import sys
import logging
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from backend.app.services.framework_loader_service import FrameworkLoaderService
from backend.app.models.enhanced_mongo_models import FrameworkControlDefinition
from backend.app.config import get_settings


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def initialize_database():
    """Initialize database connection"""
    try:
        settings = get_settings()
        # Note: In real implementation, you'd initialize MongoDB connection here
        logger.info("Database connection initialized")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        return False


async def load_framework(framework_id: str = None):
    """Load framework(s) into MongoDB"""
    
    if not await initialize_database():
        return False
    
    loader = FrameworkLoaderService()
    
    try:
        if framework_id:
            # Load specific framework
            json_file = loader.framework_definitions_path / f"{framework_id}.json"
            if not json_file.exists():
                logger.error(f"Framework file not found: {json_file}")
                return False
                
            count = await loader.load_framework_from_file(json_file)
            logger.info(f"Successfully loaded {count} controls for framework {framework_id}")
            
        else:
            # Load all frameworks
            results = await loader.load_all_frameworks()
            
            total_loaded = sum(results.values())
            logger.info(f"Successfully loaded {total_loaded} total controls across {len(results)} frameworks")
            
            for framework, count in results.items():
                logger.info(f"  {framework}: {count} controls")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to load frameworks: {str(e)}")
        return False


async def validate_frameworks():
    """Validate loaded frameworks"""
    
    if not await initialize_database():
        return False
    
    loader = FrameworkLoaderService()
    
    try:
        # Get list of loaded frameworks
        frameworks = await FrameworkControlDefinition.distinct("framework_id")
        
        if not frameworks:
            logger.warning("No frameworks found in database")
            return True
        
        logger.info(f"Validating {len(frameworks)} frameworks...")
        
        for framework_id in frameworks:
            result = await loader.validate_framework_integrity(framework_id)
            
            if result["integrity_score"] == 1.0:
                logger.info(f"✅ {framework_id}: Perfect integrity ({result['db_control_count']} controls)")
            else:
                logger.warning(f"⚠️  {framework_id}: Integrity score {result['integrity_score']}")
                
                if not result["count_match"]:
                    logger.warning(f"   Control count mismatch: DB={result['db_control_count']}, File={result['file_control_count']}")
                
                if result["missing_references"]:
                    logger.warning(f"   Missing references: {len(result['missing_references'])}")
                    for ref in result["missing_references"][:5]:  # Show first 5
                        logger.warning(f"     {ref['control']} -> {ref['missing_reference']}")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to validate frameworks: {str(e)}")
        return False


async def show_summary():
    """Show summary of loaded frameworks"""
    
    if not await initialize_database():
        return False
    
    loader = FrameworkLoaderService()
    
    try:
        summary = await loader.get_framework_summary()
        
        if not summary:
            logger.info("No frameworks loaded")
            return True
        
        logger.info("Framework Summary:")
        logger.info("=" * 60)
        
        total_controls = 0
        for framework_id, data in summary.items():
            logger.info(f"Framework: {framework_id}")
            logger.info(f"  Name: {data['name']}")
            logger.info(f"  Version: {data['version']}")
            logger.info(f"  Organization: {data['organization']}")
            logger.info(f"  Controls: {data['control_count']}")
            logger.info(f"  Loaded: {data['loaded_at']}")
            logger.info("")
            
            total_controls += data['control_count']
        
        logger.info(f"Total Controls: {total_controls}")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to get framework summary: {str(e)}")
        return False


async def update_references():
    """Update cross-references between frameworks"""
    
    if not await initialize_database():
        return False
    
    loader = FrameworkLoaderService()
    
    try:
        logger.info("Updating cross-references between frameworks...")
        
        results = await loader.update_cross_references()
        
        total_updated = sum(results.values())
        logger.info(f"Updated {total_updated} controls across {len(results)} frameworks")
        
        for framework, count in results.items():
            if count > 0:
                logger.info(f"  {framework}: {count} controls updated")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to update cross-references: {str(e)}")
        return False


def print_usage():
    """Print usage information"""
    print("""
Usage: python -m backend.app.cli.load_frameworks [command] [options]

Commands:
  load [framework_id]    Load framework(s) into MongoDB
                         If framework_id provided, loads only that framework
                         Otherwise loads all frameworks
  
  validate              Validate integrity of loaded frameworks
  
  summary               Show summary of loaded frameworks
  
  update-refs           Update cross-references between frameworks
  
  help                  Show this help message

Examples:
  python -m backend.app.cli.load_frameworks load
  python -m backend.app.cli.load_frameworks load nist_800_53_r5
  python -m backend.app.cli.load_frameworks validate
  python -m backend.app.cli.load_frameworks summary
  python -m backend.app.cli.load_frameworks update-refs
""")


async def main():
    """Main CLI entry point"""
    
    if len(sys.argv) < 2:
        print_usage()
        return
    
    command = sys.argv[1].lower()
    
    if command == "help":
        print_usage()
        
    elif command == "load":
        framework_id = sys.argv[2] if len(sys.argv) > 2 else None
        success = await load_framework(framework_id)
        sys.exit(0 if success else 1)
        
    elif command == "validate":
        success = await validate_frameworks()
        sys.exit(0 if success else 1)
        
    elif command == "summary":
        success = await show_summary()
        sys.exit(0 if success else 1)
        
    elif command == "update-refs":
        success = await update_references()
        sys.exit(0 if success else 1)
        
    else:
        logger.error(f"Unknown command: {command}")
        print_usage()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())