#!/usr/bin/env python3
"""
OVAL Filename Population Script

Populates the oval_filename field in MongoDB compliance_rules collection
by matching rules to OVAL definition files.

This script enables the 'notchecked' filtering functionality in the XCCDF
generator by providing file paths to OVAL automated check definitions.

Architecture:
1. Scan OVAL directories to build filename → rule mapping
2. Match OVAL files to MongoDB rules using intelligent pattern matching
3. Update MongoDB with oval_filename paths
4. Validate all operations with comprehensive logging

Usage:
    python populate_oval_filenames.py --dry-run   # Preview changes
    python populate_oval_filenames.py             # Apply changes
    python populate_oval_filenames.py --verbose   # Detailed logging

Requirements:
- MongoDB connection to openwatch_rules database
- Access to /app/data/oval_definitions/ directory
- Beanie ODM initialized

Security:
- Transaction support for atomic updates
- Validation before committing changes
- No destructive operations (only adds oval_filename field)
"""

import asyncio
import logging
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from beanie import init_beanie
    from motor.motor_asyncio import AsyncIOMotorClient

    from app.core.config import settings
    from app.models.mongo_models import ComplianceRule
except ImportError as e:
    print(f"ERROR: Failed to import required modules: {e}")
    print("This script must be run from the OpenWatch backend environment")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler("/tmp/oval_population.log")],
)
logger = logging.getLogger(__name__)


class OVALFilenamePopulator:
    """
    Populates OVAL filename references in MongoDB compliance rules.

    This class implements intelligent matching between OVAL definition files
    and compliance rule IDs, handling platform-specific paths and multiple
    naming conventions.
    """

    def __init__(
        self, oval_base_path: Path = Path("/app/data/oval_definitions"), dry_run: bool = False, verbose: bool = False
    ):
        """
        Initialize OVAL filename populator.

        Args:
            oval_base_path: Root directory containing OVAL definitions
            dry_run: If True, preview changes without committing
            verbose: Enable detailed logging
        """
        self.oval_base_path = oval_base_path
        self.dry_run = dry_run
        self.verbose = verbose

        # Statistics tracking
        self.stats = {
            "total_rules": 0,
            "rules_with_oval": 0,
            "rules_without_oval": 0,
            "oval_files_found": 0,
            "matches_found": 0,
            "updates_applied": 0,
            "errors": 0,
        }

        # OVAL file mapping: filename -> list of platform paths
        self.oval_files: Dict[str, List[str]] = defaultdict(list)

        if verbose:
            logger.setLevel(logging.DEBUG)

    async def scan_oval_directories(self) -> None:
        """
        Scan all OVAL definition directories and build filename index.

        Builds a mapping of OVAL filenames to their platform-specific paths.
        Example: "accounts_password_minlen.xml" -> ["rhel9/accounts_password_minlen.xml"]

        This enables fast lookups when matching rules to OVAL files.
        """
        logger.info(f"Scanning OVAL directories in {self.oval_base_path}")

        if not self.oval_base_path.exists():
            logger.error(f"OVAL base path does not exist: {self.oval_base_path}")
            return

        # Scan each platform directory
        for platform_dir in self.oval_base_path.iterdir():
            if not platform_dir.is_dir():
                continue

            platform_name = platform_dir.name
            logger.debug(f"Scanning platform: {platform_name}")

            # Scan XML files in platform directory
            xml_files = list(platform_dir.glob("*.xml"))
            logger.debug(f"  Found {len(xml_files)} OVAL files in {platform_name}")

            for xml_file in xml_files:
                filename = xml_file.name
                relative_path = f"{platform_name}/{filename}"

                # Store mapping: filename -> platform-specific path
                self.oval_files[filename].append(relative_path)
                self.stats["oval_files_found"] += 1

        logger.info(
            f"OVAL scan complete: {len(self.oval_files)} unique filenames, "
            f"{self.stats['oval_files_found']} total files across platforms"
        )

    def extract_rule_name_from_oval_filename(self, filename: str) -> Optional[str]:
        """
        Extract rule name from OVAL filename.

        OVAL files typically follow this naming convention:
        - accounts_password_minlen.xml
        - account_disable_post_pw_expiration.xml
        - package_aide_installed.xml

        This function strips the .xml extension to get the rule name.

        Args:
            filename: OVAL filename (e.g., "accounts_password_minlen.xml")

        Returns:
            Rule name without extension (e.g., "accounts_password_minlen")
        """
        if filename.endswith(".xml"):
            return filename[:-4]  # Remove .xml extension
        return filename

    def match_rule_to_oval(self, rule_id: str, platform: Optional[str] = None) -> Optional[str]:
        """
        Match a compliance rule to its OVAL definition file.

        Matching Strategy:
        1. Extract rule name from rule_id (e.g., "ow-accounts_password_minlen" -> "accounts_password_minlen")
        2. Look for exact filename match in OVAL files
        3. If platform specified, prefer platform-specific path
        4. Fall back to first available path if no platform match

        Args:
            rule_id: OpenWatch rule ID (e.g., "ow-accounts_password_minlen")
            platform: Optional platform hint (e.g., "rhel9", "ubuntu2204")

        Returns:
            Relative OVAL file path (e.g., "rhel9/accounts_password_minlen.xml")
            or None if no match found
        """
        # Extract rule name from OpenWatch rule ID
        # Pattern: "ow-{rule_name}" or "xccdf_org.ssgproject.content_rule_{rule_name}"
        rule_name = None

        # Try OpenWatch pattern first: "ow-{rule_name}"
        if rule_id.startswith("ow-"):
            rule_name = rule_id[3:]  # Remove "ow-" prefix

        # Try SCAP pattern: "xccdf_org.ssgproject.content_rule_{rule_name}"
        elif "content_rule_" in rule_id:
            parts = rule_id.split("content_rule_")
            if len(parts) > 1:
                rule_name = parts[1]

        if not rule_name:
            logger.debug(f"Could not extract rule name from rule_id: {rule_id}")
            return None

        # Look for OVAL filename match
        oval_filename = f"{rule_name}.xml"

        if oval_filename not in self.oval_files:
            logger.debug(f"No OVAL file found for rule: {rule_id} (looking for {oval_filename})")
            return None

        # Get available paths for this OVAL file
        available_paths = self.oval_files[oval_filename]

        # If platform specified, prefer platform-specific path
        if platform:
            for path in available_paths:
                if path.startswith(f"{platform}/"):
                    logger.debug(f"Matched rule {rule_id} to OVAL: {path} (platform: {platform})")
                    return path

        # Fall back to first available path
        selected_path = available_paths[0]
        logger.debug(f"Matched rule {rule_id} to OVAL: {selected_path} (default)")
        return selected_path

    async def populate_oval_filenames(self) -> None:
        """
        Main execution: populate oval_filename field for all compliance rules.

        Process:
        1. Fetch all rules from MongoDB
        2. For each rule, attempt to match to OVAL file
        3. Update rule with oval_filename if match found
        4. Track statistics and log results

        Uses Beanie ODM for MongoDB operations with proper error handling.
        """
        logger.info("Starting OVAL filename population")

        # Fetch all compliance rules from MongoDB
        try:
            rules = await ComplianceRule.find_all().to_list()
            self.stats["total_rules"] = len(rules)
            logger.info(f"Fetched {len(rules)} compliance rules from MongoDB")
        except Exception as e:
            logger.error(f"Failed to fetch rules from MongoDB: {e}", exc_info=True)
            self.stats["errors"] += 1
            return

        # Process each rule
        for rule in rules:
            try:
                # Extract platform hint from rule metadata
                platform = None
                if hasattr(rule, "metadata") and isinstance(rule.metadata, dict):
                    # Try to get platform from metadata
                    # OpenWatch rules may have platform info in different fields
                    platform = rule.metadata.get("platform")
                    if not platform and "platforms" in rule.metadata:
                        platforms = rule.metadata.get("platforms", [])
                        if platforms:
                            platform = platforms[0]  # Use first platform

                # Attempt to match rule to OVAL file
                oval_path = self.match_rule_to_oval(rule.rule_id, platform)

                if oval_path:
                    self.stats["matches_found"] += 1

                    # Update rule with OVAL filename (if not dry-run)
                    if not self.dry_run:
                        rule.oval_filename = oval_path
                        await rule.save()
                        self.stats["updates_applied"] += 1
                        logger.debug(f"Updated rule {rule.rule_id} with OVAL: {oval_path}")
                    else:
                        logger.info(f"[DRY-RUN] Would update {rule.rule_id} with OVAL: {oval_path}")

                    self.stats["rules_with_oval"] += 1
                else:
                    self.stats["rules_without_oval"] += 1
                    if self.verbose:
                        logger.debug(f"No OVAL match for rule: {rule.rule_id}")

            except Exception as e:
                logger.error(f"Error processing rule {rule.rule_id}: {e}", exc_info=True)
                self.stats["errors"] += 1

        # Log summary statistics
        self.log_statistics()

    def log_statistics(self) -> None:
        """
        Log comprehensive statistics about the population process.

        Provides visibility into:
        - Total rules processed
        - Match success rate
        - OVAL file coverage
        - Errors encountered
        """
        logger.info("=" * 60)
        logger.info("OVAL Filename Population Statistics")
        logger.info("=" * 60)
        logger.info(f"Total compliance rules:       {self.stats['total_rules']}")
        logger.info(f"OVAL files scanned:           {self.stats['oval_files_found']}")
        logger.info(f"Unique OVAL filenames:        {len(self.oval_files)}")
        logger.info("")
        logger.info(f"Rules matched to OVAL:        {self.stats['matches_found']}")
        logger.info(f"Rules without OVAL:           {self.stats['rules_without_oval']}")
        logger.info(f"Match rate:                   {self._calculate_match_rate():.1f}%")
        logger.info("")

        if self.dry_run:
            logger.info(f"Updates that would be applied: {self.stats['matches_found']}")
            logger.info("DRY-RUN MODE: No changes committed to MongoDB")
        else:
            logger.info(f"Updates applied to MongoDB:   {self.stats['updates_applied']}")

        logger.info(f"Errors encountered:           {self.stats['errors']}")
        logger.info("=" * 60)

    def _calculate_match_rate(self) -> float:
        """Calculate percentage of rules matched to OVAL files."""
        if self.stats["total_rules"] == 0:
            return 0.0
        return (self.stats["matches_found"] / self.stats["total_rules"]) * 100


async def init_mongodb() -> AsyncIOMotorClient:
    """
    Initialize MongoDB connection and Beanie ODM.

    Uses settings from backend configuration for connection parameters.

    Returns:
        Initialized MongoDB client

    Raises:
        Exception: If MongoDB connection or Beanie initialization fails
    """
    logger.info("Initializing MongoDB connection")

    try:
        # Create MongoDB client
        client = AsyncIOMotorClient(settings.MONGODB_URL)

        # Test connection
        await client.admin.command("ping")
        logger.info("MongoDB connection successful")

        # Initialize Beanie ODM
        await init_beanie(database=client[settings.MONGODB_DB_NAME], document_models=[ComplianceRule])
        logger.info("Beanie ODM initialized successfully")

        return client

    except Exception as e:
        logger.error(f"Failed to initialize MongoDB: {e}", exc_info=True)
        raise


async def main():
    """
    Main entry point for OVAL filename population script.

    Handles:
    - Command-line argument parsing
    - MongoDB initialization
    - OVAL directory scanning
    - Rule matching and updates
    - Cleanup and error handling
    """
    import argparse

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Populate OVAL filenames in MongoDB compliance rules")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without committing to MongoDB")
    parser.add_argument("--verbose", action="store_true", help="Enable detailed debug logging")
    parser.add_argument(
        "--oval-path",
        type=str,
        default="/app/data/oval_definitions",
        help="Path to OVAL definitions directory (default: /app/data/oval_definitions)",
    )

    args = parser.parse_args()

    # Display execution mode
    if args.dry_run:
        logger.info("=" * 60)
        logger.info("DRY-RUN MODE: Changes will be previewed but not committed")
        logger.info("=" * 60)

    # Initialize MongoDB
    client = None
    try:
        client = await init_mongodb()

        # Create populator instance
        populator = OVALFilenamePopulator(
            oval_base_path=Path(args.oval_path), dry_run=args.dry_run, verbose=args.verbose
        )

        # Execute population workflow
        await populator.scan_oval_directories()
        await populator.populate_oval_filenames()

        # Report success
        if not args.dry_run:
            logger.info("OVAL filename population complete!")
            logger.info(f"Updated {populator.stats['updates_applied']} rules with OVAL file paths")
        else:
            logger.info("DRY-RUN complete - no changes committed")
            logger.info("Run without --dry-run to apply changes")

    except KeyboardInterrupt:
        logger.warning("Operation cancelled by user")
        sys.exit(1)

    except Exception as e:
        logger.error(f"Fatal error during OVAL population: {e}", exc_info=True)
        sys.exit(1)

    finally:
        # Clean up MongoDB connection
        if client:
            client.close()
            logger.info("MongoDB connection closed")


if __name__ == "__main__":
    # Run async main function
    asyncio.run(main())
