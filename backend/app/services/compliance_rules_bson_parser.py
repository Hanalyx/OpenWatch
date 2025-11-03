"""
BSON Parser Service for Compliance Rules
Handles Binary JSON parsing and validation for compliance rule uploads
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import bson
from bson import BSON, Binary, Decimal128, ObjectId, decode, encode
from bson.errors import InvalidBSON

logger = logging.getLogger(__name__)


class BSONParsingError(Exception):
    """BSON parsing specific exceptions"""

    pass


class BSONParserService:
    """Parse and validate BSON compliance rule files"""

    # MongoDB BSON document size limit
    MAX_BSON_SIZE = 16 * 1024 * 1024  # 16MB per BSON document

    # Maximum individual rule file size (more restrictive for safety)
    MAX_RULE_FILE_SIZE = 1 * 1024 * 1024  # 1MB per rule file

    def __init__(self):
        self.parsed_rules_count = 0
        self.parsing_errors: List[Dict[str, Any]] = []

    async def parse_bson_file(self, file_path: Path) -> Dict[str, Any]:
        """
        Parse a single BSON file

        Args:
            file_path: Path to .bson file

        Returns:
            Decoded dictionary

        Raises:
            BSONParsingError: If parsing fails
        """
        try:
            # Check file size
            file_size = file_path.stat().st_size

            if file_size == 0:
                raise BSONParsingError(f"BSON file is empty: {file_path.name}")

            if file_size > self.MAX_BSON_SIZE:
                raise BSONParsingError(f"BSON file too large: {file_size:,} bytes " f"(max: {self.MAX_BSON_SIZE:,})")

            # Read BSON data
            with open(file_path, "rb") as f:
                bson_data = f.read()

            # Quick validation check
            if not self.validate_bson_structure(bson_data):
                raise BSONParsingError(f"Invalid BSON structure in {file_path.name}")

            # Decode BSON to Python dict
            decoded = bson.decode(bson_data)

            # Validate basic structure
            if not isinstance(decoded, dict):
                raise BSONParsingError(f"BSON file did not decode to dictionary: {type(decoded).__name__}")

            # Convert BSON-specific types to Python types
            normalized = self._normalize_bson_types(decoded)

            logger.debug(f"Successfully parsed BSON file: {file_path.name}")
            self.parsed_rules_count += 1

            return normalized

        except InvalidBSON as e:
            error_msg = f"Invalid BSON format: {str(e)}"
            logger.error(f"{error_msg} in {file_path}")
            raise BSONParsingError(error_msg)

        except Exception as e:
            error_msg = f"Failed to parse BSON file: {str(e)}"
            logger.error(f"{error_msg} - {file_path}")
            raise BSONParsingError(error_msg)

    async def parse_json_file(self, file_path: Path) -> Dict[str, Any]:
        """
        Parse a JSON file (backward compatibility)

        Args:
            file_path: Path to .json file

        Returns:
            Decoded dictionary

        Raises:
            BSONParsingError: If parsing fails
        """
        import json

        try:
            file_size = file_path.stat().st_size

            if file_size == 0:
                raise BSONParsingError(f"JSON file is empty: {file_path.name}")

            if file_size > self.MAX_RULE_FILE_SIZE:
                raise BSONParsingError(
                    f"JSON file too large: {file_size:,} bytes " f"(max: {self.MAX_RULE_FILE_SIZE:,})"
                )

            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                raise BSONParsingError(f"JSON file did not decode to dictionary: {type(data).__name__}")

            logger.debug(f"Successfully parsed JSON file: {file_path.name}")
            self.parsed_rules_count += 1

            return data

        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON format: {str(e)}"
            logger.error(f"{error_msg} in {file_path}")
            raise BSONParsingError(error_msg)

        except Exception as e:
            error_msg = f"Failed to parse JSON file: {str(e)}"
            logger.error(f"{error_msg} - {file_path}")
            raise BSONParsingError(error_msg)

    async def parse_manifest_bson(self, manifest_path: Path) -> Dict[str, Any]:
        """
        Parse manifest.bson file and validate required fields

        Args:
            manifest_path: Path to manifest.bson

        Returns:
            Validated manifest dictionary

        Raises:
            BSONParsingError: If parsing or validation fails
        """
        manifest = await self.parse_bson_file(manifest_path)

        # Validate required manifest fields
        required_fields = ["name", "version", "rules_count", "created_at"]
        missing = [f for f in required_fields if f not in manifest]

        if missing:
            raise BSONParsingError(f"Manifest missing required fields: {', '.join(missing)}")

        # Validate field types
        if not isinstance(manifest["name"], str):
            raise BSONParsingError(f"Manifest 'name' must be string, got {type(manifest['name']).__name__}")

        if not isinstance(manifest["version"], str):
            raise BSONParsingError(f"Manifest 'version' must be string, got {type(manifest['version']).__name__}")

        if not isinstance(manifest["rules_count"], int):
            raise BSONParsingError(
                f"Manifest 'rules_count' must be integer, got {type(manifest['rules_count']).__name__}"
            )

        # Convert created_at to datetime if string
        if isinstance(manifest["created_at"], str):
            try:
                manifest["created_at"] = datetime.fromisoformat(manifest["created_at"].replace("Z", "+00:00"))
            except ValueError as e:
                raise BSONParsingError(f"Invalid created_at format: {str(e)}")
        elif not isinstance(manifest["created_at"], datetime):
            raise BSONParsingError(f"Manifest 'created_at' must be datetime or ISO string")

        logger.info(f"Parsed manifest: {manifest['name']} v{manifest['version']} ({manifest['rules_count']} rules)")

        return manifest

    async def parse_manifest_json(self, manifest_path: Path) -> Dict[str, Any]:
        """
        Parse manifest.json file (backward compatibility)

        Args:
            manifest_path: Path to manifest.json

        Returns:
            Validated manifest dictionary

        Raises:
            BSONParsingError: If parsing or validation fails
        """
        manifest = await self.parse_json_file(manifest_path)

        # Validate required manifest fields
        required_fields = ["name", "version", "rules_count", "created_at"]
        missing = [f for f in required_fields if f not in manifest]

        if missing:
            raise BSONParsingError(f"Manifest missing required fields: {', '.join(missing)}")

        # Convert created_at to datetime if string
        if isinstance(manifest["created_at"], str):
            try:
                manifest["created_at"] = datetime.fromisoformat(manifest["created_at"].replace("Z", "+00:00"))
            except ValueError as e:
                raise BSONParsingError(f"Invalid created_at format: {str(e)}")

        logger.info(f"Parsed manifest: {manifest['name']} v{manifest['version']} ({manifest['rules_count']} rules)")

        return manifest

    async def parse_all_rule_files(self, extracted_path: Path, max_rules: int = 10000) -> List[Dict[str, Any]]:
        """
        Parse all rule files (.bson and .json) in directory

        Args:
            extracted_path: Path to extracted archive directory
            max_rules: Maximum number of rules to parse

        Returns:
            List of parsed rule dictionaries

        Raises:
            BSONParsingError: If too many rules or critical parsing failures
        """
        # Find all BSON files
        bson_files = list(extracted_path.glob("**/*.bson"))
        bson_files = [f for f in bson_files if f.name != "manifest.bson"]

        # Find all JSON files (backward compatibility)
        json_files = list(extracted_path.glob("**/*.json"))
        json_files = [f for f in json_files if f.name not in ["manifest.json", "checksums.sha512"]]

        all_files = bson_files + json_files

        logger.info(f"Found {len(bson_files)} BSON files and {len(json_files)} JSON files")

        # Check rule count limit
        if len(all_files) > max_rules:
            raise BSONParsingError(f"Archive contains {len(all_files)} rule files (max: {max_rules})")

        if len(all_files) == 0:
            raise BSONParsingError("Archive contains no rule files")

        # Parse all files
        rules = []
        self.parsing_errors = []

        for file_path in all_files:
            try:
                # Determine file type and parse accordingly
                if file_path.suffix == ".bson":
                    rule_data = await self.parse_bson_file(file_path)
                else:  # .json
                    rule_data = await self.parse_json_file(file_path)

                # Basic validation - must have rule_id
                if "rule_id" not in rule_data:
                    self.parsing_errors.append(
                        {
                            "file": str(file_path.name),
                            "error": "Missing required field: rule_id",
                            "severity": "error",
                        }
                    )
                    continue

                rules.append(rule_data)

            except BSONParsingError as e:
                self.parsing_errors.append({"file": str(file_path.name), "error": str(e), "severity": "error"})
                logger.error(f"Failed to parse {file_path.name}: {e}")

            except Exception as e:
                self.parsing_errors.append(
                    {
                        "file": str(file_path.name),
                        "error": f"Unexpected error: {str(e)}",
                        "severity": "error",
                    }
                )
                logger.error(f"Unexpected error parsing {file_path.name}: {e}")

        # Log summary
        logger.info(f"Parsed {len(rules)} rules successfully, " f"{len(self.parsing_errors)} errors")

        if self.parsing_errors:
            logger.warning(f"Parsing errors: {self.parsing_errors}")

        return rules

    def validate_bson_structure(self, bson_data: bytes) -> bool:
        """
        Validate BSON structure without full parsing

        Args:
            bson_data: Raw BSON bytes

        Returns:
            True if valid BSON structure, False otherwise
        """
        try:
            # Quick validation - just check if decodable
            decoded = bson.decode(bson_data)
            return isinstance(decoded, dict)
        except (InvalidBSON, Exception):
            return False

    def _normalize_bson_types(self, data: Any) -> Any:
        """
        Normalize BSON-specific types to Python types

        Handles:
        - ObjectId → str
        - Binary → bytes (preserve)
        - Decimal128 → float
        - datetime → datetime (preserve)
        - Nested dicts and lists (recursive)

        Args:
            data: Data structure to normalize

        Returns:
            Normalized data structure
        """
        if isinstance(data, ObjectId):
            # Convert ObjectId to string for JSON compatibility
            return str(data)

        elif isinstance(data, Binary):
            # Preserve binary data (convert to hex string for safety)
            return data.hex()

        elif isinstance(data, Decimal128):
            # Convert Decimal128 to float
            return float(data.to_decimal())

        elif isinstance(data, datetime):
            # Preserve datetime objects
            return data

        elif isinstance(data, dict):
            # Recursively normalize dictionary values
            return {k: self._normalize_bson_types(v) for k, v in data.items()}

        elif isinstance(data, list):
            # Recursively normalize list items
            return [self._normalize_bson_types(item) for item in data]

        else:
            # Return as-is for standard Python types
            return data

    def get_parsing_statistics(self) -> Dict[str, Any]:
        """
        Get parsing statistics

        Returns:
            Dictionary with parsing metrics
        """
        return {
            "parsed_rules_count": self.parsed_rules_count,
            "parsing_errors_count": len(self.parsing_errors),
            "parsing_errors": self.parsing_errors,
        }

    def reset_statistics(self):
        """Reset parsing statistics for new upload"""
        self.parsed_rules_count = 0
        self.parsing_errors = []


async def detect_file_format(file_path: Path) -> str:
    """
    Detect whether file is BSON or JSON

    Args:
        file_path: Path to file

    Returns:
        'bson' or 'json'

    Raises:
        ValueError: If format cannot be determined
    """
    # First check file extension
    if file_path.suffix == ".bson":
        return "bson"
    elif file_path.suffix == ".json":
        return "json"

    # If no clear extension, try to detect by content
    try:
        with open(file_path, "rb") as f:
            first_bytes = f.read(16)

        # JSON files typically start with { or [
        if first_bytes and first_bytes[0] in [ord("{"), ord("[")]:
            return "json"

        # Try BSON decode
        try:
            bson.decode(first_bytes)
            return "bson"
        except:
            pass

        raise ValueError("Cannot determine file format")

    except Exception as e:
        raise ValueError(f"Cannot detect file format: {str(e)}")
