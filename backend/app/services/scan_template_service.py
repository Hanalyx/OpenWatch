"""
Scan template service for managing saved scan configurations.

Provides CRUD operations for scan templates, including creation, listing,
updating, deletion, and application to targets.
"""

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from ..models.scan_config_models import ScanTargetType, ScanTemplate, TemplateStatistics
from ..repositories import ScanTemplateRepository

logger = logging.getLogger(__name__)


class ScanTemplateService:
    """
    Service for managing scan configuration templates.

    Provides methods to:
    - Create and save scan templates
    - List templates with filters
    - Update existing templates
    - Delete templates
    - Apply templates to targets
    - Query template statistics
    """

    def __init__(self, db: AsyncIOMotorDatabase):
        """
        Initialize scan template service.

        Args:
            db: MongoDB database instance
        """
        self.db = db
        # Repository Pattern: Centralized MongoDB access
        self._template_repo = ScanTemplateRepository()

    async def create_template(
        self,
        name: str,
        framework: str,
        framework_version: str,
        target_type: ScanTargetType,
        variable_overrides: Dict[str, str],
        rule_filter: Optional[Dict[str, Any]] = None,
        description: Optional[str] = None,
        tags: Optional[List[str]] = None,
        created_by: str = None,
        is_public: bool = False,
    ) -> ScanTemplate:
        """
        Create and save a scan template.

        Args:
            name: Template name
            framework: Framework identifier
            framework_version: Framework version
            target_type: Target system type
            variable_overrides: Variable value overrides
            rule_filter: Rule selection filter
            description: Template description
            tags: User-defined tags
            created_by: Creator username
            is_public: Public visibility flag

        Returns:
            Created ScanTemplate document

        Raises:
            ValueError: Invalid parameters
        """
        logger.info(f"Creating template: {name} ({framework}/{framework_version})")

        # Generate template ID
        template_id = f"tpl_{uuid.uuid4().hex[:12]}"

        # Create template document
        template = ScanTemplate(
            template_id=template_id,
            name=name,
            description=description,
            framework=framework,
            framework_version=framework_version,
            target_type=target_type,
            variable_overrides=variable_overrides or {},
            rule_filter=rule_filter,
            created_by=created_by or "unknown",
            tags=tags or [],
            is_public=is_public,
        )

        # Repository Pattern: Use create() for new documents
        await self._template_repo.create(template)

        logger.info(f"Created template {template_id}")
        return template

    async def get_template(self, template_id: str) -> Optional[ScanTemplate]:
        """
        Get template by ID.

        Args:
            template_id: Template ID

        Returns:
            ScanTemplate or None if not found
        """
        # Repository Pattern: Use find_by_template_id() for lookup
        return await self._template_repo.find_by_template_id(template_id)

    async def list_templates(
        self,
        created_by: Optional[str] = None,
        framework: Optional[str] = None,
        tags: Optional[List[str]] = None,
        is_public: Optional[bool] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> List[ScanTemplate]:
        """
        List templates with filters.

        Args:
            created_by: Filter by creator
            framework: Filter by framework
            tags: Filter by tags (any match)
            is_public: Filter by visibility
            skip: Pagination offset
            limit: Max results

        Returns:
            List of ScanTemplate documents
        """
        query = {}

        if created_by:
            # Show user's own templates OR public templates
            query["$or"] = [{"created_by": created_by}, {"is_public": True}]

        if framework:
            query["framework"] = framework

        if tags:
            query["tags"] = {"$in": tags}

        if is_public is not None:
            query["is_public"] = is_public

        # Repository Pattern: Use find_many() with pagination
        templates = await self._template_repo.find_many(query, skip=skip, limit=limit, sort=[("created_at", -1)])

        return templates

    async def update_template(
        self,
        template_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        variable_overrides: Optional[Dict[str, str]] = None,
        rule_filter: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        is_public: Optional[bool] = None,
    ) -> ScanTemplate:
        """
        Update template fields.

        Args:
            template_id: Template ID
            name: New name
            description: New description
            variable_overrides: New variable overrides
            rule_filter: New rule filter
            tags: New tags
            is_public: New visibility

        Returns:
            Updated ScanTemplate

        Raises:
            ValueError: Template not found
        """
        logger.info(f"Updating template {template_id}")

        template = await self.get_template(template_id)
        if not template:
            raise ValueError(f"Template {template_id} not found")

        # Build update document
        update_fields: Dict[str, Any] = {}

        if name is not None:
            update_fields["name"] = name

        if description is not None:
            update_fields["description"] = description

        if variable_overrides is not None:
            update_fields["variable_overrides"] = variable_overrides

        if rule_filter is not None:
            update_fields["rule_filter"] = rule_filter

        if tags is not None:
            update_fields["tags"] = tags

        if is_public is not None:
            update_fields["is_public"] = is_public

        # Update timestamp and version
        update_fields["updated_at"] = datetime.utcnow()
        update_fields["version"] = template.version + 1

        # Repository Pattern: Use update_one() for updates
        await self._template_repo.update_one(
            {"template_id": template_id},
            {"$set": update_fields},
        )

        # Fetch updated template
        updated_template = await self._template_repo.find_by_template_id(template_id)
        if not updated_template:
            raise ValueError(f"Template {template_id} not found after update")

        logger.info(f"Updated template {template_id} to version {updated_template.version}")
        return updated_template

    async def delete_template(self, template_id: str):
        """
        Delete template.

        Args:
            template_id: Template ID

        Raises:
            ValueError: Template not found
        """
        logger.info(f"Deleting template {template_id}")

        template = await self.get_template(template_id)
        if not template:
            raise ValueError(f"Template {template_id} not found")

        # Repository Pattern: Use delete_one() for deletions
        await self._template_repo.delete_one({"template_id": template_id})
        logger.info(f"Deleted template {template_id}")

    async def apply_template(
        self,
        template_id: str,
        target: Dict[str, Any],
        additional_overrides: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Apply template to create scan configuration.

        Args:
            template_id: Template ID
            target: Target configuration dict
            additional_overrides: Additional variable overrides

        Returns:
            ScanConfiguration dict ready for scan service

        Raises:
            ValueError: Template not found
        """
        logger.info(f"Applying template {template_id}")

        template = await self.get_template(template_id)
        if not template:
            raise ValueError(f"Template {template_id} not found")

        # Merge variable overrides
        variable_overrides = dict(template.variable_overrides)
        if additional_overrides:
            variable_overrides.update(additional_overrides)

        # Build scan configuration
        scan_config = {
            "target": target,
            "framework": template.framework,
            "framework_version": template.framework_version,
            "variable_overrides": variable_overrides,
            "rule_filter": template.rule_filter,
        }

        logger.info(f"Applied template {template_id}")
        return scan_config

    async def set_as_default(self, template_id: str, created_by: str) -> ScanTemplate:
        """
        Set template as default for user/framework.

        Clears any existing default for same user/framework.

        Args:
            template_id: Template ID
            created_by: Username

        Returns:
            Updated ScanTemplate

        Raises:
            ValueError: Template not found
        """
        logger.info(f"Setting template {template_id} as default for {created_by}")

        template = await self.get_template(template_id)
        if not template:
            raise ValueError(f"Template {template_id} not found")

        # Repository Pattern: Clear existing defaults for this user/framework
        await self._template_repo.update_many(
            {
                "created_by": created_by,
                "framework": template.framework,
                "is_default": True,
            },
            {"$set": {"is_default": False}},
        )

        # Repository Pattern: Set this template as default
        await self._template_repo.update_one(
            {"template_id": template_id},
            {"$set": {"is_default": True}},
        )

        # Fetch updated template
        updated = await self._template_repo.find_by_template_id(template_id)

        logger.info(f"Set template {template_id} as default")
        return updated if updated else template

    async def get_default_template(self, framework: str, created_by: str) -> Optional[ScanTemplate]:
        """
        Get default template for user/framework.

        Args:
            framework: Framework identifier
            created_by: Username

        Returns:
            Default ScanTemplate or None
        """
        # Repository Pattern: Use find_one() with query
        return await self._template_repo.find_one(
            {
                "created_by": created_by,
                "framework": framework,
                "is_default": True,
            }
        )

    async def clone_template(self, template_id: str, new_name: str, created_by: str) -> ScanTemplate:
        """
        Clone existing template with new name.

        Args:
            template_id: Source template ID
            new_name: New template name
            created_by: New owner username

        Returns:
            Cloned ScanTemplate

        Raises:
            ValueError: Source template not found
        """
        logger.info(f"Cloning template {template_id} as '{new_name}'")

        source = await self.get_template(template_id)
        if not source:
            raise ValueError(f"Template {template_id} not found")

        # Create clone
        clone = await self.create_template(
            name=new_name,
            framework=source.framework,
            framework_version=source.framework_version,
            target_type=source.target_type,
            variable_overrides=dict(source.variable_overrides),
            rule_filter=source.rule_filter,
            description=f"Cloned from: {source.name}",
            tags=list(source.tags),
            created_by=created_by,
            is_public=False,
        )

        logger.info(f"Cloned template {template_id} to {clone.template_id}")
        return clone

    async def get_statistics(self, created_by: Optional[str] = None) -> TemplateStatistics:
        """
        Get template usage statistics.

        Args:
            created_by: Filter by user (None for global stats)

        Returns:
            TemplateStatistics
        """
        query = {}
        if created_by:
            query["created_by"] = created_by

        # Repository Pattern: Use find_many() for queries
        templates = await self._template_repo.find_many(query, limit=10000)

        # Calculate statistics
        stats = TemplateStatistics()
        stats.total_templates = len(templates)

        framework_counts = {}
        user_counts = {}

        for template in templates:
            # By framework
            framework_counts[template.framework] = framework_counts.get(template.framework, 0) + 1

            # By user
            user_counts[template.created_by] = user_counts.get(template.created_by, 0) + 1

            # Public count
            if template.is_public:
                stats.public_templates += 1

        stats.by_framework = framework_counts
        stats.by_user = user_counts

        return stats

    async def share_template(self, template_id: str, username: str) -> ScanTemplate:
        """
        Share template with a user.

        Args:
            template_id: Template ID
            username: Username to share with

        Returns:
            Updated ScanTemplate

        Raises:
            ValueError: Template not found
        """
        logger.info(f"Sharing template {template_id} with {username}")

        template = await self.get_template(template_id)
        if not template:
            raise ValueError(f"Template {template_id} not found")

        if username not in template.shared_with:
            # Repository Pattern: Use update_one() with $addToSet
            await self._template_repo.update_one(
                {"template_id": template_id},
                {"$addToSet": {"shared_with": username}},
            )
            template.shared_with.append(username)

        logger.info(f"Shared template {template_id} with {username}")
        return template

    async def unshare_template(self, template_id: str, username: str) -> ScanTemplate:
        """
        Revoke template sharing.

        Args:
            template_id: Template ID
            username: Username to revoke access

        Returns:
            Updated ScanTemplate

        Raises:
            ValueError: Template not found
        """
        logger.info(f"Unsharing template {template_id} from {username}")

        template = await self.get_template(template_id)
        if not template:
            raise ValueError(f"Template {template_id} not found")

        if username in template.shared_with:
            # Repository Pattern: Use update_one() with $pull
            await self._template_repo.update_one(
                {"template_id": template_id},
                {"$pull": {"shared_with": username}},
            )
            template.shared_with.remove(username)

        logger.info(f"Unshared template {template_id} from {username}")
        return template
