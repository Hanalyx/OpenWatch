"""Rename aegis tables, columns, and indexes to kensa

Revision ID: 036_rename_aegis_to_kensa
Revises: 035_merge_alerts
Create Date: 2026-02-23

This migration renames all database objects from "aegis" to "kensa" as part
of the Aegis -> Kensa rebranding:

Tables:
  - aegis_rules -> kensa_rules

Columns:
  - kensa_rules.aegis_version -> kensa_version
  - framework_mappings.aegis_rule_id -> kensa_rule_id

Indexes:
  - idx_aegis_rules_* -> idx_kensa_rules_*
  - idx_framework_mappings_aegis_rule_id -> idx_framework_mappings_kensa_rule_id

Data:
  - plugin_updates.plugin_id 'aegis' -> 'kensa'
  - plugin_update_notifications.plugin_id 'aegis' -> 'kensa'
  - plugin_registry: plugin_id 'aegis' -> 'kensa', name updated
"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic
revision = "036_rename_aegis_to_kensa"
down_revision = "035_merge_alerts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Rename aegis -> kensa in tables, columns, indexes, and data."""
    conn = op.get_bind()

    # --- Tables ---
    conn.execute(sa.text("ALTER TABLE aegis_rules RENAME TO kensa_rules"))

    # --- Columns ---
    conn.execute(sa.text("ALTER TABLE kensa_rules RENAME COLUMN aegis_version TO kensa_version"))
    conn.execute(sa.text("ALTER TABLE framework_mappings RENAME COLUMN aegis_rule_id TO kensa_rule_id"))

    # --- Indexes on kensa_rules (formerly aegis_rules) ---
    conn.execute(sa.text("ALTER INDEX IF EXISTS idx_aegis_rules_rule_id " "RENAME TO idx_kensa_rules_rule_id"))
    conn.execute(sa.text("ALTER INDEX IF EXISTS idx_aegis_rules_severity " "RENAME TO idx_kensa_rules_severity"))
    conn.execute(sa.text("ALTER INDEX IF EXISTS idx_aegis_rules_category " "RENAME TO idx_kensa_rules_category"))
    conn.execute(sa.text("ALTER INDEX IF EXISTS idx_aegis_rules_tags " "RENAME TO idx_kensa_rules_tags"))
    conn.execute(sa.text("ALTER INDEX IF EXISTS idx_aegis_rules_references " "RENAME TO idx_kensa_rules_references"))

    # --- Indexes on framework_mappings ---
    conn.execute(
        sa.text(
            "ALTER INDEX IF EXISTS idx_framework_mappings_aegis_rule_id "
            "RENAME TO idx_framework_mappings_kensa_rule_id"
        )
    )

    # --- Data: update plugin_updates ---
    conn.execute(sa.text("UPDATE plugin_updates SET plugin_id = 'kensa' WHERE plugin_id = 'aegis'"))

    # --- Data: update plugin_update_notifications ---
    conn.execute(sa.text("UPDATE plugin_update_notifications " "SET plugin_id = 'kensa' WHERE plugin_id = 'aegis'"))

    # --- Data: update plugin_registry ---
    conn.execute(
        sa.text(
            "UPDATE plugin_registry "
            "SET plugin_id = 'kensa', name = 'Kensa Compliance Engine' "
            "WHERE plugin_id = 'aegis'"
        )
    )


def downgrade() -> None:
    """Revert kensa -> aegis in tables, columns, indexes, and data."""
    conn = op.get_bind()

    # --- Data: revert plugin_registry ---
    conn.execute(
        sa.text(
            "UPDATE plugin_registry "
            "SET plugin_id = 'aegis', name = 'Aegis Compliance Engine' "
            "WHERE plugin_id = 'kensa'"
        )
    )

    # --- Data: revert plugin_update_notifications ---
    conn.execute(sa.text("UPDATE plugin_update_notifications " "SET plugin_id = 'aegis' WHERE plugin_id = 'kensa'"))

    # --- Data: revert plugin_updates ---
    conn.execute(sa.text("UPDATE plugin_updates SET plugin_id = 'aegis' WHERE plugin_id = 'kensa'"))

    # --- Indexes on framework_mappings ---
    conn.execute(
        sa.text(
            "ALTER INDEX IF EXISTS idx_framework_mappings_kensa_rule_id "
            "RENAME TO idx_framework_mappings_aegis_rule_id"
        )
    )

    # --- Indexes on kensa_rules -> aegis_rules ---
    conn.execute(sa.text("ALTER INDEX IF EXISTS idx_kensa_rules_references " "RENAME TO idx_aegis_rules_references"))
    conn.execute(sa.text("ALTER INDEX IF EXISTS idx_kensa_rules_tags " "RENAME TO idx_aegis_rules_tags"))
    conn.execute(sa.text("ALTER INDEX IF EXISTS idx_kensa_rules_category " "RENAME TO idx_aegis_rules_category"))
    conn.execute(sa.text("ALTER INDEX IF EXISTS idx_kensa_rules_severity " "RENAME TO idx_aegis_rules_severity"))
    conn.execute(sa.text("ALTER INDEX IF EXISTS idx_kensa_rules_rule_id " "RENAME TO idx_aegis_rules_rule_id"))

    # --- Columns ---
    conn.execute(sa.text("ALTER TABLE framework_mappings RENAME COLUMN kensa_rule_id TO aegis_rule_id"))
    conn.execute(sa.text("ALTER TABLE kensa_rules RENAME COLUMN kensa_version TO aegis_version"))

    # --- Tables ---
    conn.execute(sa.text("ALTER TABLE kensa_rules RENAME TO aegis_rules"))
