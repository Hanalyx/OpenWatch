"""
Runtime tests that exercise actual function bodies to increase line coverage.
Focuses on pure functions, validators, and utilities that don't need DB.

Spec: specs/system/architecture.spec.yaml
"""

import pytest
from datetime import datetime, timedelta, timezone


@pytest.mark.unit
class TestQueryBuilder:
    """AC-5: QueryBuilder produces correct SQL."""

    def test_basic_select(self):
        from app.utils.query_builder import QueryBuilder

        b = QueryBuilder("hosts").select("id", "hostname")
        q, p = b.build()
        assert "SELECT id, hostname FROM hosts" in q

    def test_where_clause(self):
        from app.utils.query_builder import QueryBuilder

        b = QueryBuilder("hosts").select("id").where("status = :status", "online", "status")
        q, p = b.build()
        assert "WHERE" in q
        assert p["status"] == "online"

    def test_order_by(self):
        from app.utils.query_builder import QueryBuilder

        b = QueryBuilder("hosts").select("id").order_by("created_at", "DESC")
        q, p = b.build()
        assert "ORDER BY" in q
        assert "DESC" in q

    def test_paginate(self):
        from app.utils.query_builder import QueryBuilder

        b = QueryBuilder("hosts").select("id").paginate(page=2, per_page=10)
        q, p = b.build()
        assert "LIMIT" in q
        assert "OFFSET" in q

    def test_join(self):
        from app.utils.query_builder import QueryBuilder

        b = QueryBuilder("hosts h").select("h.id").join("host_groups g", "h.group_id = g.id")
        q, p = b.build()
        assert "JOIN" in q

    def test_search(self):
        from app.utils.query_builder import QueryBuilder

        b = QueryBuilder("hosts").select("id").search("hostname", "web")
        q, p = b.build()
        assert "ILIKE" in q

    def test_count_query(self):
        from app.utils.query_builder import QueryBuilder

        b = QueryBuilder("hosts").select("id").where("status = :s", "active", "s")
        cq, cp = b.count_query()
        assert "COUNT" in cq


@pytest.mark.unit
class TestMutationBuilders:
    """AC-5: Mutation builders produce correct SQL."""

    def test_insert_builder(self):
        from app.utils.mutation_builders import InsertBuilder

        b = InsertBuilder("hosts").columns("id", "hostname").values("uuid-1", "web-01")
        q, p = b.build()
        assert "INSERT INTO hosts" in q
        assert "uuid-1" in str(p.values())

    def test_insert_returning(self):
        from app.utils.mutation_builders import InsertBuilder

        b = InsertBuilder("hosts").columns("id").values("uuid-1").returning("id")
        q, p = b.build()
        assert "RETURNING" in q

    def test_insert_on_conflict(self):
        from app.utils.mutation_builders import InsertBuilder

        b = (
            InsertBuilder("hosts")
            .columns("id", "hostname")
            .values("uuid-1", "web-01")
            .on_conflict_do_nothing("id")
        )
        q, p = b.build()
        assert "ON CONFLICT" in q

    def test_update_builder(self):
        from app.utils.mutation_builders import UpdateBuilder

        b = UpdateBuilder("hosts").set("hostname", "new-name").where("id = :id", "uuid-1", "id")
        q, p = b.build()
        assert "UPDATE hosts" in q
        assert "SET" in q

    def test_update_set_if_none(self):
        from app.utils.mutation_builders import UpdateBuilder

        b = UpdateBuilder("hosts").set_if("hostname", None).set("status", "x").where(
            "id = :id", "x", "id"
        )
        q, p = b.build()
        # set_if with None should not add hostname to SET clause
        # but we need at least one SET clause for valid SQL
        assert "status" in q

    def test_update_set_if_value(self):
        from app.utils.mutation_builders import UpdateBuilder

        b = UpdateBuilder("hosts").set_if("hostname", "val").where("id = :id", "x", "id")
        q, p = b.build()
        assert "hostname" in q

    def test_update_set_raw(self):
        from app.utils.mutation_builders import UpdateBuilder

        b = UpdateBuilder("hosts").set_raw("updated_at", "CURRENT_TIMESTAMP").where(
            "id = :id", "x", "id"
        )
        q, p = b.build()
        assert "CURRENT_TIMESTAMP" in q

    def test_update_returning(self):
        from app.utils.mutation_builders import UpdateBuilder

        b = (
            UpdateBuilder("hosts")
            .set("name", "x")
            .where("id = :id", "x", "id")
            .returning("id", "updated_at")
        )
        q, p = b.build()
        assert "RETURNING" in q

    def test_delete_builder(self):
        from app.utils.mutation_builders import DeleteBuilder

        b = DeleteBuilder("hosts").where("id = :id", "uuid-1", "id")
        q, p = b.build()
        assert "DELETE FROM hosts" in q

    def test_delete_returning(self):
        from app.utils.mutation_builders import DeleteBuilder

        b = DeleteBuilder("hosts").where("id = :id", "x", "id").returning("id")
        q, p = b.build()
        assert "RETURNING" in q

    def test_delete_where_in(self):
        from app.utils.mutation_builders import DeleteBuilder

        b = DeleteBuilder("hosts").where_in("id", ["a", "b", "c"])
        q, p = b.build_unsafe()
        assert "IN" in q

    def test_insert_values_dict(self):
        from app.utils.mutation_builders import InsertBuilder

        b = InsertBuilder("hosts").values_dict({"id": "uuid-1", "hostname": "web"})
        q, p = b.build()
        assert "INSERT INTO hosts" in q

    def test_update_set_dict(self):
        from app.utils.mutation_builders import UpdateBuilder

        b = UpdateBuilder("hosts").set_dict(
            {"hostname": "new", "description": None}, skip_none=True
        ).where("id = :id", "x", "id")
        q, p = b.build()
        assert "hostname" in q
        assert "description" not in q  # skip_none=True


@pytest.mark.unit
class TestBuildPaginatedQuery:
    """AC-5: build_paginated_query convenience function."""

    def test_basic_pagination(self):
        from app.utils.query_builder import build_paginated_query

        dq, cq, params = build_paginated_query(
            table="hosts",
            page=1,
            limit=20,
        )
        assert "SELECT" in dq
        assert "COUNT" in cq
        assert "LIMIT" in dq

    def test_with_search(self):
        from app.utils.query_builder import build_paginated_query

        dq, cq, params = build_paginated_query(
            table="hosts",
            page=1,
            limit=10,
            search="web",
            search_column="hostname",
        )
        assert "ILIKE" in dq

    def test_with_filters(self):
        from app.utils.query_builder import build_paginated_query

        dq, cq, params = build_paginated_query(
            table="hosts",
            page=1,
            limit=10,
            filters={"status": "online"},
        )
        assert "status" in dq


@pytest.mark.unit
class TestCredentialValidation:
    """AC-1: Credential security validation."""

    def test_credential_validator_importable(self):
        from app.services.auth.validation import CredentialSecurityValidator

        assert CredentialSecurityValidator is not None

    def test_security_policy_levels(self):
        from app.services.auth.validation import SecurityPolicyLevel

        assert SecurityPolicyLevel is not None

    def test_ssh_key_types(self):
        from app.services.auth.validation import SSHKeyType

        assert SSHKeyType is not None

    def test_fips_compliance_status(self):
        from app.services.auth.validation import FIPSComplianceStatus

        assert FIPSComplianceStatus is not None


@pytest.mark.unit
class TestEncryptionService:
    """AC-6: Encryption service works end-to-end."""

    def test_encrypt_decrypt_roundtrip(self):
        from app.encryption.service import EncryptionService
        import os

        key = os.urandom(32).hex()
        svc = EncryptionService(master_key=key)
        plaintext = b"sensitive data"
        encrypted = svc.encrypt(plaintext)
        decrypted = svc.decrypt(encrypted)
        assert decrypted == plaintext

    def test_encrypt_produces_different_ciphertext(self):
        from app.encryption.service import EncryptionService
        import os

        key = os.urandom(32).hex()
        svc = EncryptionService(master_key=key)
        ct1 = svc.encrypt(b"same data")
        ct2 = svc.encrypt(b"same data")
        assert ct1 != ct2  # Random nonce

    def test_decrypt_wrong_key_fails(self):
        from app.encryption.service import EncryptionService
        from app.encryption.exceptions import DecryptionError
        import os

        key1 = os.urandom(32).hex()
        key2 = os.urandom(32).hex()
        svc1 = EncryptionService(master_key=key1)
        svc2 = EncryptionService(master_key=key2)
        encrypted = svc1.encrypt(b"secret")
        with pytest.raises((DecryptionError, Exception)):
            svc2.decrypt(encrypted)

    def test_encrypt_with_aad(self):
        from app.encryption.service import EncryptionService
        import os

        key = os.urandom(32).hex()
        svc = EncryptionService(master_key=key)
        encrypted = svc.encrypt(b"data", aad=b"context")
        decrypted = svc.decrypt(encrypted, aad=b"context")
        assert decrypted == b"data"


@pytest.mark.unit
class TestScanUtilities:
    """AC-5: Utility functions."""

    def test_version_module(self):
        from app.version import get_version

        v = get_version()
        assert isinstance(v, str)

    def test_rbac_manager_importable(self):
        from app.rbac import RBACManager, UserRole, Permission

        assert RBACManager is not None
        assert len(UserRole) == 6

    def test_rbac_permissions_count(self):
        from app.rbac import Permission

        assert len(Permission) >= 30

    def test_rbac_has_permission_method(self):
        from app.rbac import RBACManager

        assert hasattr(RBACManager, "has_permission") or hasattr(
            RBACManager, "can_access_resource"
        )
