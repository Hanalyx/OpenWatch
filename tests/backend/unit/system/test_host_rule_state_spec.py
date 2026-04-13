"""
Source-inspection tests for host rule state (write-on-change model).

Spec: specs/system/host-rule-state.spec.yaml
Status: draft (Q1 — promotion to active scheduled after implementation)

Tests are skip-marked until the corresponding Q1 implementation lands.
Each PR in the host-rule-state workstream removes skip markers from the
tests it makes passing. Once all tests pass, the spec promotes to active.
"""

import pytest

SKIP_REASON = "Q1: host-rule-state implementation in progress"


@pytest.mark.unit
class TestAC1HostRuleStateTable:
    """AC-1: host_rule_state table exists with composite PK and required columns."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_migration_exists(self):
        """Migration file for host_rule_state table exists."""
        from pathlib import Path

        migration = Path(
            "backend/alembic/versions/20260412_0400_048_add_host_rule_state.py"
        )
        assert migration.exists(), f"Migration file not found: {migration}"

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_composite_primary_key(self):
        """host_rule_state uses composite PK (host_id, rule_id), not a UUID PK."""
        from pathlib import Path

        migration = Path(
            "backend/alembic/versions/20260412_0400_048_add_host_rule_state.py"
        )
        content = migration.read_text()
        assert "host_rule_state" in content
        assert "PrimaryKeyConstraint" in content or "primary_key=True" in content

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_required_columns(self):
        """Migration includes all required columns per spec."""
        from pathlib import Path

        migration = Path(
            "backend/alembic/versions/20260412_0400_048_add_host_rule_state.py"
        )
        content = migration.read_text()
        required_columns = [
            "current_status",
            "severity",
            "evidence_envelope",
            "framework_refs",
            "first_seen_at",
            "last_checked_at",
            "last_changed_at",
            "check_count",
            "previous_status",
        ]
        for col in required_columns:
            assert col in content, f"Required column '{col}' not found in migration"


@pytest.mark.unit
class TestAC2FirstSeenInsert:
    """AC-2: First-seen rule creates state row AND transaction row."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_state_writer_inserts_state_row(self):
        """state_writer inserts into host_rule_state on first seen."""
        import inspect

        import app.services.compliance.state_writer as mod

        source = inspect.getsource(mod)
        assert "host_rule_state" in source
        assert "INSERT" in source.upper() or "InsertBuilder" in source

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_state_writer_creates_transaction_on_first_seen(self):
        """state_writer writes a transaction row when rule is first seen."""
        import inspect

        import app.services.compliance.state_writer as mod

        source = inspect.getsource(mod)
        assert "transactions" in source.lower() or 'InsertBuilder("transactions")' in source


@pytest.mark.unit
class TestAC3UnchangedStatusNoTransaction:
    """AC-3: Unchanged status updates state row only, no transaction written."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_state_writer_updates_without_transaction(self):
        """state_writer updates last_checked_at and check_count without transaction insert."""
        import inspect

        import app.services.compliance.state_writer as mod

        source = inspect.getsource(mod)
        # Must handle the unchanged case: update state but skip transaction
        assert "last_checked_at" in source
        assert "check_count" in source


@pytest.mark.unit
class TestAC4StatusChangeTransaction:
    """AC-4: Status change updates state row AND writes transaction."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_state_writer_records_previous_status(self):
        """state_writer sets previous_status on state change."""
        import inspect

        import app.services.compliance.state_writer as mod

        source = inspect.getsource(mod)
        assert "previous_status" in source

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_state_writer_updates_last_changed_at(self):
        """state_writer updates last_changed_at on state change."""
        import inspect

        import app.services.compliance.state_writer as mod

        source = inspect.getsource(mod)
        assert "last_changed_at" in source

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_state_writer_writes_change_transaction(self):
        """state_writer inserts transaction row on status change."""
        import inspect

        import app.services.compliance.state_writer as mod

        source = inspect.getsource(mod)
        assert "transactions" in source.lower() or 'InsertBuilder("transactions")' in source


@pytest.mark.unit
class TestAC5CheckCountAlwaysIncrements:
    """AC-5: check_count increments on every scan regardless of status change."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_state_writer_increments_check_count(self):
        """state_writer increments check_count in UPDATE path."""
        import inspect

        import app.services.compliance.state_writer as mod

        source = inspect.getsource(mod)
        assert "check_count" in source
        assert "+ 1" in source or "+1" in source or "check_count + 1" in source


@pytest.mark.unit
class TestAC6EvidenceAlwaysUpdated:
    """AC-6: evidence_envelope always updated, even when status unchanged."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_state_writer_updates_evidence_on_unchanged(self):
        """state_writer updates evidence_envelope in the unchanged-status path."""
        import inspect

        import app.services.compliance.state_writer as mod

        source = inspect.getsource(mod)
        assert "evidence_envelope" in source


@pytest.mark.unit
class TestAC7PostureFromStateTable:
    """AC-7: Current posture queryable from host_rule_state alone."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_posture_reads_host_rule_state(self):
        """Posture query reads from host_rule_state, not scan aggregation."""
        pass  # read-path AC — implemented when posture query is refactored


@pytest.mark.unit
class TestAC8ScaleCharacteristics:
    """AC-8: host_rule_state rows fixed at N*R; transactions proportional to changes."""

    @pytest.mark.skip(reason=SKIP_REASON)
    @pytest.mark.slow
    def test_row_count_proportional_to_hosts(self):
        """At scale, host_rule_state rows are O(hosts * rules), not O(scans * rules)."""
        pass  # scale/benchmark AC — integration suite
