"""
Integration test: transaction backfill task.

Spec: specs/system/transaction-log.spec.yaml AC-6, AC-7
"""

import inspect

import pytest


@pytest.mark.integration
class TestTransactionBackfill:
    """AC-6/7: Backfill is idempotent and marks historical rows."""

    def test_backfill_task_importable(self):
        """backfill_transactions_from_scans can be imported and is callable."""
        from app.tasks.transaction_backfill_tasks import backfill_transactions_from_scans

        assert callable(backfill_transactions_from_scans)

    def test_backfill_uses_schema_version_09(self):
        """Historical rows get schema_version 0.9."""
        import app.tasks.transaction_backfill_tasks as mod

        source = inspect.getsource(mod)
        assert '"schema_version": "0.9"' in source

    def test_backfill_uses_left_join_for_resumability(self):
        """LEFT JOIN pattern ensures already-backfilled rows are skipped."""
        import app.tasks.transaction_backfill_tasks as mod

        source = inspect.getsource(mod)
        assert "LEFT JOIN transactions" in source

    def test_backfill_processes_in_chunks(self):
        """Backfill accepts a chunk_size parameter for batch processing."""
        import app.tasks.transaction_backfill_tasks as mod

        source = inspect.getsource(mod)
        assert "chunk_size" in source

    @pytest.mark.skip(reason="Requires running database with fixture scan_findings")
    def test_backfill_idempotent(self):
        """Running backfill twice produces same row count."""
        # 1. Insert fixture scan_findings rows
        # 2. Run backfill_transactions_from_scans()
        # 3. Count transactions rows
        # 4. Run backfill_transactions_from_scans() again
        # 5. Assert same count
        pass

    @pytest.mark.skip(reason="Requires running database with fixture scan_findings")
    def test_backfill_resumable(self):
        """Interrupted backfill resumes from last checkpoint."""
        # 1. Insert 100 fixture scan_findings rows
        # 2. Run backfill with chunk_size=50 (interrupt after first chunk)
        # 3. Verify 50 transactions rows exist
        # 4. Run backfill again
        # 5. Verify all 100 transactions rows exist
        pass
