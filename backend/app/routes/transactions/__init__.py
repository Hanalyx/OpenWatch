"""
Transactions API Package

Provides REST endpoints for querying the transactions table, which stores
compliance check results in a four-phase transaction model.

Endpoints:
    GET  /api/transactions                     - List transactions (paginated, filtered)
    GET  /api/transactions/{transaction_id}    - Get transaction detail
    GET  /api/hosts/{host_id}/transactions     - Per-host transaction timeline

Usage:
    from app.routes.transactions import router, host_transactions_router
    app.include_router(router)
    app.include_router(host_transactions_router)
"""

from app.routes.transactions.crud import host_transactions_router, router  # noqa: E402

__all__ = ["router", "host_transactions_router"]
