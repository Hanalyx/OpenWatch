"""
Transactions API Package

Provides REST endpoints for querying the transactions table, which stores
compliance check results in a four-phase transaction model.

Endpoints:
    GET  /api/transactions                     - List transactions (paginated, filtered)
    GET  /api/transactions/{transaction_id}    - Get transaction detail
    GET  /api/hosts/{host_id}/transactions     - Per-host transaction timeline
    POST /api/transactions/query               - Structured query DSL (Q3 §6.1)

Usage:
    from app.routes.transactions import router, host_transactions_router, query_router
    app.include_router(router)
    app.include_router(host_transactions_router)
    app.include_router(query_router)
"""

from app.routes.transactions.crud import host_transactions_router, router  # noqa: E402
from app.routes.transactions.query import query_router  # noqa: E402

__all__ = ["router", "host_transactions_router", "query_router"]
