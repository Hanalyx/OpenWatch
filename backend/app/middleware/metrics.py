"""
Prometheus Metrics Middleware for OpenWatch
Automatic metrics collection for HTTP requests and application events
Author: Noah Chen - nc9010@hanalyx.com
"""

import logging
import time
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from ..services.prometheus_metrics import get_metrics_instance

logger = logging.getLogger(__name__)


class PrometheusMiddleware(BaseHTTPMiddleware):
    """
    Middleware to automatically collect Prometheus metrics for HTTP requests
    """

    def __init__(self, app, service_name: str = "openwatch"):
        super().__init__(app)
        self.service_name = service_name
        self.metrics = get_metrics_instance()

        # Set service as up
        self.metrics.set_service_up(service_name, True)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and collect metrics"""
        start_time = time.time()

        # Extract path and method
        path = request.url.path
        method = request.method

        # Normalize endpoint for metrics (remove dynamic parts)
        endpoint = self._normalize_endpoint(path)

        try:
            # Process request
            response = await call_next(request)

            # Calculate duration
            duration = time.time() - start_time

            # Record metrics
            self.metrics.record_http_request(
                method=method,
                endpoint=endpoint,
                status_code=response.status_code,
                duration=duration,
                service=self.service_name,
            )

            # Record specific application events
            self._record_application_metrics(request, response, duration)

            return response

        except Exception as e:
            # Record error metrics
            duration = time.time() - start_time
            self.metrics.record_http_request(
                method=method,
                endpoint=endpoint,
                status_code=500,
                duration=duration,
                service=self.service_name,
            )

            # Record security event for unhandled exceptions
            self.metrics.record_security_event("HTTP_EXCEPTION", "high")

            # Re-raise the exception
            raise e

    def _normalize_endpoint(self, path: str) -> str:
        """
        Normalize endpoint path for metrics collection
        Replace dynamic segments with placeholders
        """
        # Common patterns to normalize
        normalizations = [
            # UUIDs and IDs
            (r"/[a-f0-9-]{36}", "/{uuid}"),
            (r"/\d+", "/{id}"),
            # Remove query parameters
            (r"\?.*", ""),
        ]

        normalized_path = path
        import re

        for pattern, replacement in normalizations:
            normalized_path = re.sub(pattern, replacement, normalized_path)

        # Limit path length and complexity
        if len(normalized_path) > 100:
            normalized_path = normalized_path[:97] + "..."

        return normalized_path

    def _record_application_metrics(self, request: Request, response: Response, duration: float):
        """Record application-specific metrics based on request/response"""
        path = request.url.path

        try:
            # Authentication metrics
            if path.startswith("/api/auth"):
                if response.status_code == 200:
                    self.metrics.record_authentication_attempt("success")
                elif response.status_code in [401, 403]:
                    self.metrics.record_authentication_attempt("failure")
                    self.metrics.record_security_event("AUTH_FAILURE", "medium")

            # Scan operation metrics
            elif path.startswith("/api/scans"):
                if request.method == "POST" and response.status_code == 201:
                    # Scan initiated
                    pass  # Detailed metrics will be recorded by scan service
                elif request.method == "GET" and "results" in path:
                    # Scan results accessed
                    pass

            # Host management metrics
            elif path.startswith("/api/hosts"):
                if request.method == "POST" and response.status_code == 201:
                    # New host added
                    pass
                elif request.method == "DELETE" and response.status_code == 200:
                    # Host removed
                    pass

            # Integration metrics
            elif path.startswith("/api/webhooks") or "integration" in path:
                self.metrics.record_integration_call(
                    target="webhook",
                    endpoint=path,
                    status="success" if response.status_code < 400 else "error",
                    duration=duration,
                )

            # Security events for suspicious activity
            if response.status_code == 401:
                self.metrics.record_security_event("UNAUTHORIZED_ACCESS", "medium")
            elif response.status_code == 403:
                self.metrics.record_security_event("FORBIDDEN_ACCESS", "medium")
            elif response.status_code == 429:
                self.metrics.record_security_event("RATE_LIMIT_EXCEEDED", "low")
            elif response.status_code >= 500:
                self.metrics.record_security_event("SERVER_ERROR", "high")

        except Exception as e:
            logger.error(f"Error recording application metrics: {e}")


class DatabaseMetricsCollector:
    """Collector for database-related metrics"""

    def __init__(self):
        self.metrics = get_metrics_instance()

    def record_query_metrics(self, operation: str, duration: float):
        """Record database query metrics"""
        from ..services.prometheus_metrics import database_query_duration_seconds

        database_query_duration_seconds.labels(operation=operation).observe(duration)

    async def update_connection_metrics(self, db):
        """Update database connection metrics"""
        await self.metrics.update_database_metrics(db)


class BackgroundMetricsUpdater:
    """Background task to update system and application metrics"""

    def __init__(self):
        self.metrics = get_metrics_instance()
        self.is_running = False

    async def start_background_updates(self):
        """Start background metrics collection"""
        if self.is_running:
            return

        self.is_running = True
        import asyncio

        while self.is_running:
            try:
                # Update system metrics
                self.metrics.update_system_metrics()

                # Update application-specific metrics
                await self._update_application_metrics()

                # Wait 30 seconds before next update
                await asyncio.sleep(30)

            except Exception as e:
                logger.error(f"Error in background metrics update: {e}")
                await asyncio.sleep(60)  # Wait longer on error

    async def _update_application_metrics(self):
        """Update application-specific metrics"""
        try:
            from sqlalchemy import text

            from ..database import get_db

            db = next(get_db())

            try:
                # Update host counts
                result = db.execute(text("""
                    SELECT status, COUNT(*) as count
                    FROM hosts
                    WHERE is_active = true
                    GROUP BY status
                """))

                status_counts = {}
                for row in result:
                    status_counts[row.status] = row.count

                self.metrics.update_host_counts(status_counts)

                # Update active scans count
                result = db.execute(text("""
                    SELECT COUNT(*) as active_scans
                    FROM scans
                    WHERE status IN ('running', 'pending')
                """))

                row = result.fetchone()
                if row:
                    self.metrics.set_active_scans(row.active_scans)

                # Update database metrics
                await self.metrics.update_database_metrics(db)

            finally:
                db.close()

        except Exception as e:
            logger.error(f"Error updating application metrics: {e}")

    def stop_background_updates(self) -> None:
        """Stop background metrics collection."""
        self.is_running = False


# Global instances
db_metrics = DatabaseMetricsCollector()
background_updater = BackgroundMetricsUpdater()
