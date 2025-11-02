"""
OpenTelemetry Distributed Tracing Configuration for OpenWatch
Comprehensive tracing for request flows and service integration
Author: Noah Chen - nc9010@hanalyx.com
"""

import os
import logging
from typing import Optional
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

logger = logging.getLogger(__name__)


class TracingConfig:
    """OpenTelemetry tracing configuration and setup"""

    def __init__(
        self,
        service_name: str = "openwatch",
        service_version: str = "1.0.0",
        environment: str = "production",
        jaeger_endpoint: Optional[str] = None,
        otlp_endpoint: Optional[str] = None,
    ):
        self.service_name = service_name
        self.service_version = service_version
        self.environment = environment
        self.jaeger_endpoint = jaeger_endpoint or os.getenv(
            "JAEGER_ENDPOINT", "http://secureops-jaeger:14268/api/traces"
        )
        self.otlp_endpoint = otlp_endpoint or os.getenv(
            "OTLP_ENDPOINT", "http://secureops-jaeger:14250"
        )

        self.tracer_provider = None
        self.tracer = None

    def initialize_tracing(self):
        """Initialize OpenTelemetry tracing"""
        try:
            # Create resource with service information
            resource = Resource.create(
                {
                    "service.name": self.service_name,
                    "service.version": self.service_version,
                    "service.environment": self.environment,
                    "service.instance.id": os.getenv("HOSTNAME", "unknown"),
                }
            )

            # Create tracer provider
            self.tracer_provider = TracerProvider(resource=resource)
            trace.set_tracer_provider(self.tracer_provider)

            # Configure exporters
            self._setup_exporters()

            # Get tracer
            self.tracer = trace.get_tracer(__name__)

            # Instrument libraries
            self._instrument_libraries()

            logger.info(f"OpenTelemetry tracing initialized for {self.service_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize tracing: {e}")
            return False

    def _setup_exporters(self):
        """Setup trace exporters (Jaeger, OTLP, Console)"""
        exporters = []

        # Jaeger exporter
        try:
            jaeger_exporter = JaegerExporter(
                agent_host_name="secureops-jaeger",
                agent_port=6831,
                collector_endpoint=self.jaeger_endpoint,
            )
            exporters.append(jaeger_exporter)
            logger.info("Jaeger exporter configured")
        except Exception as e:
            logger.warning(f"Failed to configure Jaeger exporter: {e}")

        # OTLP exporter
        try:
            otlp_exporter = OTLPSpanExporter(
                endpoint=self.otlp_endpoint, insecure=True  # Use TLS in production
            )
            exporters.append(otlp_exporter)
            logger.info("OTLP exporter configured")
        except Exception as e:
            logger.warning(f"Failed to configure OTLP exporter: {e}")

        # Console exporter for development
        if os.getenv("OPENWATCH_DEBUG", "false").lower() == "true":
            console_exporter = ConsoleSpanExporter()
            exporters.append(console_exporter)
            logger.info("Console exporter configured for development")

        # Add exporters to tracer provider
        for exporter in exporters:
            span_processor = BatchSpanProcessor(exporter)
            self.tracer_provider.add_span_processor(span_processor)

    def _instrument_libraries(self):
        """Instrument common libraries for automatic tracing"""
        try:
            # Instrument HTTP requests
            RequestsInstrumentor().instrument()
            HTTPXClientInstrumentor().instrument()

            # Instrument Redis (if available)
            try:
                RedisInstrumentor().instrument()
                logger.info("Redis instrumentation enabled")
            except Exception as e:
                logger.warning(f"Redis instrumentation failed: {e}")

            logger.info("Library instrumentation completed")

        except Exception as e:
            logger.error(f"Library instrumentation failed: {e}")

    def instrument_fastapi(self, app):
        """Instrument FastAPI application"""
        try:
            FastAPIInstrumentor.instrument_app(
                app,
                tracer_provider=self.tracer_provider,
                excluded_urls="/health,/metrics",  # Exclude health checks from tracing
            )
            logger.info("FastAPI instrumentation enabled")
        except Exception as e:
            logger.error(f"FastAPI instrumentation failed: {e}")

    def instrument_sqlalchemy(self, engine):
        """Instrument SQLAlchemy for database tracing"""
        try:
            SQLAlchemyInstrumentor().instrument(
                engine=engine, tracer_provider=self.tracer_provider
            )
            logger.info("SQLAlchemy instrumentation enabled")
        except Exception as e:
            logger.error(f"SQLAlchemy instrumentation failed: {e}")

    def get_tracer(self):
        """Get the configured tracer"""
        return self.tracer


class SecureOpsTracer:
    """Custom tracer for SecureOps-specific operations"""

    def __init__(self, tracer):
        self.tracer = tracer

    def trace_scan_operation(self, scan_id: str, host_id: str, profile: str):
        """Create span for SCAP scan operation"""
        return self.tracer.start_span(
            "scap_scan",
            attributes={
                "scan.id": scan_id,
                "scan.host_id": host_id,
                "scan.profile": profile,
                "operation.type": "scap_scan",
            },
        )

    def trace_remediation_call(self, host_id: str, rule_count: int):
        """Create span for AEGIS remediation call"""
        return self.tracer.start_span(
            "aegis_remediation",
            attributes={
                "remediation.host_id": host_id,
                "remediation.rule_count": rule_count,
                "operation.type": "remediation",
            },
        )

    def trace_integration_call(self, target_service: str, endpoint: str):
        """Create span for external service integration"""
        return self.tracer.start_span(
            f"integration_call_{target_service}",
            attributes={
                "integration.target": target_service,
                "integration.endpoint": endpoint,
                "operation.type": "integration",
            },
        )

    def trace_database_operation(self, operation: str, table: str):
        """Create span for database operations"""
        return self.tracer.start_span(
            f"db_{operation}",
            attributes={
                "db.operation": operation,
                "db.table": table,
                "operation.type": "database",
            },
        )

    def trace_authentication(self, username: str, method: str):
        """Create span for authentication operations"""
        return self.tracer.start_span(
            "authentication",
            attributes={
                "auth.username": username,
                "auth.method": method,
                "operation.type": "authentication",
            },
        )

    def trace_workflow(self, workflow_type: str, workflow_id: str):
        """Create span for end-to-end workflows"""
        return self.tracer.start_span(
            f"workflow_{workflow_type}",
            attributes={
                "workflow.type": workflow_type,
                "workflow.id": workflow_id,
                "operation.type": "workflow",
            },
        )

    def add_scan_result_attributes(self, span, scan_result):
        """Add scan result attributes to span"""
        if span and scan_result:
            span.set_attributes(
                {
                    "scan.rules_total": scan_result.get("rules_total", 0),
                    "scan.rules_passed": scan_result.get("rules_passed", 0),
                    "scan.rules_failed": scan_result.get("rules_failed", 0),
                    "scan.compliance_score": scan_result.get("compliance_score", 0),
                    "scan.duration_seconds": scan_result.get("duration", 0),
                }
            )

    def add_error_attributes(self, span, error: Exception):
        """Add error attributes to span"""
        if span and error:
            span.set_status(trace.Status(trace.StatusCode.ERROR))
            span.record_exception(error)
            span.set_attributes(
                {"error.type": type(error).__name__, "error.message": str(error)}
            )


# Global tracing configuration
_tracing_config: Optional[TracingConfig] = None
_secureops_tracer: Optional[SecureOpsTracer] = None


def initialize_tracing(
    service_name: str = "openwatch",
    service_version: str = "1.0.0",
    environment: str = "production",
) -> bool:
    """Initialize global tracing configuration"""
    global _tracing_config, _secureops_tracer

    _tracing_config = TracingConfig(
        service_name=service_name,
        service_version=service_version,
        environment=environment,
    )

    success = _tracing_config.initialize_tracing()

    if success:
        _secureops_tracer = SecureOpsTracer(_tracing_config.get_tracer())

    return success


def get_tracing_config() -> Optional[TracingConfig]:
    """Get global tracing configuration"""
    return _tracing_config


def get_secureops_tracer() -> Optional[SecureOpsTracer]:
    """Get SecureOps-specific tracer"""
    return _secureops_tracer


def instrument_fastapi_app(app):
    """Instrument FastAPI application with tracing"""
    if _tracing_config:
        _tracing_config.instrument_fastapi(app)


def instrument_database_engine(engine):
    """Instrument database engine with tracing"""
    if _tracing_config:
        _tracing_config.instrument_sqlalchemy(engine)
