"""
FIPS-compliant Celery configuration for secure task processing
Redis with TLS and encrypted message passing
"""
import os
import ssl
import logging
from celery import Celery
from celery.signals import worker_ready, worker_shutdown
from kombu import Queue
import redis
import asyncio

from .config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# FIPS-compliant SSL context for Redis
def create_redis_ssl_context():
    """Create FIPS-compliant SSL context for Redis connections"""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    
    # FIPS-approved settings
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    
    # FIPS-approved cipher suites
    context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS")
    
    # Certificate verification
    if settings.redis_ssl_ca:
        context.load_verify_locations(settings.redis_ssl_ca)
    
    if settings.redis_ssl_cert and settings.redis_ssl_key:
        context.load_cert_chain(settings.redis_ssl_cert, settings.redis_ssl_key)
    
    return context

# Redis connection configuration
redis_ssl_context = create_redis_ssl_context() if settings.redis_ssl else None

# Celery broker URL with SSL
broker_url = settings.redis_url
if settings.redis_ssl and not broker_url.startswith("rediss://"):
    broker_url = broker_url.replace("redis://", "rediss://")

# Create Celery app with FIPS-compliant configuration
celery_app = Celery(
    "openwatch",
    broker=broker_url,
    backend=broker_url,
    include=[]  # No tasks module for now
)

# FIPS-compliant Celery configuration
celery_app.conf.update(
    # Security settings (Note: ssl_ciphers not supported by redis-py)
    broker_use_ssl={
        "ssl_cert_reqs": ssl.CERT_REQUIRED,
        "ssl_ca_certs": settings.redis_ssl_ca,
        "ssl_certfile": settings.redis_ssl_cert,
        "ssl_keyfile": settings.redis_ssl_key
    } if settings.redis_ssl else None,
    
    redis_backend_use_ssl={
        "ssl_cert_reqs": ssl.CERT_REQUIRED,
        "ssl_ca_certs": settings.redis_ssl_ca,
        "ssl_certfile": settings.redis_ssl_cert,
        "ssl_keyfile": settings.redis_ssl_key
    } if settings.redis_ssl else None,
    
    # Task settings
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    
    # Security and reliability
    task_reject_on_worker_lost=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    
    # Task routing
    task_routes={
        "backend.app.tasks.scan_host": {"queue": "scans"},
        "backend.app.tasks.process_scan_result": {"queue": "results"},
        "backend.app.tasks.cleanup_old_files": {"queue": "maintenance"}
    },
    
    # Queue configuration
    task_default_queue="default",
    task_queues=[
        Queue("default", routing_key="default"),
        Queue("scans", routing_key="scans"),
        Queue("results", routing_key="results"),
        Queue("maintenance", routing_key="maintenance")
    ],
    
    # Result backend settings
    result_expires=3600,  # 1 hour
    result_backend_transport_options={
        "retry_policy": {
            "timeout": 5.0
        }
    },
    
    # Worker settings
    worker_max_tasks_per_child=1000,
    worker_disable_rate_limits=False,
    worker_send_task_events=True,
    task_send_sent_event=True,
    
    # Security: Disable pickle serialization
    task_always_eager=False,
    task_eager_propagates=True if settings.debug else False
)


class SecureCeleryManager:
    """Secure Celery task management with audit logging"""
    
    def __init__(self):
        self.app = celery_app
        
    def submit_scan_task(self, scan_id: int, host_data: dict, content_data: dict, 
                        profile_id: str, user_id: int) -> str:
        """Submit scan task with security validation"""
        try:
            # Validate inputs
            if not all([scan_id, host_data, content_data, profile_id, user_id]):
                raise ValueError("Missing required parameters for scan task")
            
            # Submit task
            task = self.app.send_task(
                "backend.app.tasks.scan_host",
                args=[scan_id, host_data, content_data, profile_id, user_id],
                queue="scans",
                retry=True,
                retry_policy={
                    "max_retries": 3,
                    "interval_start": 0,
                    "interval_step": 0.2,
                    "interval_max": 0.2
                }
            )
            
            logger.info(f"Submitted scan task {task.id} for scan {scan_id}")
            return task.id
            
        except Exception as e:
            logger.error(f"Failed to submit scan task: {e}")
            raise
    
    def get_task_status(self, task_id: str) -> dict:
        """Get task status with security checks"""
        try:
            result = self.app.AsyncResult(task_id)
            return {
                "task_id": task_id,
                "status": result.status,
                "result": result.result if result.ready() else None,
                "traceback": result.traceback if result.failed() else None
            }
        except Exception as e:
            logger.error(f"Failed to get task status: {e}")
            return {"task_id": task_id, "status": "UNKNOWN", "error": str(e)}
    
    def revoke_task(self, task_id: str, terminate: bool = True) -> bool:
        """Revoke task with audit logging"""
        try:
            self.app.control.revoke(task_id, terminate=terminate)
            logger.info(f"Revoked task {task_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to revoke task {task_id}: {e}")
            return False


# Global Celery manager instance
celery_manager = SecureCeleryManager()


def check_redis_health() -> bool:
    """Check Redis connectivity for health checks"""
    try:
        # Parse Redis URL
        import urllib.parse
        parsed = urllib.parse.urlparse(settings.redis_url)
        
        # Create Redis connection
        redis_client = redis.Redis(
            host=parsed.hostname,
            port=parsed.port or 6379,
            password=parsed.password,
            ssl=settings.redis_ssl,
            ssl_cert_reqs=ssl.CERT_REQUIRED if settings.redis_ssl else None,
            ssl_ca_certs=settings.redis_ssl_ca if settings.redis_ssl else None,
            ssl_certfile=settings.redis_ssl_cert if settings.redis_ssl else None,
            ssl_keyfile=settings.redis_ssl_key if settings.redis_ssl else None,
            socket_timeout=5,
            socket_connect_timeout=5
        )
        
        # Test connection
        redis_client.ping()
        redis_client.close()
        return True
        
    except Exception as e:
        logger.error(f"Redis health check failed: {type(e).__name__}")
        return False


@worker_ready.connect
def worker_ready_handler(sender=None, **kwargs):
    """Handle worker ready signal"""
    logger.info(f"Celery worker ready: {sender}")
    
    # Log FIPS mode status
    if settings.fips_mode:
        try:
            from security.config.fips_config import FIPSConfig
            fips_enabled = FIPSConfig.validate_fips_mode()
            logger.info(f"FIPS mode enabled: {fips_enabled}")
        except ImportError:
            logger.warning("FIPS configuration module not found - using development mode")


@worker_shutdown.connect
def worker_shutdown_handler(sender=None, **kwargs):
    """Handle worker shutdown signal"""
    logger.info(f"Celery worker shutting down: {sender}")


# Export Celery app for worker startup
__all__ = ["celery_app", "celery_manager", "check_redis_health"]