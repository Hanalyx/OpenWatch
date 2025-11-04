"""
HTTP Client Infrastructure with Retry Logic
Centralized HTTP client for OpenWatch with exponential backoff, circuit breaker, and monitoring
"""

import asyncio
import logging
import time
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Union

import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class CircuitBreakerState(str, Enum):
    """Circuit breaker states"""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered


class RetryPolicy(BaseModel):
    """Retry policy configuration"""

    max_retries: int = 3
    base_delay: float = 1.0  # seconds
    max_delay: float = 60.0  # seconds
    exponential_base: float = 2.0
    jitter: bool = True


class CircuitBreakerConfig(BaseModel):
    """Circuit breaker configuration"""

    failure_threshold: int = 5  # Failures before opening
    recovery_timeout: int = 60  # Seconds before trying half-open
    success_threshold: int = 2  # Successes needed to close


class HTTPClientStats(BaseModel):
    """HTTP client statistics"""

    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_retries: int = 0
    circuit_breaker_state: CircuitBreakerState = CircuitBreakerState.CLOSED
    last_failure: Optional[datetime] = None
    consecutive_failures: int = 0
    consecutive_successes: int = 0


class CircuitBreaker:
    """Circuit breaker implementation for HTTP requests"""

    def __init__(self, config: CircuitBreakerConfig):
        self.config = config
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None

    def can_execute(self) -> bool:
        """Check if request can be executed"""
        if self.state == CircuitBreakerState.CLOSED:
            return True
        elif self.state == CircuitBreakerState.OPEN:
            # Check if enough time has passed to try half-open
            if (
                self.last_failure_time
                and time.time() - self.last_failure_time >= self.config.recovery_timeout
            ):
                self.state = CircuitBreakerState.HALF_OPEN
                self.success_count = 0
                logger.info("Circuit breaker transitioning to half-open")
                return True
            return False
        else:  # HALF_OPEN
            return True

    def record_success(self):
        """Record successful request"""
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                self.state = CircuitBreakerState.CLOSED
                self.failure_count = 0
                logger.info("Circuit breaker closed after successful recovery")
        elif self.state == CircuitBreakerState.CLOSED:
            self.failure_count = 0

    def record_failure(self):
        """Record failed request"""
        self.failure_count += 1
        self.last_failure_time = time.time()

        if (
            self.state == CircuitBreakerState.CLOSED
            and self.failure_count >= self.config.failure_threshold
        ):
            self.state = CircuitBreakerState.OPEN
            logger.warning(f"Circuit breaker opened after {self.failure_count} failures")
        elif self.state == CircuitBreakerState.HALF_OPEN:
            self.state = CircuitBreakerState.OPEN
            logger.warning("Circuit breaker reopened during half-open test")


class HttpClient:
    """Enhanced HTTP client with retry logic, circuit breaker, and monitoring"""

    def __init__(
        self,
        retry_policy: Optional[RetryPolicy] = None,
        circuit_breaker_config: Optional[CircuitBreakerConfig] = None,
        timeout: float = 30.0,
        user_agent: str = "OpenWatch-HttpClient/1.0",
    ):
        self.retry_policy = retry_policy or RetryPolicy()
        self.circuit_breaker = CircuitBreaker(circuit_breaker_config or CircuitBreakerConfig())
        self.timeout = httpx.Timeout(timeout)
        self.user_agent = user_agent
        self.stats = HTTPClientStats()

        # Create httpx client
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            headers={"User-Agent": self.user_agent},
            follow_redirects=True,
        )

    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()

    def _calculate_delay(self, attempt: int) -> float:
        """Calculate delay for exponential backoff"""
        delay = min(
            self.retry_policy.base_delay * (self.retry_policy.exponential_base**attempt),
            self.retry_policy.max_delay,
        )

        # Add jitter to prevent thundering herd (using secrets for cryptographic randomness)
        if self.retry_policy.jitter:
            import secrets

            delay *= 0.5 + secrets.SystemRandom().random() * 0.5

        return delay

    def _is_retryable_error(self, exception: Exception) -> bool:
        """Determine if an error is retryable"""
        if isinstance(exception, httpx.TimeoutException):
            return True
        elif isinstance(exception, httpx.ConnectError):
            return True
        elif isinstance(exception, httpx.HTTPStatusError):
            # Retry on server errors (5xx) but not client errors (4xx)
            return 500 <= exception.response.status_code < 600
        return False

    async def _execute_request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Execute HTTP request with retry logic and circuit breaker"""

        # Check circuit breaker
        if not self.circuit_breaker.can_execute():
            self.stats.failed_requests += 1
            raise httpx.ConnectError(
                "Circuit breaker is open - service unavailable",
                request=httpx.Request(method, url),
            )

        self.stats.total_requests += 1
        last_exception = None

        for attempt in range(self.retry_policy.max_retries + 1):
            try:
                # Log request
                logger.debug(
                    "HTTP request",
                    method=method,
                    url=url,
                    attempt=attempt + 1,
                    max_attempts=self.retry_policy.max_retries + 1,
                )

                # Execute request
                response = await self.client.request(method, url, **kwargs)

                # Check for HTTP errors
                response.raise_for_status()

                # Success - update stats and circuit breaker
                self.stats.successful_requests += 1
                self.circuit_breaker.record_success()

                logger.debug(
                    "HTTP request successful",
                    method=method,
                    url=url,
                    status_code=response.status_code,
                    attempt=attempt + 1,
                )

                return response

            except Exception as e:
                last_exception = e
                self.stats.total_retries += 1

                logger.warning(
                    "HTTP request failed",
                    method=method,
                    url=url,
                    attempt=attempt + 1,
                    error=str(e),
                    error_type=type(e).__name__,
                )

                # Check if we should retry
                if attempt < self.retry_policy.max_retries and self._is_retryable_error(e):
                    delay = self._calculate_delay(attempt)
                    logger.debug(f"Retrying request in {delay:.2f} seconds")
                    await asyncio.sleep(delay)
                    continue
                else:
                    # No more retries or non-retryable error
                    break

        # All retries exhausted - record failure
        self.stats.failed_requests += 1
        self.circuit_breaker.record_failure()
        self.stats.last_failure = datetime.utcnow()
        self.stats.consecutive_failures += 1
        self.stats.consecutive_successes = 0

        logger.error(
            "HTTP request failed after all retries",
            method=method,
            url=url,
            total_attempts=self.retry_policy.max_retries + 1,
            final_error=str(last_exception),
        )

        raise last_exception

    async def get(self, url: str, **kwargs) -> httpx.Response:
        """Execute GET request"""
        return await self._execute_request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        """Execute POST request"""
        return await self._execute_request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> httpx.Response:
        """Execute PUT request"""
        return await self._execute_request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> httpx.Response:
        """Execute DELETE request"""
        return await self._execute_request("DELETE", url, **kwargs)

    async def patch(self, url: str, **kwargs) -> httpx.Response:
        """Execute PATCH request"""
        return await self._execute_request("PATCH", url, **kwargs)

    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics"""
        self.stats.circuit_breaker_state = self.circuit_breaker.state
        return self.stats.dict()

    def reset_stats(self):
        """Reset client statistics"""
        self.stats = HTTPClientStats()


class WebhookHttpClient(HttpClient):
    """Specialized HTTP client for webhook delivery"""

    def __init__(self):
        # Webhook-specific configuration
        retry_policy = RetryPolicy(
            max_retries=3,
            base_delay=1.0,
            max_delay=30.0,
            exponential_base=2.0,
            jitter=True,
        )

        circuit_breaker_config = CircuitBreakerConfig(
            failure_threshold=5,
            recovery_timeout=300,  # 5 minutes for webhooks
            success_threshold=2,
        )

        super().__init__(
            retry_policy=retry_policy,
            circuit_breaker_config=circuit_breaker_config,
            timeout=30.0,
            user_agent="OpenWatch-Webhook/1.0",
        )

    async def deliver_webhook(
        self, url: str, payload: Dict[str, Any], headers: Dict[str, str]
    ) -> httpx.Response:
        """Deliver webhook with specialized handling"""
        import json

        # Prepare webhook headers
        webhook_headers = {"Content-Type": "application/json", **headers}

        # Convert payload to JSON
        json_payload = json.dumps(payload, separators=(",", ":"))

        return await self.post(url, headers=webhook_headers, content=json_payload)


# Global client instances
_default_client: Optional[HttpClient] = None
_webhook_client: Optional[WebhookHttpClient] = None


async def get_default_client() -> HttpClient:
    """Get the default HTTP client instance"""
    global _default_client
    if _default_client is None:
        _default_client = HttpClient()
    return _default_client


async def get_webhook_client() -> WebhookHttpClient:
    """Get the webhook HTTP client instance"""
    global _webhook_client
    if _webhook_client is None:
        _webhook_client = WebhookHttpClient()
    return _webhook_client


async def close_all_clients():
    """Close all HTTP client instances"""
    global _default_client, _webhook_client

    if _default_client:
        await _default_client.close()
        _default_client = None

    if _webhook_client:
        await _webhook_client.close()
        _webhook_client = None
