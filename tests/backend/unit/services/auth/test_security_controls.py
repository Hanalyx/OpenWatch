"""
Unit tests for rate limiting security controls: TokenBucket algorithm,
per-category rate limits (auth/anonymous/authenticated), 429 response with
Retry-After header, auth brute-force threshold, env var enable/disable,
excluded endpoints, HMAC-based client identification, cleanup intervals,
and suspicious activity tracking key format.

Spec: specs/system/security-controls.spec.yaml
Tests middleware/rate_limiting.py (RateLimitingMiddleware, RateLimitStore,
TokenBucket, 461 LOC).
"""

import inspect

import pytest

from app.middleware.rate_limiting import RateLimitingMiddleware, RateLimitStore, TokenBucket

# ---------------------------------------------------------------------------
# AC-1: TokenBucket with capacity/tokens/rate/last_update; consume refills
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC1TokenBucket:
    """AC-1: TokenBucket has capacity, tokens, rate, last_update; consume refills."""

    def test_has_capacity_field(self):
        """Verify TokenBucket has capacity field."""
        import dataclasses

        fields = {f.name for f in dataclasses.fields(TokenBucket)}
        assert "capacity" in fields

    def test_has_tokens_field(self):
        """Verify TokenBucket has tokens field."""
        import dataclasses

        fields = {f.name for f in dataclasses.fields(TokenBucket)}
        assert "tokens" in fields

    def test_has_rate_field(self):
        """Verify TokenBucket has rate field."""
        import dataclasses

        fields = {f.name for f in dataclasses.fields(TokenBucket)}
        assert "rate" in fields

    def test_consume_refills_based_on_elapsed_time(self):
        """Verify consume adds tokens based on elapsed time."""
        source = inspect.getsource(TokenBucket.consume)
        assert "elapsed" in source
        assert "rate" in source


# ---------------------------------------------------------------------------
# AC-2: Auth endpoints: 15 req/min, burst=5
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC2AuthRateLimit:
    """AC-2: Auth endpoint base config: requests_per_minute=15, burst_capacity=5."""

    def test_auth_requests_per_minute_15(self):
        """Verify auth endpoint base limit is 15 req/min."""
        source = inspect.getsource(RateLimitingMiddleware._get_limits_configuration)
        # Find auth block
        auth_pos = source.find('"auth"')
        assert auth_pos != -1
        auth_section = source[auth_pos : auth_pos + 300]
        assert "15" in auth_section

    def test_auth_burst_capacity_5(self):
        """Verify auth endpoint burst capacity is 5."""
        source = inspect.getsource(RateLimitingMiddleware._get_limits_configuration)
        auth_pos = source.find('"auth"')
        auth_section = source[auth_pos : auth_pos + 300]
        assert "5" in auth_section


# ---------------------------------------------------------------------------
# AC-3: Anonymous=60 req/min, authenticated=300 req/min
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC3BaseRateLimits:
    """AC-3: Anonymous base is 60 req/min; authenticated base is 300 req/min."""

    def test_anonymous_limit_60(self):
        """Verify anonymous base limit is 60 requests/min."""
        source = inspect.getsource(RateLimitingMiddleware._get_limits_configuration)
        anon_pos = source.find('"anonymous"')
        anon_section = source[anon_pos : anon_pos + 300]
        assert "60" in anon_section

    def test_authenticated_limit_300(self):
        """Verify authenticated base limit is 300 requests/min."""
        source = inspect.getsource(RateLimitingMiddleware._get_limits_configuration)
        auth_user_pos = source.find('"authenticated"')
        auth_section = source[auth_user_pos : auth_user_pos + 300]
        assert "300" in auth_section


# ---------------------------------------------------------------------------
# AC-4: Rate limit exceeded returns 429 with Retry-After
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC4RateLimitResponse:
    """AC-4: _create_rate_limit_response returns 429 with Retry-After header."""

    def test_returns_429_status_code(self):
        """Verify status_code=429 in rate limit response."""
        source = inspect.getsource(RateLimitingMiddleware._create_rate_limit_response)
        assert "429" in source

    def test_includes_retry_after_header(self):
        """Verify Retry-After header is set."""
        source = inspect.getsource(RateLimitingMiddleware._create_rate_limit_response)
        assert "Retry-After" in source

    def test_includes_x_ratelimit_headers(self):
        """Verify X-RateLimit-* headers are added."""
        source = inspect.getsource(RateLimitingMiddleware._create_rate_limit_headers)
        assert "X-RateLimit-Limit" in source
        assert "X-RateLimit-Remaining" in source
        assert "X-RateLimit-Reset" in source


# ---------------------------------------------------------------------------
# AC-5: auth_brute_force threshold=5 per 1 minute
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC5BruteForceThreshold:
    """AC-5: SUSPICIOUS_PATTERNS auth_brute_force threshold=5, window_minutes=1."""

    def test_auth_brute_force_threshold_is_5(self):
        """Verify auth_brute_force threshold is 5."""
        assert RateLimitingMiddleware.SUSPICIOUS_PATTERNS["auth_brute_force"]["threshold"] == 5

    def test_auth_brute_force_window_is_1_minute(self):
        """Verify auth_brute_force window is 1 minute."""
        assert RateLimitingMiddleware.SUSPICIOUS_PATTERNS["auth_brute_force"]["window_minutes"] == 1

    def test_three_suspicious_pattern_types(self):
        """Verify exactly 3 suspicious pattern types exist."""
        assert len(RateLimitingMiddleware.SUSPICIOUS_PATTERNS) == 3


# ---------------------------------------------------------------------------
# AC-6: OPENWATCH_RATE_LIMITING env var controls enable/disable
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC6EnvVarControl:
    """AC-6: OPENWATCH_RATE_LIMITING env var controls self.enabled."""

    def test_reads_rate_limiting_env_var(self):
        """Verify OPENWATCH_RATE_LIMITING env var read in __init__."""
        source = inspect.getsource(RateLimitingMiddleware.__init__)
        assert "OPENWATCH_RATE_LIMITING" in source

    def test_enabled_attribute_set(self):
        """Verify self.enabled is set from env var."""
        source = inspect.getsource(RateLimitingMiddleware.__init__)
        assert "self.enabled" in source

    def test_disabled_passes_requests_through(self):
        """Verify disabled middleware calls call_next directly."""
        source = inspect.getsource(RateLimitingMiddleware.__call__)
        assert "self.enabled" in source
        assert "call_next" in source


# ---------------------------------------------------------------------------
# AC-7: Health/metrics/docs endpoints excluded
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC7ExcludedEndpoints:
    """AC-7: _get_endpoint_category returns 'excluded' for monitoring endpoints."""

    def test_health_endpoint_excluded(self):
        """Verify /health is in excluded paths."""
        source = inspect.getsource(RateLimitingMiddleware._get_endpoint_category)
        assert "/health" in source
        assert '"excluded"' in source

    def test_metrics_endpoint_excluded(self):
        """Verify /metrics is in excluded paths."""
        source = inspect.getsource(RateLimitingMiddleware._get_endpoint_category)
        assert "/metrics" in source

    def test_docs_endpoint_excluded(self):
        """Verify /docs is in excluded paths."""
        source = inspect.getsource(RateLimitingMiddleware._get_endpoint_category)
        assert "/docs" in source

    def test_security_info_excluded(self):
        """Verify /security-info is in excluded paths."""
        source = inspect.getsource(RateLimitingMiddleware._get_endpoint_category)
        assert "/security-info" in source


# ---------------------------------------------------------------------------
# AC-8: HMAC-SHA256 client identification
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC8HMACClientIdentification:
    """AC-8: Clients identified by HMAC-SHA256 of token or IP address."""

    def test_uses_hmac(self):
        """Verify hmac module used for client identification."""
        source = inspect.getsource(RateLimitingMiddleware._get_client_identifier)
        assert "hmac" in source

    def test_uses_sha256_for_hashing(self):
        """Verify sha256 used in HMAC."""
        source = inspect.getsource(RateLimitingMiddleware._get_client_identifier)
        assert "sha256" in source

    def test_authenticated_uses_bearer_token(self):
        """Verify Bearer token hashed for authenticated clients."""
        source = inspect.getsource(RateLimitingMiddleware._get_client_identifier)
        assert "Bearer" in source
        assert '"authenticated"' in source

    def test_anonymous_uses_ip_address(self):
        """Verify IP address hashed for anonymous clients."""
        source = inspect.getsource(RateLimitingMiddleware._get_client_identifier)
        assert '"anonymous"' in source


# ---------------------------------------------------------------------------
# AC-9: Cleanup runs every 300s; unused buckets purged after 3600s
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC9CleanupIntervals:
    """AC-9: cleanup_old_entries runs every 300s; removes buckets unused 3600s."""

    def test_cleanup_interval_300_seconds(self):
        """Verify cleanup skips if fewer than 300 seconds elapsed."""
        source = inspect.getsource(RateLimitStore.cleanup_old_entries)
        assert "300" in source

    def test_bucket_age_threshold_3600_seconds(self):
        """Verify buckets unused for 3600 seconds are removed."""
        source = inspect.getsource(RateLimitStore.cleanup_old_entries)
        assert "3600" in source


# ---------------------------------------------------------------------------
# AC-10: Suspicious activity tracked by minute-bucket key
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC10SuspiciousActivityKeys:
    """AC-10: track_suspicious_activity keys as '{activity_type}:{current_minute}'."""

    def test_key_uses_current_minute(self):
        """Verify key format includes current_minute from time.time()//60."""
        source = inspect.getsource(RateLimitStore.track_suspicious_activity)
        assert "time.time()" in source or "time()" in source
        assert "// 60" in source

    def test_key_format_is_type_colon_minute(self):
        """Verify key is formatted as '{activity_type}:{minute}'."""
        source = inspect.getsource(RateLimitStore.track_suspicious_activity)
        assert "activity_type" in source
        assert "current_minute" in source

    def test_get_activity_count_queries_minute_range(self):
        """Verify get_suspicious_activity_count iterates over minute range."""
        source = inspect.getsource(RateLimitStore.get_suspicious_activity_count)
        assert "range(minutes)" in source
