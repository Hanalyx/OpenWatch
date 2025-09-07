"""
OpenWatch Rate Limiting Middleware
Implements industry-standard rate limiting with token bucket algorithm
"""
import os
import time
import hashlib
import secrets
from typing import Dict, Optional, Tuple, List
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from dataclasses import dataclass
import logging

from ..models.error_models import RateLimitResponse
from ..services.security_audit_logger import get_security_audit_logger

logger = logging.getLogger(__name__)
audit_logger = get_security_audit_logger()

@dataclass
class TokenBucket:
    """Token bucket implementation for smooth rate limiting"""
    capacity: int  # Maximum tokens
    tokens: float  # Current tokens
    rate: float    # Tokens per second
    last_update: float  # Last update timestamp
    
    def consume(self, tokens_requested: int = 1) -> bool:
        """Attempt to consume tokens from bucket"""
        now = time.time()
        
        # Add tokens based on elapsed time
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + (elapsed * self.rate))
        self.last_update = now
        
        # Check if we have enough tokens
        if self.tokens >= tokens_requested:
            self.tokens -= tokens_requested
            return True
        return False
    
    def time_until_available(self, tokens_needed: int = 1) -> float:
        """Calculate seconds until tokens are available"""
        if self.tokens >= tokens_needed:
            return 0.0
        
        tokens_deficit = tokens_needed - self.tokens
        return tokens_deficit / self.rate


class RateLimitStore:
    """In-memory rate limit store with token buckets and automatic cleanup"""
    
    def __init__(self):
        # Token buckets per client/endpoint
        self.buckets: Dict[str, TokenBucket] = {}
        # Track suspicious activity
        self.suspicious_activity: Dict[str, Dict[str, int]] = {}
        # Last cleanup time
        self.last_cleanup = time.time()
    
    def get_or_create_bucket(self, bucket_key: str, capacity: int, rate: float) -> TokenBucket:
        """Get or create token bucket for client"""
        if bucket_key not in self.buckets:
            self.buckets[bucket_key] = TokenBucket(
                capacity=capacity,
                tokens=capacity,  # Start with full bucket
                rate=rate,
                last_update=time.time()
            )
        return self.buckets[bucket_key]
    
    def track_suspicious_activity(self, client_id: str, activity_type: str):
        """Track suspicious activity patterns"""
        if client_id not in self.suspicious_activity:
            self.suspicious_activity[client_id] = {}
        
        current_minute = int(time.time() // 60)
        key = f"{activity_type}:{current_minute}"
        
        if key not in self.suspicious_activity[client_id]:
            self.suspicious_activity[client_id][key] = 0
        
        self.suspicious_activity[client_id][key] += 1
    
    def get_suspicious_activity_count(self, client_id: str, activity_type: str, minutes: int = 1) -> int:
        """Get count of suspicious activities within time window"""
        if client_id not in self.suspicious_activity:
            return 0
        
        current_minute = int(time.time() // 60)
        count = 0
        
        for i in range(minutes):
            key = f"{activity_type}:{current_minute - i}"
            count += self.suspicious_activity[client_id].get(key, 0)
        
        return count
    
    def cleanup_old_entries(self):
        """Clean up old entries to prevent memory bloat"""
        if time.time() - self.last_cleanup < 300:  # Every 5 minutes
            return
        
        now = time.time()
        cleanup_age = 3600  # Remove buckets unused for 1 hour
        
        # Clean up old token buckets
        buckets_to_remove = [
            key for key, bucket in self.buckets.items()
            if now - bucket.last_update > cleanup_age
        ]
        
        for key in buckets_to_remove:
            del self.buckets[key]
        
        # Clean up old suspicious activity data
        current_minute = int(now // 60)
        cutoff_minute = current_minute - 120  # Keep 2 hours of data
        
        for client_id in list(self.suspicious_activity.keys()):
            activities = self.suspicious_activity[client_id]
            old_keys = [
                key for key in activities.keys()
                if ':' in key and int(key.split(':')[1]) < cutoff_minute
            ]
            
            for key in old_keys:
                del activities[key]
            
            if not activities:
                del self.suspicious_activity[client_id]
        
        self.last_cleanup = now
        if buckets_to_remove:
            logger.debug(f"Rate limit cleanup: removed {len(buckets_to_remove)} unused buckets")


class RateLimitingMiddleware:
    """Industry-standard rate limiting middleware with token bucket algorithm"""
    
    def __init__(self):
        self.store = RateLimitStore()
        self.enabled = os.getenv("OPENWATCH_RATE_LIMITING", "true").lower() == "true"
        self.environment = os.getenv("OPENWATCH_ENVIRONMENT", "development").lower()
        self.limits_config = self._get_limits_configuration()
        
        logger.info(f"Rate limiting initialized - Environment: {self.environment}, Enabled: {self.enabled}")
    
    def _get_limits_configuration(self) -> Dict:
        """Get rate limits following industry patterns"""
        base_config = {
            # Anonymous users (like GitHub's unauthenticated API)
            'anonymous': {
                'requests_per_minute': 60,    # 1 per second average
                'burst_capacity': 20,         # Allow short bursts
                'retry_after_seconds': 60     # 1 minute recovery
            },
            
            # Authenticated users (like GitHub's authenticated API)
            'authenticated': {
                'requests_per_minute': 300,   # 5 per second average
                'burst_capacity': 100,        # Generous burst allowance
                'retry_after_seconds': 30     # 30 second recovery
            },
            
            # System/health endpoints (like AWS health checks)
            'system': {
                'requests_per_minute': 600,   # High limit for monitoring
                'burst_capacity': 200,        # Large burst for health checks
                'retry_after_seconds': 10     # Quick recovery
            },
            
            # Authentication endpoints (like Stripe's sensitive endpoints)
            'auth': {
                'requests_per_minute': 15,    # Even more restrictive for security
                'burst_capacity': 5,          # Very small burst allowance
                'retry_after_seconds': 300    # 5 minute recovery for security
            },
            
            # Error-prone endpoints
            'error_endpoints': {
                'requests_per_minute': 50,
                'burst_capacity': 15,
                'retry_after_seconds': 60
            },
            
            # Validation endpoints
            'validation': {
                'requests_per_minute': 60,
                'burst_capacity': 20,
                'retry_after_seconds': 60
            }
        }
        
        # Environment-specific adjustments
        if self.environment == "development":
            # Much higher limits for development
            for category in base_config:
                base_config[category]['requests_per_minute'] *= 10
                base_config[category]['burst_capacity'] *= 5
                base_config[category]['retry_after_seconds'] = min(30, base_config[category]['retry_after_seconds'])
        
        elif self.environment == "testing":
            # Lower limits for testing rate limiting
            for category in base_config:
                base_config[category]['requests_per_minute'] //= 2
                base_config[category]['retry_after_seconds'] = 30
        
        elif self.environment == "staging":
            # Slightly higher limits than production
            for category in base_config:
                base_config[category]['requests_per_minute'] = int(base_config[category]['requests_per_minute'] * 1.2)
        
        return base_config
    
    # Suspicious behavior patterns
    SUSPICIOUS_PATTERNS = {
        'high_error_rate': {'threshold': 30, 'window_minutes': 1},
        'validation_farming': {'threshold': 20, 'window_minutes': 1},
        'auth_brute_force': {'threshold': 5, 'window_minutes': 1}
    }
    
    async def __call__(self, request: Request, call_next) -> Response:
        """Main rate limiting middleware function"""
        # Skip if disabled
        if not self.enabled:
            return await call_next(request)
        
        # Periodic cleanup
        self.store.cleanup_old_entries()
        
        # Get client information
        client_id, client_type = self._get_client_identifier(request)
        endpoint = str(request.url.path)
        endpoint_category = self._get_endpoint_category(endpoint)
        
        # Skip excluded endpoints
        if endpoint_category == 'excluded':
            return await call_next(request)
        
        # Get appropriate configuration
        config_key = endpoint_category if endpoint_category in self.limits_config else client_type
        config = self.limits_config.get(config_key, self.limits_config['anonymous'])
        
        # Get or create token bucket
        bucket_key = f"{client_id}:{endpoint_category}"
        rate_per_second = config['requests_per_minute'] / 60.0
        bucket = self.store.get_or_create_bucket(
            bucket_key,
            config['burst_capacity'],
            rate_per_second
        )
        
        # Create headers for response
        headers = self._create_rate_limit_headers(bucket, config)
        
        # Try to consume token
        if bucket.consume(1):
            # Track suspicious patterns
            self._track_suspicious_patterns(client_id, endpoint, request)
            
            # Check for suspicious behavior
            suspicious_behavior = self._detect_suspicious_behavior(client_id)
            if suspicious_behavior:
                client_ip = self._get_client_ip(request)
                audit_logger.log_reconnaissance_attempt(
                    source_ip=client_ip,
                    suspicious_patterns=suspicious_behavior,
                    user_id=self._get_user_id(request),
                    session_id=self._get_session_id(request)
                )
            
            # Request allowed - proceed
            response = await call_next(request)
            
            # Add rate limit headers
            for header_name, header_value in headers.items():
                response.headers[header_name] = header_value
            
            return response
        else:
            # Rate limit exceeded
            retry_after = min(
                config['retry_after_seconds'],
                int(bucket.time_until_available(1)) + 1
            )
            
            client_ip = self._get_client_ip(request)
            audit_logger.log_rate_limit_event(
                source_ip=client_ip,
                error_count=int(bucket.capacity - bucket.tokens),
                action_taken=f"rate_limited_retry_after_{retry_after}s",
                user_id=self._get_user_id(request)
            )
            
            logger.warning(f"Rate limit exceeded for {client_id} on {endpoint} - retry after {retry_after}s")
            
            return self._create_rate_limit_response(retry_after, headers)
    
    def _get_client_identifier(self, request: Request) -> Tuple[str, str]:
        """Get client identifier and type (anonymous/authenticated)"""
        # Check for authentication
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            # Authenticated user - use secure token hash as identifier with salt
            # Use HMAC-SHA256 instead of plain SHA256 for better security
            import hmac
            secret_key = os.getenv("RATE_LIMIT_SECRET", secrets.token_hex(32))
            token_hash = hmac.new(
                secret_key.encode(), 
                auth_header.encode(), 
                hashlib.sha256
            ).hexdigest()[:16]
            return f"auth:{token_hash}", "authenticated"
        
        # Anonymous user - use IP address with secure hashing
        client_ip = self._get_client_ip(request)
        import hmac
        secret_key = os.getenv("RATE_LIMIT_SECRET", secrets.token_hex(32))
        ip_hash = hmac.new(
            secret_key.encode(), 
            f"{client_ip}:anonymous".encode(), 
            hashlib.sha256
        ).hexdigest()[:16]
        return f"anon:{ip_hash}", "anonymous"
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP handling proxy headers"""
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"
    
    def _get_endpoint_category(self, path: str) -> str:
        """Categorize endpoint for appropriate rate limiting"""
        path_lower = path.lower()
        
        # Excluded endpoints
        if any(path.startswith(p) for p in ['/health', '/metrics', '/docs', '/redoc', '/openapi.json', '/security-info']):
            return 'excluded'
        
        # System endpoints
        if any(p in path_lower for p in ['/health', '/metrics']):
            return 'system'
        
        # Authentication endpoints
        if any(p in path_lower for p in ['/auth/', '/login', '/token', '/register', '/mfa']):
            return 'auth'
        
        # Validation endpoints
        if 'validate' in path_lower:
            return 'validation'
        
        # Error/debug endpoints
        if any(p in path_lower for p in ['/error', '/debug', '/classify']):
            return 'error_endpoints'
        
        # Default to regular API
        return 'api'
    
    def _create_rate_limit_headers(self, bucket: TokenBucket, config: Dict) -> Dict[str, str]:
        """Create industry-standard rate limit headers"""
        current_minute = int(time.time() // 60)
        reset_time = (current_minute + 1) * 60  # Next minute boundary
        
        return {
            "X-RateLimit-Limit": str(config['requests_per_minute']),
            "X-RateLimit-Remaining": str(max(0, int(bucket.tokens))),
            "X-RateLimit-Reset": str(reset_time),
            "X-RateLimit-Burst": str(config['burst_capacity']),
        }
    
    def _create_rate_limit_response(self, retry_after: int, headers: Dict[str, str]) -> JSONResponse:
        """Create standardized rate limit exceeded response"""
        headers["Retry-After"] = str(retry_after)
        headers["X-RateLimit-Retry-After"] = str(retry_after)
        
        rate_limit_response = RateLimitResponse(
            retry_after=retry_after
        )
        
        return JSONResponse(
            status_code=429,
            content=rate_limit_response.dict(),
            headers=headers
        )
    
    def _track_suspicious_patterns(self, client_id: str, endpoint: str, request: Request):
        """Track patterns that might indicate suspicious behavior"""
        endpoint_lower = endpoint.lower()
        
        # Track error endpoints
        if any(p in endpoint_lower for p in ['/error', '/debug', '/classify']):
            self.store.track_suspicious_activity(client_id, 'error_endpoints')
        
        # Track validation endpoints
        if 'validate' in endpoint_lower:
            self.store.track_suspicious_activity(client_id, 'validation_endpoints')
        
        # Track auth failures (would need response status in real implementation)
        if any(p in endpoint_lower for p in ['/auth/', '/login', '/token']):
            self.store.track_suspicious_activity(client_id, 'auth_attempts')
    
    def _detect_suspicious_behavior(self, client_id: str) -> List[str]:
        """Detect suspicious behavior patterns"""
        suspicious = []
        
        # Check high error rate
        error_count = self.store.get_suspicious_activity_count(
            client_id, 'error_endpoints', 
            self.SUSPICIOUS_PATTERNS['high_error_rate']['window_minutes']
        )
        if error_count > self.SUSPICIOUS_PATTERNS['high_error_rate']['threshold']:
            suspicious.append('high_error_rate')
        
        # Check validation farming
        validation_count = self.store.get_suspicious_activity_count(
            client_id, 'validation_endpoints',
            self.SUSPICIOUS_PATTERNS['validation_farming']['window_minutes']
        )
        if validation_count > self.SUSPICIOUS_PATTERNS['validation_farming']['threshold']:
            suspicious.append('validation_farming')
        
        # Check auth brute force
        auth_count = self.store.get_suspicious_activity_count(
            client_id, 'auth_attempts',
            self.SUSPICIOUS_PATTERNS['auth_brute_force']['window_minutes']
        )
        if auth_count > self.SUSPICIOUS_PATTERNS['auth_brute_force']['threshold']:
            suspicious.append('auth_brute_force')
        
        return suspicious
    
    def _get_user_id(self, request: Request) -> Optional[str]:
        """Extract user ID from request if available"""
        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            # Simplified - in production decode JWT
            return "authenticated_user"
        return None
    
    def _get_session_id(self, request: Request) -> Optional[str]:
        """Extract session ID from request if available"""
        session_id = request.cookies.get("session_id")
        if not session_id:
            session_id = request.headers.get("x-session-id")
        return session_id


# Global instance for dependency injection
_rate_limiting_middleware = None

def get_rate_limiting_middleware() -> RateLimitingMiddleware:
    """Get or create the global rate limiting middleware"""
    global _rate_limiting_middleware
    if _rate_limiting_middleware is None:
        _rate_limiting_middleware = RateLimitingMiddleware()
    return _rate_limiting_middleware

# Alias for backward compatibility
get_industry_standard_rate_limiter = get_rate_limiting_middleware