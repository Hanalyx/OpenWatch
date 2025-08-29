"""
OpenWatch Rate Limiting Middleware
Prevents abuse and reconnaissance through error endpoint farming
"""
import time
import hashlib
from typing import Dict, Optional, Tuple, List
from datetime import datetime, timedelta
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from collections import defaultdict, deque
import asyncio
import logging

from ..models.error_models import RateLimitResponse
from ..services.security_audit_logger import get_security_audit_logger

logger = logging.getLogger(__name__)
audit_logger = get_security_audit_logger()

class RateLimitStore:
    """In-memory rate limit store with automatic cleanup"""
    
    def __init__(self):
        # Store request timestamps per IP
        self.requests: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        # Store blocked IPs with expiration
        self.blocked_ips: Dict[str, datetime] = {}
        # Store error counts per IP
        self.error_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        # Last cleanup time
        self.last_cleanup = datetime.utcnow()
        
    def add_request(self, ip_hash: str, endpoint: str):
        """Add a request timestamp"""
        now = datetime.utcnow()
        self.requests[ip_hash].append(now)
        
        # Track error endpoints specifically
        if 'error' in endpoint or 'validate' in endpoint or 'scan' in endpoint:
            self.error_counts[ip_hash]['total'] += 1
            self.error_counts[ip_hash][endpoint] += 1
            
        # Periodic cleanup
        if (now - self.last_cleanup).seconds > 300:  # Every 5 minutes
            self._cleanup_old_entries()
            
    def get_request_count(self, ip_hash: str, window_seconds: int) -> int:
        """Get request count within time window"""
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=window_seconds)
        
        if ip_hash not in self.requests:
            return 0
            
        # Count requests within window
        count = 0
        for request_time in reversed(self.requests[ip_hash]):
            if request_time >= cutoff:
                count += 1
            else:
                break  # Requests are ordered by time
                
        return count
        
    def is_blocked(self, ip_hash: str) -> Tuple[bool, Optional[datetime]]:
        """Check if IP is currently blocked"""
        if ip_hash in self.blocked_ips:
            block_until = self.blocked_ips[ip_hash]
            if datetime.utcnow() < block_until:
                return True, block_until
            else:
                # Block expired, remove it
                del self.blocked_ips[ip_hash]
                
        return False, None
        
    def block_ip(self, ip_hash: str, duration_minutes: int):
        """Block IP for specified duration"""
        block_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
        self.blocked_ips[ip_hash] = block_until
        
    def get_error_stats(self, ip_hash: str) -> Dict[str, int]:
        """Get error statistics for IP"""
        return dict(self.error_counts[ip_hash])
        
    def _cleanup_old_entries(self):
        """Clean up old entries to prevent memory bloat"""
        now = datetime.utcnow()
        cutoff = now - timedelta(hours=2)
        
        # Clean up old request timestamps
        for ip_hash in list(self.requests.keys()):
            # Remove old timestamps
            while self.requests[ip_hash] and self.requests[ip_hash][0] < cutoff:
                self.requests[ip_hash].popleft()
                
            # Remove empty deques
            if not self.requests[ip_hash]:
                del self.requests[ip_hash]
                
        # Clean up expired blocks
        expired_blocks = [
            ip_hash for ip_hash, block_until in self.blocked_ips.items()
            if now >= block_until
        ]
        for ip_hash in expired_blocks:
            del self.blocked_ips[ip_hash]
            
        # Clean up old error counts
        expired_errors = []
        for ip_hash in self.error_counts:
            if ip_hash not in self.requests:
                expired_errors.append(ip_hash)
                
        for ip_hash in expired_errors:
            del self.error_counts[ip_hash]
            
        self.last_cleanup = now
        logger.debug(f"Rate limit cleanup completed: {len(expired_blocks)} expired blocks, {len(expired_errors)} expired error counts")


class RateLimitingMiddleware:
    """Rate limiting middleware for security protection"""
    
    # Rate limit configuration
    LIMITS = {
        # General API limits (for dashboard, hosts, scans, etc.)
        'default': {'requests': 200, 'window': 60, 'block_duration': 5},  # 200 req/min - increased for frontend
        
        # Authenticated user limits (higher limits for legitimate users)
        'authenticated': {'requests': 300, 'window': 60, 'block_duration': 5},  # 300 req/min for auth users
        
        # Error-prone endpoints (actual error/debug endpoints only)
        'error_endpoints': {'requests': 50, 'window': 60, 'block_duration': 10},  # 50 req/min - increased from 20
        
        # Scan validation (high limit for legitimate pre-flight checks)
        'validation': {'requests': 60, 'window': 60, 'block_duration': 10},  # 60 req/min - doubled from 30
        
        # Authentication endpoints (slightly increased for legitimate retries)
        'auth': {'requests': 10, 'window': 60, 'block_duration': 30},  # 10 req/min - doubled from 5, reduced block time
        
        # System/health endpoints (very high limit for monitoring)
        'system': {'requests': 500, 'window': 60, 'block_duration': 2},  # 500 req/min for health checks
    }
    
    # Suspicious behavior patterns (relaxed for legitimate usage)
    SUSPICIOUS_PATTERNS = {
        'high_error_rate': {'errors_per_minute': 30, 'action': 'block_30min'},  # Increased from 15
        'validation_farming': {'validation_per_minute': 20, 'action': 'block_30min'},  # Increased from 8, reduced block time
        'auth_brute_force': {'auth_failures_per_minute': 5, 'action': 'block_60min'},  # Increased from 3, reduced block time
    }
    
    def __init__(self):
        self.store = RateLimitStore()
        
    async def __call__(self, request: Request, call_next):
        """Process request through rate limiting"""
        
        # Get client IP (handle proxy headers)
        client_ip = self._get_client_ip(request)
        ip_hash = self._hash_ip(client_ip)
        endpoint = str(request.url.path)
        
        # Exclude certain endpoints from rate limiting
        excluded_endpoints = ['/health', '/metrics', '/security-info', '/docs', '/redoc', '/openapi.json']
        if any(endpoint.startswith(excluded) for excluded in excluded_endpoints):
            return await call_next(request)
        
        # Check if request is authenticated
        self._current_request_authenticated = self._check_request_authentication(request)
        
        # Determine rate limit category
        limit_category = self._get_limit_category(endpoint)
        limits = self.LIMITS[limit_category]
        
        # Check if IP is blocked
        is_blocked, block_until = self.store.is_blocked(ip_hash)
        if is_blocked:
            audit_logger.log_rate_limit_event(
                source_ip=client_ip,
                error_count=self.store.get_request_count(ip_hash, 3600),
                action_taken="request_blocked",
                user_id=self._get_user_id(request)
            )
            
            return self._create_rate_limit_response(block_until)
            
        # Check rate limits
        request_count = self.store.get_request_count(ip_hash, limits['window'])
        
        if request_count >= limits['requests']:
            # Block IP
            self.store.block_ip(ip_hash, limits['block_duration'])
            
            audit_logger.log_rate_limit_event(
                source_ip=client_ip,
                error_count=request_count,
                action_taken=f"blocked_for_{limits['block_duration']}_minutes",
                user_id=self._get_user_id(request)
            )
            
            logger.warning(f"Rate limit exceeded for IP {ip_hash}: {request_count} requests in {limits['window']}s")
            
            return self._create_rate_limit_response(
                datetime.utcnow() + timedelta(minutes=limits['block_duration'])
            )
            
        # Check for suspicious patterns
        suspicious_behavior = self._detect_suspicious_behavior(ip_hash, endpoint)
        if suspicious_behavior:
            audit_logger.log_reconnaissance_attempt(
                source_ip=client_ip,
                suspicious_patterns=suspicious_behavior,
                user_id=self._get_user_id(request),
                session_id=self._get_session_id(request)
            )
            
            # Take action based on pattern
            self._handle_suspicious_behavior(ip_hash, suspicious_behavior)
            
        # Record the request
        self.store.add_request(ip_hash, endpoint)
        
        # Add rate limit headers to response
        response = await call_next(request)
        
        # Add rate limit info to response headers
        remaining = max(0, limits['requests'] - request_count - 1)
        response.headers["X-RateLimit-Limit"] = str(limits['requests'])
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(time.time() + limits['window']))
        
        return response
        
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request, handling proxy headers"""
        
        # Check for X-Forwarded-For header (most common proxy header)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in the chain
            return forwarded_for.split(",")[0].strip()
            
        # Check for X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
            
        # Fall back to client host
        return request.client.host if request.client else "unknown"
        
    def _hash_ip(self, ip_address: str) -> str:
        """Hash IP address for privacy while maintaining consistency"""
        salt = "openwatch_rate_limit_salt_2024"
        return hashlib.sha256(f"{salt}{ip_address}".encode()).hexdigest()[:16]
        
    def _get_limit_category(self, endpoint: str) -> str:
        """Determine rate limit category for endpoint"""
        
        endpoint_lower = endpoint.lower()
        
        # System/health endpoints (highest limits)
        if any(sys_path in endpoint_lower for sys_path in ['/health', '/metrics', '/security-info']):
            return 'system'
            
        # Authentication endpoints
        if any(auth_path in endpoint_lower for auth_path in ['/auth/', '/login', '/token', '/mfa']):
            return 'auth'
            
        # Validation endpoints (pre-flight checks)
        if 'validate' in endpoint_lower:
            return 'validation'
            
        # Actual error/debug endpoints (not normal API endpoints)
        if any(error_path in endpoint_lower for error_path in ['/error', '/debug', '/classify']):
            return 'error_endpoints'
        
        # Check if user is authenticated for higher limits
        return 'authenticated' if self._has_auth_token() else 'default'
        
    def _has_auth_token(self) -> bool:
        """Check if request has authentication token"""
        # This will be set by the middleware when processing the request
        return getattr(self, '_current_request_authenticated', False)
        
    def _check_request_authentication(self, request: Request) -> bool:
        """Check if request has valid authentication token"""
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            # For now, just check if there's a Bearer token
            # In production, you'd validate the JWT token here
            token = auth_header[7:]  # Remove "Bearer " prefix
            return len(token) > 0
        return False
        
    def _get_user_id(self, request: Request) -> Optional[str]:
        """Extract user ID from request if available"""
        
        # Try to get from JWT token or session
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            try:
                # This is a simplified approach - in real implementation,
                # you'd decode the JWT token to get user ID
                return "authenticated_user"
            except:
                pass
                
        return None
        
    def _get_session_id(self, request: Request) -> Optional[str]:
        """Extract session ID from request if available"""
        
        # Check for session cookie or header
        session_id = request.cookies.get("session_id")
        if not session_id:
            session_id = request.headers.get("X-Session-ID")
            
        return session_id
        
    def _detect_suspicious_behavior(self, ip_hash: str, endpoint: str) -> List[str]:
        """Detect suspicious behavior patterns"""
        
        suspicious = []
        error_stats = self.store.get_error_stats(ip_hash)
        
        # High error rate
        error_count_1min = self.store.get_request_count(ip_hash, 60)
        if error_count_1min > self.SUSPICIOUS_PATTERNS['high_error_rate']['errors_per_minute']:
            suspicious.append('high_error_rate')
            
        # Validation endpoint farming
        if 'validate' in endpoint:
            validation_count = error_stats.get('/scans/validate', 0)
            if validation_count > self.SUSPICIOUS_PATTERNS['validation_farming']['validation_per_minute']:
                suspicious.append('validation_farming')
                
        # Authentication brute force
        if any(auth_path in endpoint for auth_path in ['/auth/', '/login']):
            auth_count = sum(count for path, count in error_stats.items() 
                           if any(auth_path in path for auth_path in ['/auth/', '/login']))
            if auth_count > self.SUSPICIOUS_PATTERNS['auth_brute_force']['auth_failures_per_minute']:
                suspicious.append('auth_brute_force')
                
        return suspicious
        
    def _handle_suspicious_behavior(self, ip_hash: str, patterns: List[str]):
        """Handle detected suspicious behavior"""
        
        # Determine the most severe action needed
        block_duration = 0
        
        for pattern in patterns:
            if pattern in self.SUSPICIOUS_PATTERNS:
                action = self.SUSPICIOUS_PATTERNS[pattern]['action']
                
                if action == 'block_30min':
                    block_duration = max(block_duration, 30)
                elif action == 'block_60min':
                    block_duration = max(block_duration, 60)
                elif action == 'block_120min':
                    block_duration = max(block_duration, 120)
                    
        # Block the IP
        if block_duration > 0:
            self.store.block_ip(ip_hash, block_duration)
            logger.warning(f"Suspicious behavior detected for IP {ip_hash}: {patterns}. Blocked for {block_duration} minutes.")
            
    def _create_rate_limit_response(self, block_until: datetime) -> JSONResponse:
        """Create rate limit exceeded response"""
        
        retry_after = int((block_until - datetime.utcnow()).total_seconds())
        
        rate_limit_response = RateLimitResponse(
            retry_after=retry_after
        )
        
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content=rate_limit_response.dict(),
            headers={
                "Retry-After": str(retry_after),
                "X-RateLimit-Reset": str(int(block_until.timestamp()))
            }
        )

# Global instance for dependency injection        
_rate_limiting_middleware = None

def get_rate_limiting_middleware() -> RateLimitingMiddleware:
    """Get or create the global rate limiting middleware"""
    global _rate_limiting_middleware
    if _rate_limiting_middleware is None:
        _rate_limiting_middleware = RateLimitingMiddleware()
    return _rate_limiting_middleware