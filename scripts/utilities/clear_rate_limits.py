#!/usr/bin/env python3
"""
Utility script to clear rate limit blocks
Use this if legitimate users are being blocked by rate limiting

Usage:
  docker-compose exec backend python3 /app/clear_rate_limits.py
  OR
  docker-compose restart backend  # Clears all in-memory state
"""
import sys
import os

# Add the backend directory to Python path
backend_path = '/app/backend' if os.path.exists('/app/backend') else os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, backend_path)

try:
    from app.middleware.rate_limiting import get_rate_limiting_middleware
except ImportError:
    # Fallback for different container structure
    import sys
    sys.path.insert(0, '/app')
    from backend.app.middleware.rate_limiting import get_rate_limiting_middleware

def clear_all_blocks():
    """Clear all IP blocks from rate limiter"""
    middleware = get_rate_limiting_middleware()
    
    # Clear blocked IPs
    blocked_count = len(middleware.store.blocked_ips)
    middleware.store.blocked_ips.clear()
    
    # Clear request history
    request_count = len(middleware.store.requests)
    middleware.store.requests.clear()
    
    # Clear error counts
    error_count = len(middleware.store.error_counts)
    middleware.store.error_counts.clear()
    
    print(f"Cleared {blocked_count} blocked IPs")
    print(f"Cleared {request_count} request histories")
    print(f"Cleared {error_count} error count records")
    print("Rate limiting state has been reset")

if __name__ == "__main__":
    clear_all_blocks()