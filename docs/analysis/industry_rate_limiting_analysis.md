# Rate Limiting: Industry Standards vs OpenWatch Implementation

## How Major Companies Handle Rate Limiting

### 1. **GitHub API**
```
Standard: 5,000 requests/hour for authenticated users
Approach: Sliding window with gradual throttling
Headers: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
Recovery: Immediate when window resets (1 hour)
```

### 2. **Twitter API v2**
```
Standard: 300 requests/15-minute window
Approach: Token bucket algorithm
Headers: x-rate-limit-limit, x-rate-limit-remaining
Recovery: 15-minute sliding window
```

### 3. **AWS API Gateway**
```
Standard: 10,000 requests/second, 5,000 burst
Approach: Token bucket with burst capacity
Recovery: Immediate replenishment
Throttling: HTTP 429 with exponential backoff
```

### 4. **Stripe API**
```
Standard: 100 requests/second (live mode)
Approach: Sliding window with burst allowance
Headers: X-RateLimit-Limit, X-RateLimit-Remaining
Recovery: 1-second sliding window
```

## Industry Best Practices

### 🔄 **1. Sliding Window Algorithm**
Most companies use sliding window instead of fixed window:
- Smoother rate limiting
- Prevents thundering herd problems
- Better user experience

### 🪣 **2. Token Bucket Algorithm**
Popular for burst handling:
- Allows short bursts of traffic
- Gradual replenishment
- Natural backpressure

### 📊 **3. Tiered Rate Limiting**
Different limits based on authentication/subscription:
- Anonymous: Lower limits
- Authenticated: Higher limits  
- Premium/Enterprise: Highest limits
- Per-endpoint customization

### 🚦 **4. Graceful Degradation**
Instead of hard blocking:
- Return cache data when rate limited
- Reduce response detail (summary instead of full data)
- Offer alternative endpoints
- Progressive delays instead of blocks

### 🔧 **5. HTTP Headers for Transparency**
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
X-RateLimit-Retry-After: 60
```

### ⚡ **6. Short Recovery Times**
- Seconds to minutes, not hours
- Exponential backoff for repeated violations
- Immediate recovery when behavior improves

## OpenWatch Current Issues

### ❌ **Problems with Current Implementation**

1. **Excessive Block Duration**: 27+ minutes is unprecedented in industry
2. **Fixed Window**: Can cause thundering herd at window boundaries
3. **Hard Blocking**: No degraded service option
4. **No Burst Allowance**: Can't handle normal traffic spikes
5. **In-Memory Only**: Doesn't scale across instances
6. **No Transparency**: Users don't know why they're blocked
7. **All Endpoints Equal**: Critical vs non-critical treated same

### ✅ **Industry-Standard Solution**

```python
class IndustryStandardRateLimiter:
    """
    Implementation following industry best practices
    """
    
    def __init__(self):
        # Redis-based distributed storage
        self.storage = RedisTokenBucket()
        
        # Tiered limits based on authentication
        self.limits = {
            'anonymous': TokenBucket(rate=60/minute, burst=10),
            'authenticated': TokenBucket(rate=300/minute, burst=30),
            'premium': TokenBucket(rate=1000/minute, burst=100)
        }
        
        # Graceful degradation options
        self.degradation_modes = [
            'cache_only',      # Return cached data
            'summary_only',    # Reduced response detail
            'delay_response',  # Add processing delay
            'hard_limit'       # Last resort blocking
        ]
    
    async def check_rate_limit(self, user, endpoint):
        bucket = self.get_user_bucket(user)
        
        if bucket.consume():
            return RateLimitResult.ALLOW
        
        # Try graceful degradation before blocking
        if self.can_degrade(endpoint):
            return RateLimitResult.DEGRADE
        
        # Short-term backoff (30-60 seconds max)
        return RateLimitResult.THROTTLE(retry_after=60)
```

## Recommended Implementation Strategy

### 🎯 **Phase 1: Quick Fix (Immediate)**
- Reduce block durations to 1-5 minutes maximum
- Add burst allowance for normal usage patterns
- Implement proper HTTP headers

### 🎯 **Phase 2: Industry Standard (Short-term)**
- Implement token bucket algorithm
- Add Redis-based distributed storage
- Create tiered limits by authentication level

### 🎯 **Phase 3: Advanced Features (Long-term)**
- Graceful degradation modes
- Per-endpoint customization
- Machine learning for dynamic limits
- Circuit breaker patterns

## Real-World Examples

### **GitHub's Approach**
```bash
curl -I https://api.github.com/user
# Returns:
X-RateLimit-Limit: 5000
X-RateLimit-Remaining: 4999
X-RateLimit-Reset: 1640995200
X-RateLimit-Used: 1
```

### **AWS API Gateway Pattern**
- Steady rate: 1000 requests/second
- Burst capacity: 2000 requests
- Recovery: Immediate token replenishment
- Throttling: Exponential backoff with jitter

### **Cloudflare Edge Rate Limiting**
- Distributed across global edge locations
- Sub-second response times
- Automatic scaling during attacks
- Custom rules per application

## Key Takeaway

**Industry rate limiting focuses on:**
1. **User Experience**: Short recovery times, clear feedback
2. **Scalability**: Distributed, high-performance systems
3. **Flexibility**: Tiered limits, graceful degradation
4. **Transparency**: Clear headers and documentation
5. **Adaptability**: Dynamic limits based on behavior

**Our current implementation focuses on:**
1. **Security**: Long block times, hard enforcement
2. **Simplicity**: In-memory, single-instance
3. **Uniformity**: Same limits for all users/endpoints

The industry approach provides better security through intelligent throttling while maintaining excellent user experience.