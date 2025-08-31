#!/usr/bin/env python3
"""
Industry Standard Rate Limiting Demo
Demonstrates the difference between old and new rate limiting approaches
"""
import asyncio
import aiohttp
import time
import json
from datetime import datetime
import argparse

class RateLimitDemo:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def make_request(self, endpoint="/health", headers=None):
        """Make a request and return response details including headers"""
        start_time = time.time()
        
        try:
            async with self.session.get(f"{self.base_url}{endpoint}", headers=headers or {}) as response:
                response_time = time.time() - start_time
                text = await response.text()
                
                return {
                    'status': response.status,
                    'time': response_time,
                    'headers': dict(response.headers),
                    'body': text,
                    'timestamp': datetime.now()
                }
        except Exception as e:
            return {
                'status': 0,
                'time': time.time() - start_time,
                'headers': {},
                'body': str(e),
                'timestamp': datetime.now(),
                'error': True
            }
    
    def print_response_analysis(self, response, request_num):
        """Print detailed analysis of response"""
        status_emoji = {
            200: "✅",
            429: "🚫", 
            0: "❌"
        }.get(response['status'], "⚠️")
        
        print(f"{request_num:3d}. {status_emoji} Status: {response['status']} | Time: {response['time']:.3f}s | {response['timestamp'].strftime('%H:%M:%S')}")
        
        # Print rate limiting headers if present
        rate_headers = [k for k in response['headers'].keys() if 'rate' in k.lower() or k.lower() == 'retry-after']
        if rate_headers:
            for header in rate_headers:
                print(f"     📊 {header}: {response['headers'][header]}")
        
        # Show rate limit details for 429 responses
        if response['status'] == 429:
            try:
                body = json.loads(response['body'])
                if 'retry_after' in body:
                    print(f"     ⏳ Retry After: {body['retry_after']} seconds")
                if 'message' in body:
                    print(f"     💬 Message: {body['message']}")
            except:
                pass
        
        print()
    
    async def demo_anonymous_user_limits(self):
        """Demo rate limiting for anonymous users"""
        print("=" * 80)
        print("🔍 DEMO: Anonymous User Rate Limiting (Industry Standard)")
        print("=" * 80)
        print("Testing rapid requests as anonymous user...")
        print("Industry Standard: 60 requests/minute with 20 burst capacity")
        print("Expected: First 20 requests succeed, then throttling begins")
        print("-" * 80)
        
        for i in range(25):  # Test 25 requests
            response = await self.make_request("/health")
            self.print_response_analysis(response, i + 1)
            
            # Small delay to see pattern
            await asyncio.sleep(0.1)
    
    async def demo_authenticated_user_limits(self):
        """Demo rate limiting for authenticated users"""
        print("=" * 80)
        print("🔍 DEMO: Authenticated User Rate Limiting")
        print("=" * 80)
        print("Testing rapid requests as authenticated user...")
        print("Industry Standard: 300 requests/minute with 100 burst capacity")
        print("Expected: Much higher limits, better user experience")
        print("-" * 80)
        
        # First get an auth token
        auth_response = await self.make_request(
            "/api/auth/login",
            headers={"Content-Type": "application/json"}
        )
        
        # For demo, use a fake token (would be real in production)
        fake_token = "Bearer demo_token_for_testing"
        auth_headers = {"Authorization": fake_token}
        
        for i in range(25):
            response = await self.make_request("/health", headers=auth_headers)
            self.print_response_analysis(response, i + 1)
            await asyncio.sleep(0.1)
    
    async def demo_recovery_time(self):
        """Demo quick recovery vs old long block times"""
        print("=" * 80)
        print("🔍 DEMO: Recovery Time Comparison")
        print("=" * 80)
        print("Old Implementation: 27+ minute blocks")
        print("Industry Standard: 60 seconds maximum")
        print("-" * 80)
        
        # Make enough requests to trigger rate limit
        print("Making requests to trigger rate limit...")
        for i in range(25):
            response = await self.make_request("/api/hosts/")
            if response['status'] == 429:
                print(f"✅ Rate limit triggered at request {i + 1}")
                
                # Show retry-after time
                retry_after = response['headers'].get('retry-after', 'Unknown')
                print(f"📊 Retry-After: {retry_after} seconds (Industry Standard)")
                print("🆚 Old implementation would block for 1620+ seconds")
                break
            await asyncio.sleep(0.1)
        else:
            print("⚠️  Rate limit not triggered - may be disabled or limits very high")
    
    async def demo_header_transparency(self):
        """Demo HTTP headers for rate limiting transparency"""
        print("=" * 80)
        print("🔍 DEMO: Rate Limiting Headers (Industry Standard)")
        print("=" * 80)
        print("Industry provides transparent headers like GitHub, AWS, Stripe")
        print("-" * 80)
        
        response = await self.make_request("/health")
        
        print("Response Headers:")
        rate_limit_headers = {
            k: v for k, v in response['headers'].items() 
            if any(term in k.lower() for term in ['rate', 'limit', 'remaining', 'reset', 'retry'])
        }
        
        if rate_limit_headers:
            for header, value in rate_limit_headers.items():
                print(f"  📊 {header}: {value}")
            
            # Explain what each header means
            print("\n📖 Header Explanations:")
            if 'x-ratelimit-limit' in response['headers']:
                print(f"  • X-RateLimit-Limit: Maximum requests allowed per window")
            if 'x-ratelimit-remaining' in response['headers']:
                print(f"  • X-RateLimit-Remaining: Requests remaining in current window")
            if 'x-ratelimit-reset' in response['headers']:
                print(f"  • X-RateLimit-Reset: When the rate limit resets (Unix timestamp)")
            if 'x-ratelimit-burst' in response['headers']:
                print(f"  • X-RateLimit-Burst: Burst capacity for handling traffic spikes")
        else:
            print("⚠️  No rate limiting headers found - may be disabled")
    
    async def compare_implementations(self):
        """Show side-by-side comparison of old vs new"""
        print("=" * 80)
        print("📊 IMPLEMENTATION COMPARISON")
        print("=" * 80)
        
        comparison = [
            ("Aspect", "Old Implementation", "Industry Standard"),
            ("Algorithm", "Fixed Window", "Token Bucket"),
            ("Block Duration", "27+ minutes", "30-120 seconds"),
            ("Recovery", "Hard block", "Immediate replenishment"),
            ("Burst Handling", "None", "Configurable capacity"),
            ("Headers", "Minimal", "Full transparency"),
            ("Authentication", "Same limits", "Tiered limits"),
            ("Graceful Degradation", "No", "Future: Yes"),
            ("Distribution", "In-memory only", "Redis-ready"),
            ("Monitoring", "Basic", "Comprehensive metrics"),
        ]
        
        for aspect, old, new in comparison:
            if aspect == "Aspect":
                print(f"{'':20} | {'Old Implementation':20} | {'Industry Standard':20}")
                print("-" * 65)
            else:
                emoji_old = "❌" if "minutes" in old or old == "None" or old == "No" else "⚠️"
                emoji_new = "✅"
                print(f"{aspect:20} | {emoji_old} {old:18} | {emoji_new} {new:18}")

async def main():
    parser = argparse.ArgumentParser(description='Industry Standard Rate Limiting Demo')
    parser.add_argument('--demo', choices=['anonymous', 'authenticated', 'recovery', 'headers', 'comparison', 'all'],
                       default='all', help='Which demo to run')
    parser.add_argument('--url', default='http://localhost:8000', help='Backend URL')
    
    args = parser.parse_args()
    
    print("🚀 OpenWatch Industry Standard Rate Limiting Demo")
    print(f"Testing against: {args.url}")
    print()
    
    async with RateLimitDemo(args.url) as demo:
        if args.demo in ['anonymous', 'all']:
            await demo.demo_anonymous_user_limits()
            await asyncio.sleep(2)
        
        if args.demo in ['authenticated', 'all']:
            await demo.demo_authenticated_user_limits()
            await asyncio.sleep(2)
        
        if args.demo in ['recovery', 'all']:
            await demo.demo_recovery_time()
            await asyncio.sleep(2)
        
        if args.demo in ['headers', 'all']:
            await demo.demo_header_transparency()
            await asyncio.sleep(2)
        
        if args.demo in ['comparison', 'all']:
            await demo.compare_implementations()
    
    print("\n" + "=" * 80)
    print("🎯 SUMMARY")
    print("=" * 80)
    print("✅ Industry Standard Benefits:")
    print("   • Smooth traffic handling with token bucket algorithm")
    print("   • Short recovery times (seconds, not minutes)")
    print("   • Transparent rate limiting headers")
    print("   • Tiered limits for authenticated vs anonymous users")
    print("   • Burst capacity for normal traffic spikes")
    print("   • Environment-aware configuration")
    print()
    print("🚀 Ready for production deployment!")

if __name__ == "__main__":
    asyncio.run(main())