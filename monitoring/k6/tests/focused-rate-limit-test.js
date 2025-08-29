/**
 * OpenWatch Focused Rate Limiting Stress Test
 * Simplified test for infrastructure constraints
 */

import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Rate, Counter, Trend } from 'k6/metrics';

// Custom metrics
const rateLimitHits = new Counter('rate_limit_hits');
const successfulRequests = new Counter('successful_requests');
const responseTime = new Trend('response_time');

// Configuration
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';
const AUTH_TOKEN = __ENV.AUTH_TOKEN || '';

export const options = {
  stages: [
    // Warm up - 10 users for 30 seconds
    { duration: '30s', target: 10 },
    
    // Ramp up - increase to 100 concurrent users over 1 minute
    { duration: '1m', target: 100 },
    
    // Stress phase - 300 concurrent users for 2 minutes
    { duration: '2m', target: 300 },
    
    // Peak stress - 500 concurrent users for 1 minute
    { duration: '1m', target: 500 },
    
    // Cool down - back to 50 users for 1 minute
    { duration: '1m', target: 50 },
    
    // Final ramp down
    { duration: '30s', target: 0 },
  ],
  
  thresholds: {
    'rate_limit_hits': ['count>0'], // We expect rate limiting to trigger
    'http_req_failed': ['rate<0.95'], // Allow up to 95% failure during peak stress
    'http_req_duration': ['p(95)<5000'], // 95% of requests under 5s
  },
};

export function setup() {
  console.log('🚀 Starting OpenWatch Focused Rate Limiting Test');
  console.log(`   Base URL: ${BASE_URL}`);
  
  // Verify API accessibility
  const healthCheck = http.get(`${BASE_URL}/health`);
  const isHealthy = check(healthCheck, {
    'API is accessible': (r) => r.status === 200,
  });
  
  if (!isHealthy) {
    console.error('❌ API health check failed');
    return null;
  }
  
  return { 
    baseUrl: BASE_URL, 
    authToken: AUTH_TOKEN,
    startTime: Date.now()
  };
}

export default function(data) {
  if (!data) return;
  
  const headers = data.authToken ? { 'Authorization': `Bearer ${data.authToken}` } : {};
  
  group('Rate Limiting Stress Test', function() {
    // Test different endpoints to hit various rate limit tiers
    const endpoints = [
      '/api/hosts/',
      '/api/scans/',
      '/api/host-groups/',
      '/health',
    ];
    
    const endpoint = endpoints[Math.floor(Math.random() * endpoints.length)];
    const url = `${data.baseUrl}${endpoint}`;
    
    const response = http.get(url, { headers, timeout: '10s' });
    
    // Check response
    const checks = check(response, {
      'Request completed': (r) => r.status > 0,
      'No 5xx errors': (r) => r.status < 500,
      'Rate limit or success': (r) => r.status === 200 || r.status === 429 || r.status === 401,
    });
    
    // Track metrics
    responseTime.add(response.timings.duration);
    
    if (response.status === 429) {
      rateLimitHits.add(1);
      
      // Log rate limit details
      const retryAfter = response.headers['Retry-After'] || 'unknown';
      const rateLimit = response.headers['X-RateLimit-Limit'] || 'unknown';
      const remaining = response.headers['X-RateLimit-Remaining'] || 'unknown';
      
      console.log(`🚦 Rate limited! Limit: ${rateLimit}, Remaining: ${remaining}, Retry-After: ${retryAfter}s`);
      
      // Respect rate limiting
      if (retryAfter && retryAfter !== 'unknown') {
        sleep(Math.min(parseInt(retryAfter), 5)); // Max 5 second sleep
      }
    } else if (response.status === 200) {
      successfulRequests.add(1);
    }
    
    // Brief pause to prevent overwhelming the system
    sleep(0.1 + Math.random() * 0.5); // 100-600ms random delay
  });
}

export function teardown(data) {
  if (!data) return;
  
  const duration = (Date.now() - data.startTime) / 1000;
  console.log('\n📊 Rate Limiting Stress Test Complete');
  console.log(`   Duration: ${Math.floor(duration)}s`);
  console.log('   Check k6 output for detailed metrics');
}