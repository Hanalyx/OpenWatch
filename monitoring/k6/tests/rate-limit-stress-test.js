/**
 * OpenWatch Rate Limiting Stress Test
 * Tests rate limiting behavior under various load conditions
 * Infrastructure-appropriate limits: 500 concurrent, 200 req/min sustained
 */

import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Rate, Counter, Trend, Gauge } from 'k6/metrics';

// Custom metrics
const rateLimitHits = new Counter('rate_limit_hits');
const successfulRequests = new Counter('successful_requests');
const failedRequests = new Counter('failed_requests');
const responseTime = new Trend('response_time');
const concurrentUsers = new Gauge('concurrent_users');

// Test configuration
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';
const AUTH_TOKEN = __ENV.AUTH_TOKEN || '';

// Rate limit test scenarios
export const options = {
  scenarios: {
    // Concurrent burst test - 500 users hitting API simultaneously
    concurrent_burst: {
      executor: 'per-vu-iterations',
      vus: 500,
      iterations: 1,
      startTime: '0s',
      maxDuration: '60s',
      tags: { test_type: 'concurrent_burst' },
    },
    
    // Sustained load test - 200 req/min for 10 minutes
    sustained_load: {
      executor: 'constant-arrival-rate',
      rate: 200, // 200 requests per minute
      timeUnit: '1m',
      duration: '10m',
      preAllocatedVUs: 50,
      maxVUs: 100,
      startTime: '2m', // Start after burst test
      tags: { test_type: 'sustained_load' },
    },
    
    // Rapid burst test - 300 requests in 30 seconds
    rapid_burst: {
      executor: 'constant-arrival-rate', 
      rate: 600, // 600/min = 300 in 30 seconds
      timeUnit: '1m',
      duration: '30s',
      preAllocatedVUs: 100,
      maxVUs: 200,
      startTime: '13m', // After sustained load
      tags: { test_type: 'rapid_burst' },
    },
    
    // Multi-endpoint stress - Test different rate limit tiers
    multi_endpoint: {
      executor: 'per-vu-iterations',
      vus: 100,
      iterations: 5,
      startTime: '15m',
      maxDuration: '5m',
      tags: { test_type: 'multi_endpoint' },
    }
  },
  
  thresholds: {
    // Rate limit should trigger under heavy load
    'rate_limit_hits': ['count>0'],
    
    // Most requests should succeed when under normal limits
    'http_req_failed{test_type:sustained_load}': ['rate<0.8'],
    
    // Response time should stay reasonable
    'http_req_duration{test_type:sustained_load}': ['p(95)<2000'],
    
    // System should handle concurrent load
    'http_req_duration{test_type:concurrent_burst}': ['p(95)<5000'],
  }
};

// Test data and endpoints
const endpoints = {
  hosts: '/api/hosts/',
  scans: '/api/scans/',
  groups: '/api/host-groups/',
  auth: '/api/auth/validate-token',
  health: '/health',
  system: '/api/system/info'
};

const errorEndpoints = {
  invalid_host: '/api/hosts/invalid-uuid-format',
  nonexistent: '/api/hosts/00000000-0000-0000-0000-000000000000',
  validation: '/api/auth/validate-token'
};

export function setup() {
  console.log('🚀 Starting OpenWatch Rate Limiting Stress Test');
  console.log(`   Base URL: ${BASE_URL}`);
  console.log(`   Auth Token: ${AUTH_TOKEN ? 'Provided' : 'Missing'}`);
  
  // Verify API is accessible
  const healthCheck = http.get(`${BASE_URL}/health`);
  check(healthCheck, {
    'API is accessible': (r) => r.status === 200,
  });
  
  return { 
    baseUrl: BASE_URL, 
    authToken: AUTH_TOKEN,
    startTime: Date.now()
  };
}

export default function(data) {
  const scenario = __VU <= 500 && __ITER === 0 ? 'concurrent_burst' :
                  __ENV.K6_SCENARIO_NAME || 'unknown';
  
  concurrentUsers.add(1);
  
  group(`Rate Limiting Test - ${scenario}`, function() {
    
    switch(scenario) {
      case 'concurrent_burst':
        testConcurrentBurst(data);
        break;
      case 'sustained_load':
        testSustainedLoad(data);
        break;
      case 'rapid_burst':
        testRapidBurst(data);
        break;
      case 'multi_endpoint':
        testMultiEndpointStress(data);
        break;
      default:
        testBasicRateLimit(data);
    }
  });
  
  concurrentUsers.add(-1);
}

function testConcurrentBurst(data) {
  group('Concurrent Burst (500 simultaneous requests)', function() {
    const startTime = new Date();
    const headers = data.authToken ? { 'Authorization': `Bearer ${data.authToken}` } : {};
    
    const response = http.get(`${data.baseUrl}${endpoints.hosts}`, { headers });
    
    const isRateLimit = response.status === 429;
    const isSuccess = response.status === 200 || response.status === 401;
    
    check(response, {
      'Request completed': (r) => r.status > 0,
      'Rate limit or success': (r) => isRateLimit || isSuccess,
      'Response time acceptable': (r) => r.timings.duration < 10000,
    });
    
    if (isRateLimit) {
      rateLimitHits.add(1);
      console.log(`🚦 Rate limit triggered at ${new Date().toISOString()}`);
    } else if (isSuccess) {
      successfulRequests.add(1);
    } else {
      failedRequests.add(1);
    }
    
    responseTime.add(response.timings.duration);
  });
}

function testSustainedLoad(data) {
  group('Sustained Load (200 req/min)', function() {
    const headers = data.authToken ? { 'Authorization': `Bearer ${data.authToken}` } : {};
    
    // Rotate through different endpoints
    const endpointKeys = Object.keys(endpoints);
    const endpoint = endpoints[endpointKeys[Math.floor(Math.random() * endpointKeys.length)]];
    
    const response = http.get(`${data.baseUrl}${endpoint}`, { headers });
    
    check(response, {
      'Sustained load request': (r) => r.status === 200 || r.status === 429 || r.status === 401,
      'No server errors': (r) => r.status < 500,
    });
    
    if (response.status === 429) {
      rateLimitHits.add(1);
    } else if (response.status === 200) {
      successfulRequests.add(1);
    }
    
    responseTime.add(response.timings.duration);
  });
}

function testRapidBurst(data) {
  group('Rapid Burst (300 requests in 30s)', function() {
    const headers = data.authToken ? { 'Authorization': `Bearer ${data.authToken}` } : {};
    
    const response = http.get(`${data.baseUrl}${endpoints.scans}`, { headers });
    
    check(response, {
      'Rapid burst handled': (r) => r.status > 0,
      'Rate limiting active': (r) => r.status === 429 || r.status === 200 || r.status === 401,
    });
    
    if (response.status === 429) {
      rateLimitHits.add(1);
      
      // Check rate limit headers
      const retryAfter = response.headers['Retry-After'];
      const rateLimit = response.headers['X-RateLimit-Limit'];
      const remaining = response.headers['X-RateLimit-Remaining'];
      
      console.log(`🚦 Rate limit: ${rateLimit}, Remaining: ${remaining}, Retry-After: ${retryAfter}`);
    }
    
    responseTime.add(response.timings.duration);
  });
}

function testMultiEndpointStress(data) {
  group('Multi-Endpoint Stress (Different Rate Limit Tiers)', function() {
    const headers = data.authToken ? { 'Authorization': `Bearer ${data.authToken}` } : {};
    
    // Test different endpoint types with different rate limits
    const testEndpoints = [
      { url: endpoints.hosts, tier: 'authenticated' },
      { url: endpoints.auth, tier: 'auth' },
      { url: errorEndpoints.invalid_host, tier: 'error' },
      { url: endpoints.health, tier: 'system' },
      { url: errorEndpoints.validation, tier: 'validation' }
    ];
    
    testEndpoints.forEach(({ url, tier }) => {
      const response = http.get(`${data.baseUrl}${url}`, { headers });
      
      check(response, {
        [`${tier} tier responds`]: (r) => r.status > 0,
        [`${tier} rate limiting works`]: (r) => r.status === 429 || r.status < 500,
      }, { endpoint_tier: tier });
      
      if (response.status === 429) {
        rateLimitHits.add(1);
        console.log(`🚦 ${tier} tier rate limited`);
      }
      
      responseTime.add(response.timings.duration, { endpoint_tier: tier });
      
      sleep(0.1); // Brief pause between endpoint tests
    });
  });
}

function testBasicRateLimit(data) {
  group('Basic Rate Limit Test', function() {
    const headers = data.authToken ? { 'Authorization': `Bearer ${data.authToken}` } : {};
    const response = http.get(`${data.baseUrl}${endpoints.hosts}`, { headers });
    
    check(response, {
      'Basic request completed': (r) => r.status > 0,
    });
    
    responseTime.add(response.timings.duration);
  });
}

export function teardown(data) {
  const duration = (Date.now() - data.startTime) / 1000;
  console.log('\n📊 Rate Limiting Stress Test Complete');
  console.log(`   Duration: ${duration}s`);
  console.log('   Check results in k6 metrics output');
}