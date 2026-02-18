/**
 * OpenWatch Performance Baseline - k6 Load Test
 *
 * Establishes p50/p95/p99 latency baselines for core API endpoints.
 *
 * Usage:
 *   k6 run k6/baseline.js
 *   k6 run --env BASE_URL=https://openwatch.example.com k6/baseline.js
 *   k6 run --env USERS=50 --env DURATION=5m k6/baseline.js
 *
 * Environment Variables:
 *   BASE_URL    - OpenWatch API base URL (default: http://localhost:8000)
 *   USERS       - Number of virtual users (default: 10)
 *   DURATION    - Test duration (default: 2m)
 *   USERNAME    - Login username (default: admin)
 *   PASSWORD    - Login password (default: admin)
 */

import http from "k6/http";
import { check, sleep, group } from "k6";
import { Rate, Trend } from "k6/metrics";

// Custom metrics
const errorRate = new Rate("errors");
const loginDuration = new Trend("login_duration", true);
const healthDuration = new Trend("health_duration", true);
const hostListDuration = new Trend("host_list_duration", true);
const scanListDuration = new Trend("scan_list_duration", true);

// Configuration
const BASE_URL = __ENV.BASE_URL || "http://localhost:8000";
const USERNAME = __ENV.USERNAME || "admin";
const PASSWORD = __ENV.PASSWORD || "admin";

export const options = {
  stages: [
    { duration: "30s", target: parseInt(__ENV.USERS) || 10 }, // Ramp up
    { duration: __ENV.DURATION || "2m", target: parseInt(__ENV.USERS) || 10 }, // Steady state
    { duration: "30s", target: 0 }, // Ramp down
  ],
  thresholds: {
    http_req_duration: ["p(95)<2000", "p(99)<5000"], // 95th < 2s, 99th < 5s
    errors: ["rate<0.05"], // Error rate < 5%
    health_duration: ["p(95)<500"], // Health check < 500ms at p95
    host_list_duration: ["p(95)<1500"], // Host list < 1.5s at p95
    scan_list_duration: ["p(95)<2000"], // Scan list < 2s at p95
  },
};

// Authenticate and return token
function login() {
  const res = http.post(
    `${BASE_URL}/api/auth/login`,
    JSON.stringify({ username: USERNAME, password: PASSWORD }),
    { headers: { "Content-Type": "application/json" } }
  );

  loginDuration.add(res.timings.duration);

  const success = check(res, {
    "login status 200": (r) => r.status === 200,
    "login has token": (r) => {
      try {
        return JSON.parse(r.body).access_token !== undefined;
      } catch {
        return false;
      }
    },
  });

  if (!success) {
    errorRate.add(1);
    return null;
  }

  errorRate.add(0);
  return JSON.parse(res.body).access_token;
}

// Create authenticated headers
function authHeaders(token) {
  return {
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  };
}

export default function () {
  // Login once per VU iteration
  const token = login();
  if (!token) {
    sleep(1);
    return;
  }

  const params = authHeaders(token);

  group("Health Checks", function () {
    const res = http.get(`${BASE_URL}/health`, params);
    healthDuration.add(res.timings.duration);
    check(res, { "health status 200": (r) => r.status === 200 });
    errorRate.add(res.status !== 200 ? 1 : 0);
  });

  sleep(0.5);

  group("Host Operations", function () {
    // List hosts
    const res = http.get(`${BASE_URL}/api/hosts?page=1&per_page=20`, params);
    hostListDuration.add(res.timings.duration);
    check(res, {
      "host list status 200": (r) => r.status === 200,
    });
    errorRate.add(res.status !== 200 ? 1 : 0);
  });

  sleep(0.5);

  group("Scan Operations", function () {
    // List scans
    const res = http.get(`${BASE_URL}/api/scans?page=1&per_page=20`, params);
    scanListDuration.add(res.timings.duration);
    check(res, {
      "scan list status 200": (r) => r.status === 200,
    });
    errorRate.add(res.status !== 200 ? 1 : 0);
  });

  sleep(0.5);

  group("Compliance Posture", function () {
    const res = http.get(`${BASE_URL}/api/compliance/posture`, params);
    check(res, {
      "posture status 200 or 403": (r) =>
        r.status === 200 || r.status === 403,
    });
  });

  sleep(0.5);

  group("System Info", function () {
    // Version
    http.get(`${BASE_URL}/api/system/version`, params);

    // Health summary
    http.get(`${BASE_URL}/api/system/health/summary`, params);
  });

  sleep(1);
}

export function handleSummary(data) {
  const summary = {
    timestamp: new Date().toISOString(),
    config: {
      base_url: BASE_URL,
      vus: parseInt(__ENV.USERS) || 10,
      duration: __ENV.DURATION || "2m",
    },
    results: {
      http_req_duration_p50: data.metrics.http_req_duration
        ? data.metrics.http_req_duration.values["p(50)"]
        : null,
      http_req_duration_p95: data.metrics.http_req_duration
        ? data.metrics.http_req_duration.values["p(95)"]
        : null,
      http_req_duration_p99: data.metrics.http_req_duration
        ? data.metrics.http_req_duration.values["p(99)"]
        : null,
      error_rate: data.metrics.errors
        ? data.metrics.errors.values.rate
        : null,
      total_requests: data.metrics.http_reqs
        ? data.metrics.http_reqs.values.count
        : null,
    },
  };

  return {
    "k6/results/baseline_summary.json": JSON.stringify(summary, null, 2),
    stdout: textSummary(data, { indent: " ", enableColors: true }),
  };
}

// Helper for text summary
function textSummary(data) {
  let output = "\n=== OpenWatch Performance Baseline ===\n\n";

  if (data.metrics.http_req_duration) {
    const d = data.metrics.http_req_duration.values;
    output += `HTTP Request Duration:\n`;
    output += `  p50: ${d["p(50)"]?.toFixed(2)}ms\n`;
    output += `  p95: ${d["p(95)"]?.toFixed(2)}ms\n`;
    output += `  p99: ${d["p(99)"]?.toFixed(2)}ms\n\n`;
  }

  if (data.metrics.errors) {
    output += `Error Rate: ${(data.metrics.errors.values.rate * 100).toFixed(2)}%\n`;
  }

  if (data.metrics.http_reqs) {
    output += `Total Requests: ${data.metrics.http_reqs.values.count}\n`;
    output += `Requests/sec: ${data.metrics.http_reqs.values.rate?.toFixed(2)}\n`;
  }

  return output;
}
