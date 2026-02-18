/**
 * OpenWatch Stress Test - k6 Load Test
 *
 * Tests system behavior under increasing load to find breaking points.
 *
 * Usage:
 *   k6 run k6/stress.js
 *   k6 run --env BASE_URL=https://openwatch.example.com k6/stress.js
 *
 * Environment Variables:
 *   BASE_URL    - OpenWatch API base URL (default: http://localhost:8000)
 *   USERNAME    - Login username (default: admin)
 *   PASSWORD    - Login password (default: admin)
 */

import http from "k6/http";
import { check, sleep, group } from "k6";
import { Rate } from "k6/metrics";

const errorRate = new Rate("errors");

const BASE_URL = __ENV.BASE_URL || "http://localhost:8000";
const USERNAME = __ENV.USERNAME || "admin";
const PASSWORD = __ENV.PASSWORD || "admin";

export const options = {
  stages: [
    { duration: "1m", target: 10 }, // Warm up
    { duration: "2m", target: 25 }, // Low load
    { duration: "2m", target: 50 }, // Medium load
    { duration: "2m", target: 100 }, // High load
    { duration: "2m", target: 150 }, // Stress load
    { duration: "1m", target: 0 }, // Recovery
  ],
  thresholds: {
    http_req_duration: ["p(95)<5000"], // Relaxed threshold for stress
    errors: ["rate<0.15"], // Allow up to 15% errors under stress
  },
};

function getToken() {
  const res = http.post(
    `${BASE_URL}/api/auth/login`,
    JSON.stringify({ username: USERNAME, password: PASSWORD }),
    { headers: { "Content-Type": "application/json" } }
  );

  if (res.status === 200) {
    try {
      return JSON.parse(res.body).access_token;
    } catch {
      return null;
    }
  }
  return null;
}

export default function () {
  const token = getToken();
  if (!token) {
    errorRate.add(1);
    sleep(1);
    return;
  }

  const params = {
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  };

  // Mix of read operations (simulates typical usage)
  group("Read Operations", function () {
    // Health check (lightweight)
    const healthRes = http.get(`${BASE_URL}/health`);
    check(healthRes, { "health ok": (r) => r.status === 200 });
    errorRate.add(healthRes.status !== 200 ? 1 : 0);

    sleep(0.2);

    // Host list (medium weight)
    const hostRes = http.get(
      `${BASE_URL}/api/hosts?page=1&per_page=20`,
      params
    );
    check(hostRes, { "hosts ok": (r) => r.status === 200 });
    errorRate.add(hostRes.status !== 200 ? 1 : 0);

    sleep(0.2);

    // Scan list (medium weight)
    const scanRes = http.get(
      `${BASE_URL}/api/scans?page=1&per_page=20`,
      params
    );
    check(scanRes, { "scans ok": (r) => r.status === 200 });
    errorRate.add(scanRes.status !== 200 ? 1 : 0);

    sleep(0.2);

    // Host groups (lightweight)
    const groupRes = http.get(`${BASE_URL}/api/host-groups/`, params);
    check(groupRes, {
      "groups ok": (r) => r.status === 200,
    });
    errorRate.add(groupRes.status !== 200 ? 1 : 0);
  });

  sleep(0.5 + Math.random());
}
