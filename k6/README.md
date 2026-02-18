# OpenWatch Load Tests

Performance testing scripts using [k6](https://k6.io/).

## Prerequisites

Install k6:

```bash
# Ubuntu/Debian
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg \
  --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D68
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" \
  | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update && sudo apt-get install k6

# macOS
brew install k6
```

## Test Scripts

| Script | Purpose | Default VUs | Default Duration |
|--------|---------|-------------|-----------------|
| `baseline.js` | Establish p50/p95/p99 latency baselines | 10 | 2 minutes |
| `stress.js` | Find breaking points under increasing load | 10-150 (stages) | 10 minutes |

## Usage

```bash
# Run baseline test against local instance
k6 run k6/baseline.js

# Run against a remote instance
k6 run --env BASE_URL=https://openwatch.example.com k6/baseline.js

# Custom user count and duration
k6 run --env USERS=50 --env DURATION=5m k6/baseline.js

# Run stress test
k6 run k6/stress.js
```

## Results

Baseline test outputs a JSON summary to `k6/results/baseline_summary.json` with p50/p95/p99 latencies and error rate.

## Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Health check p95 | < 500ms | Lightweight endpoint |
| Host list p95 | < 1.5s | Paginated query |
| Scan list p95 | < 2s | Paginated query |
| Overall p95 | < 2s | All endpoints combined |
| Overall p99 | < 5s | All endpoints combined |
| Error rate | < 5% | Under normal load |
