#!/usr/bin/env python3
"""
Rate Limiting Monitor
Real-time monitoring of rate limiting effectiveness and metrics

Usage:
    python3 rate_limit_monitor.py
    python3 rate_limit_monitor.py --interval 5 --duration 300
"""
import asyncio
import aiohttp
import argparse
import json
import time
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Any
from collections import defaultdict, deque
import logging
import sys
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class RateLimitMetric:
    timestamp: datetime
    endpoint: str
    status_code: int
    response_time: float
    rate_limited: bool
    ip_hash: str

class RateLimitMonitor:
    """Real-time rate limiting monitor"""

    def __init__(self, base_url: str = "http://localhost:8000", interval: int = 10):
        self.base_url = base_url
        self.interval = interval
        self.session = None
        self.metrics: List[RateLimitMetric] = []
        self.running = True

        # Tracking counters
        self.counters = defaultdict(int)
        self.rate_limit_history = deque(maxlen=100)
        self.response_times = deque(maxlen=100)

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def test_endpoint(self, endpoint: str, method: str = 'GET', **kwargs) -> RateLimitMetric:
        """Test single endpoint and return metrics"""
        start_time = time.time()
        try:
            async with self.session.request(method, f"{self.base_url}{endpoint}", **kwargs) as response:
                response_time = time.time() - start_time

                return RateLimitMetric(
                    timestamp=datetime.now(),
                    endpoint=endpoint,
                    status_code=response.status,
                    response_time=response_time,
                    rate_limited=response.status == 429,
                    ip_hash="monitor"
                )
        except Exception as e:
            return RateLimitMetric(
                timestamp=datetime.now(),
                endpoint=endpoint,
                status_code=0,
                response_time=time.time() - start_time,
                rate_limited=False,
                ip_hash="monitor"
            )

    async def collect_metrics(self):
        """Collect metrics from various endpoints"""
        endpoints = [
            ('/health', 'GET'),
            ('/api/hosts/', 'GET'),
            ('/api/scans/', 'GET'),
            ('/api/system/credentials', 'GET'),
        ]

        tasks = []
        for endpoint, method in endpoints:
            tasks.append(self.test_endpoint(endpoint, method))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, RateLimitMetric):
                self.metrics.append(result)
                self._update_counters(result)

    def _update_counters(self, metric: RateLimitMetric):
        """Update internal counters and tracking"""
        self.counters['total_requests'] += 1
        self.counters[f'status_{metric.status_code}'] += 1

        if metric.rate_limited:
            self.counters['rate_limited'] += 1
            self.rate_limit_history.append(metric.timestamp)
        else:
            self.counters['successful'] += 1

        self.response_times.append(metric.response_time)
        self.counters[f'endpoint_{metric.endpoint}'] += 1

    def _calculate_rate_limit_trend(self) -> Dict[str, Any]:
        """Calculate rate limiting trends"""
        now = datetime.now()
        recent_limits = [
            ts for ts in self.rate_limit_history
            if (now - ts).total_seconds() < 300  # Last 5 minutes
        ]

        return {
            'rate_limits_last_5min': len(recent_limits),
            'rate_limit_frequency': len(recent_limits) / 5 if recent_limits else 0,  # per minute
            'last_rate_limit': max(self.rate_limit_history).isoformat() if self.rate_limit_history else None
        }

    def _calculate_performance_metrics(self) -> Dict[str, Any]:
        """Calculate performance metrics"""
        if not self.response_times:
            return {}

        recent_times = list(self.response_times)[-50:]  # Last 50 requests

        return {
            'avg_response_time': statistics.mean(recent_times),
            'median_response_time': statistics.median(recent_times),
            'max_response_time': max(recent_times),
            'min_response_time': min(recent_times),
            'p95_response_time': statistics.quantiles(recent_times, n=20)[18] if len(recent_times) > 20 else max(recent_times)
        }

    def print_status(self):
        """Print current monitoring status"""
        print(f"\033[2J\033[H")  # Clear screen and move cursor to top

        print(f"{'='*80}")
        print(f"RATE LIMITING MONITOR - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*80}")
        print(f"Monitoring: {self.base_url}")
        print(f"Interval: {self.interval} seconds")
        print(f"Total Requests: {self.counters['total_requests']}")

        # Status Code Distribution
        print(f"\n📊 Status Code Distribution:")
        status_codes = [key for key in self.counters.keys() if key.startswith('status_')]
        for status_key in sorted(status_codes):
            code = status_key.replace('status_', '')
            count = self.counters[status_key]
            percentage = (count / max(self.counters['total_requests'], 1)) * 100

            if code == '200':
                emoji = "✅"
            elif code == '429':
                emoji = "🚫"
            elif code.startswith('4'):
                emoji = "⚠️"
            elif code.startswith('5'):
                emoji = "❌"
            else:
                emoji = "ℹ️"

            print(f"  {emoji} {code}: {count} ({percentage:.1f}%)")

        # Rate Limiting Status
        rate_limit_info = self._calculate_rate_limit_trend()
        print(f"\n🛡️  Rate Limiting Status:")
        print(f"  Total Rate Limited: {self.counters['rate_limited']}")
        print(f"  Rate Limits (5min): {rate_limit_info['rate_limits_last_5min']}")
        print(f"  Rate Limit Frequency: {rate_limit_info['rate_limit_frequency']:.2f}/min")

        if rate_limit_info['last_rate_limit']:
            last_limit_time = datetime.fromisoformat(rate_limit_info['last_rate_limit'])
            time_since = (datetime.now() - last_limit_time).total_seconds()
            print(f"  Last Rate Limit: {time_since:.0f}s ago")

        # Performance Metrics
        perf_metrics = self._calculate_performance_metrics()
        if perf_metrics:
            print(f"\n⚡ Performance Metrics:")
            print(f"  Avg Response Time: {perf_metrics['avg_response_time']:.3f}s")
            print(f"  Median Response Time: {perf_metrics['median_response_time']:.3f}s")
            print(f"  95th Percentile: {perf_metrics['p95_response_time']:.3f}s")
            print(f"  Max Response Time: {perf_metrics['max_response_time']:.3f}s")

        # Endpoint Activity
        print(f"\n🔗 Endpoint Activity:")
        endpoint_keys = [key for key in self.counters.keys() if key.startswith('endpoint_')]
        for endpoint_key in sorted(endpoint_keys):
            endpoint = endpoint_key.replace('endpoint_', '')
            count = self.counters[endpoint_key]
            print(f"  {endpoint}: {count}")

        # Rate Limiting Health Assessment
        total = max(self.counters['total_requests'], 1)
        rate_limit_percentage = (self.counters['rate_limited'] / total) * 100
        successful_percentage = (self.counters['successful'] / total) * 100

        print(f"\n🏥 System Health:")
        if rate_limit_percentage < 10 and successful_percentage > 80:
            health_status = "🟢 HEALTHY"
        elif rate_limit_percentage < 25 and successful_percentage > 60:
            health_status = "🟡 WARNING"
        else:
            health_status = "🔴 CRITICAL"

        print(f"  Overall Status: {health_status}")
        print(f"  Success Rate: {successful_percentage:.1f}%")
        print(f"  Rate Limit Rate: {rate_limit_percentage:.1f}%")

        print(f"\n💡 Recommendations:")
        if rate_limit_percentage > 20:
            print("  - High rate limiting detected - review client behavior")
        if perf_metrics and perf_metrics['avg_response_time'] > 2.0:
            print("  - High response times detected - check server performance")
        if self.counters['rate_limited'] == 0 and self.counters['total_requests'] > 50:
            print("  - No rate limiting observed - verify limits are active")

        print(f"\n{'='*80}")
        print("Press Ctrl+C to stop monitoring")

    async def start_monitoring(self, duration: int = None):
        """Start continuous monitoring"""
        start_time = time.time()

        try:
            while self.running:
                await self.collect_metrics()
                self.print_status()

                # Check duration
                if duration and (time.time() - start_time) >= duration:
                    break

                await asyncio.sleep(self.interval)

        except KeyboardInterrupt:
            print(f"\n\n{'='*80}")
            print("Monitoring stopped by user")
            self._print_final_summary()
        except Exception as e:
            print(f"\nError during monitoring: {e}")
        finally:
            self.running = False

    def _print_final_summary(self):
        """Print final monitoring summary"""
        print(f"{'='*80}")
        print("FINAL MONITORING SUMMARY")
        print(f"{'='*80}")

        if self.metrics:
            print(f"Total monitoring duration: {len(self.metrics) * self.interval} seconds")
            print(f"Total requests monitored: {self.counters['total_requests']}")
            print(f"Rate limited requests: {self.counters['rate_limited']}")
            print(f"Successful requests: {self.counters['successful']}")

            rate_limit_percentage = (self.counters['rate_limited'] / max(self.counters['total_requests'], 1)) * 100
            print(f"Rate limiting effectiveness: {rate_limit_percentage:.2f}%")

            perf_metrics = self._calculate_performance_metrics()
            if perf_metrics:
                print(f"Average response time: {perf_metrics['avg_response_time']:.3f}s")

        print(f"{'='*80}")

async def main():
    parser = argparse.ArgumentParser(description='Rate Limiting Real-time Monitor')
    parser.add_argument('--url', default='http://localhost:8000', help='Backend URL to monitor')
    parser.add_argument('--interval', type=int, default=10, help='Monitoring interval in seconds')
    parser.add_argument('--duration', type=int, help='Total monitoring duration in seconds')

    args = parser.parse_args()

    print(f"Starting rate limiting monitor...")
    print(f"URL: {args.url}")
    print(f"Interval: {args.interval} seconds")
    if args.duration:
        print(f"Duration: {args.duration} seconds")
    print("Press Ctrl+C to stop\n")

    async with RateLimitMonitor(args.url, args.interval) as monitor:
        await monitor.start_monitoring(args.duration)

if __name__ == "__main__":
    asyncio.run(main())
