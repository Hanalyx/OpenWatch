// @spec frontend-live-events
//
// AC traceability (this file):
//
//   AC-01  test('frontend-live-events/AC-01 — ALL_TOPICS is the closed v1.0 set')
//   AC-02  test('frontend-live-events/AC-02 — host.changed invalidates [hosts] + [host, id]')
//   AC-03  test('frontend-live-events/AC-03 — monitoring.band.changed invalidates [hosts] + [host, id]')
//   AC-04  test('frontend-live-events/AC-04 — host.discovered invalidates [hosts] + [host, id]')
//   AC-05  test('frontend-live-events/AC-05 — intelligence.event invalidates [host_intelligence_events, id] only, NOT [hosts]')
//   AC-06  test('frontend-live-events/AC-06 — missing host_id falls back to list-only')
//   AC-07  test('frontend-live-events/AC-07 — source-inspect: exactly one new EventSource(...) call')
//   AC-08  test('frontend-live-events/AC-08 — scan.completed invalidates [hosts] + [host, id]')

import { expect, test, beforeEach, vi } from 'vitest';
import { renderHook } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { ReactNode } from 'react';
import { ALL_TOPICS, useLiveEvents } from '@/hooks/useLiveEvents';
import { useAuthStore } from '@/store/useAuthStore';

// ---------- EventSource stub --------------------------------------------

interface StubListener {
  topic: string;
  fn: (e: MessageEvent) => void;
}

class StubEventSource {
  static instances: StubEventSource[] = [];
  url: string;
  listeners: StubListener[] = [];
  onerror: ((e: Event) => void) | null = null;
  closed = false;

  constructor(url: string, _init?: EventSourceInit) {
    this.url = url;
    StubEventSource.instances.push(this);
  }

  addEventListener(topic: string, fn: (e: MessageEvent) => void) {
    this.listeners.push({ topic, fn });
  }

  removeEventListener(_topic: string, _fn: (e: MessageEvent) => void) {
    // no-op for the stub
  }

  close() {
    this.closed = true;
  }

  // Test helper — fire a topic at all matching listeners.
  fire(topic: string, payload: Record<string, unknown>) {
    const envelope = JSON.stringify({
      kind: topic,
      timestamp: new Date().toISOString(),
      payload,
    });
    const ev = new MessageEvent(topic, { data: envelope });
    for (const l of this.listeners) {
      if (l.topic === topic) l.fn(ev);
    }
  }
}

beforeEach(() => {
  StubEventSource.instances = [];
  (globalThis as unknown as { EventSource: typeof EventSource }).EventSource =
    StubEventSource as unknown as typeof EventSource;
  // Auth store: stub an identity so useLiveEvents opens a connection.
  useAuthStore.setState({
    identity: {
      id: 'test-user',
      username: 'test',
      email: 'test@example.com',
      role: 'admin',
      permissions: ['host:read'],
      mfaEnabled: false,
    },
  });
});

// @ac AC-01
// AC-01: ALL_TOPICS exported as the closed set of 5 topics (v1.1.0
// adds scan.completed).
test('frontend-live-events/AC-01 — ALL_TOPICS is the closed v1.0 set', () => {
  const want = [
    'host.changed',
    'monitoring.band.changed',
    'host.discovered',
    'intelligence.event',
    'scan.completed',
  ];
  expect([...ALL_TOPICS]).toEqual(want);
  expect(ALL_TOPICS.length).toBe(5);
});

// Helper to mount the hook and return the stub + spies.
function mountHook() {
  const qc = new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: 0 },
      mutations: { retry: false },
    },
  });
  const spy = vi.spyOn(qc, 'invalidateQueries');
  const Wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
  renderHook(() => useLiveEvents(), { wrapper: Wrapper });
  const es = StubEventSource.instances[StubEventSource.instances.length - 1];
  if (!es) throw new Error('useLiveEvents did not open an EventSource');
  return { es, spy };
}

// @ac AC-02
test('frontend-live-events/AC-02 — host.changed invalidates [hosts] + [host, id]', () => {
  const { es, spy } = mountHook();
  es.fire('host.changed', { host_id: 'h-aaa' });
  const calls = spy.mock.calls.map((c) => c[0]?.queryKey);
  expect(calls).toContainEqual(['hosts']);
  expect(calls).toContainEqual(['host', 'h-aaa']);
});

// @ac AC-03
test('frontend-live-events/AC-03 — monitoring.band.changed invalidates [hosts] + [host, id]', () => {
  const { es, spy } = mountHook();
  es.fire('monitoring.band.changed', { host_id: 'h-bbb' });
  const calls = spy.mock.calls.map((c) => c[0]?.queryKey);
  expect(calls).toContainEqual(['hosts']);
  expect(calls).toContainEqual(['host', 'h-bbb']);
});

// @ac AC-04
test('frontend-live-events/AC-04 — host.discovered invalidates [hosts] + [host, id]', () => {
  const { es, spy } = mountHook();
  es.fire('host.discovered', { host_id: 'h-ccc' });
  const calls = spy.mock.calls.map((c) => c[0]?.queryKey);
  expect(calls).toContainEqual(['hosts']);
  expect(calls).toContainEqual(['host', 'h-ccc']);
});

// @ac AC-08
test('frontend-live-events/AC-08 — scan.completed invalidates [hosts] + [host, id]', () => {
  const { es, spy } = mountHook();
  es.fire('scan.completed', { host_id: 'h-scan' });
  const calls = spy.mock.calls.map((c) => c[0]?.queryKey);
  expect(calls).toContainEqual(['hosts']);
  expect(calls).toContainEqual(['host', 'h-scan']);
});

// @ac AC-05
test('frontend-live-events/AC-05 — intelligence.event invalidates [host_intelligence_events, id] only', () => {
  const { es, spy } = mountHook();
  es.fire('intelligence.event', { host_id: 'h-ddd' });
  const calls = spy.mock.calls.map((c) => c[0]?.queryKey);
  expect(calls).toContainEqual(['host_intelligence_events', 'h-ddd']);
  expect(calls).not.toContainEqual(['hosts']);
});

// @ac AC-06
test('frontend-live-events/AC-06 — missing host_id falls back to list-only', () => {
  const { es, spy } = mountHook();
  es.fire('host.discovered', {});
  const calls = spy.mock.calls.map((c) => c[0]?.queryKey);
  expect(calls).toContainEqual(['hosts']);
  // Must NOT invalidate ["host", undefined] — defensive.
  const hostKeyed = calls.filter((k) => Array.isArray(k) && k[0] === 'host');
  expect(hostKeyed).toEqual([]);
});

// @ac AC-07
test('frontend-live-events/AC-07 — source-inspect: exactly one new EventSource(...) call', () => {
  const src = readFileSync(resolve(process.cwd(), 'src/hooks/useLiveEvents.ts'), 'utf8');
  const matches = src.match(/new\s+EventSource\s*\(/g) ?? [];
  expect(matches.length).toBe(1);
});
