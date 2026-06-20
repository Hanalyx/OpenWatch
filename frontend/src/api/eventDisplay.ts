// Shared display helpers for the unified activity feed (the
// /api/v1/activity row shape). One source of truth so every surface
// renders source, severity, and time the same way instead of each one
// rolling its own — and never leaking a raw enum to the UI. The row's
// title/summary are already human-readable from the backend
// (system-activity v1.2.0); these helpers cover the surrounding chrome.
//
// Spec: frontend-activity v1.1.0.

export type ActivitySource = 'alert' | 'transaction' | 'intelligence' | 'audit' | 'monitoring';
export type ActivitySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Tone = 'crit' | 'warn' | 'info';

const SOURCE_LABEL: Record<string, string> = {
  alert: 'Alert',
  transaction: 'Compliance',
  intelligence: 'Intelligence',
  audit: 'Audit',
  monitoring: 'Monitoring',
};

// sourceLabel turns the feed source enum into a friendly word. An unknown
// source title-cases gracefully so a new source never renders raw.
export function sourceLabel(source: string): string {
  return SOURCE_LABEL[source] ?? titleCase(source);
}

const SEVERITY_LABEL: Record<string, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

export function severityLabel(severity: string): string {
  return SEVERITY_LABEL[severity] ?? titleCase(severity);
}

// severityTone buckets a severity onto the three display tones used across
// the app (crit/warn/info). Canonical: critical+high -> crit, medium ->
// warn, low+info -> info. Replaces the per-surface copies that disagreed on
// where "low" landed.
export function severityTone(severity: string): Tone {
  if (severity === 'critical' || severity === 'high') return 'crit';
  if (severity === 'medium') return 'warn';
  return 'info';
}

// relativeTime renders a compact "time ago" for a row's occurred_at, with an
// absolute-date fallback beyond 30 days. Avoids the em-dash in the invalid
// case (UI copy uses none).
export function relativeTime(iso: string): string {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '';
  const minutes = Math.max(0, Math.round((Date.now() - t) / 60_000));
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days <= 30) return `${days}d ago`;
  return new Date(iso).toLocaleDateString(undefined, {
    month: 'numeric',
    day: 'numeric',
    year: 'numeric',
  });
}

function titleCase(s: string): string {
  if (!s) return s;
  return s.charAt(0).toUpperCase() + s.slice(1);
}
