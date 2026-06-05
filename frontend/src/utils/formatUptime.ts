// formatUptime — pure, timezone-independent uptime formatter for the
// host detail System card. Maps a uptime-in-seconds integer (sourced
// from host_intelligence_state.snapshot.uptime_seconds) to a compact
// human-readable string. Bucketing favors operational signal:
//   <1m  -> just rebooted, signal-worthy
//   m    -> recent boot
//   h Ym -> normal day-of-operation
//   d Yh -> long-running host
//
// Spec: frontend-host-detail-system-card C-01 / AC-01.

export function formatUptime(seconds: number | null | undefined): string {
  if (seconds == null) return '—';
  if (!Number.isFinite(seconds) || seconds < 0) return '—';
  const s = Math.floor(seconds);
  if (s < 60) return '<1m';
  if (s < 3600) {
    const m = Math.floor(s / 60);
    return `${m}m`;
  }
  if (s < 86400) {
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    return `${h}h ${m}m`;
  }
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  return `${d}d ${h}h`;
}
