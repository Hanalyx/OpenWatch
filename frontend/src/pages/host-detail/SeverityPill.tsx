// SeverityPill — shared severity badge for compliance surfaces (the
// Top failed rules card on the Overview tab and the Compliance tab's
// rules table). Maps a rule severity onto the prototype's sev badge
// tiers (critical and high share the crit tint, matching the mockup).
//
// Extracted from HostDetailPage.tsx so host-detail/ComplianceTab.tsx
// can reuse it without a page-level import cycle.

export function SeverityPill({ severity }: { severity: string }) {
  const s = severity.toLowerCase();
  const tier =
    s === 'critical' || s === 'high'
      ? { fg: 'var(--ow-crit)', label: s === 'critical' ? 'Crit' : 'High' }
      : s === 'medium'
        ? { fg: 'var(--ow-warn)', label: 'Med' }
        : { fg: 'var(--ow-info)', label: s === 'low' ? 'Low' : 'Info' };
  return (
    <span
      style={{
        flexShrink: 0,
        fontSize: 10,
        fontWeight: 600,
        textTransform: 'uppercase',
        letterSpacing: '0.04em',
        color: tier.fg,
        border: `1px solid color-mix(in oklab, ${tier.fg} 40%, transparent)`,
        borderRadius: 999,
        padding: '2px 8px',
      }}
    >
      {tier.label}
    </span>
  );
}
