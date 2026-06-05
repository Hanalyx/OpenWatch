// osLabel — pure mapping from the denormalized hosts.os_family column
// (populated by system-host-discovery via Kensa) onto the user-facing
// OS display label used by HostsListPage and HostDetailPage. The
// mapping is intentionally closed; unrecognized families fall through
// to "Unknown" so a pre-Discovery host or an unsupported distro never
// gets silently labelled with a confidently-wrong guess.
//
// Spec: frontend-host-list-os C-02 + AC-01..AC-03.

const KENSA_FAMILY_TO_LABEL: Record<string, string> = {
  rhel: 'RHEL',
  centos: 'RHEL',
  rocky: 'RHEL',
  almalinux: 'RHEL',
  ubuntu: 'Ubuntu',
  debian: 'Debian',
  opensuse: 'SUSE',
  sles: 'SUSE',
};

export function osDisplayLabel(family: string | null | undefined): string {
  if (!family) return 'Unknown';
  const key = family.trim().toLowerCase();
  if (!key) return 'Unknown';
  return KENSA_FAMILY_TO_LABEL[key] ?? 'Unknown';
}
