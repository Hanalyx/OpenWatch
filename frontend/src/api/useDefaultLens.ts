import { useQuery } from '@tanstack/react-query';
import api from '@/api/client';

// The org-wide default compliance lens: a framework FAMILY id (e.g. "stig")
// or "" for All rules. Cached under ['compliance-config']; the score
// surfaces (dashboard/hosts avg compliance, host detail) read it to default
// their framework projection. A read failure degrades to "" (All rules).
export function useDefaultLens(): string {
  const q = useQuery({
    queryKey: ['compliance-config'],
    queryFn: async () => {
      const { data, response } = await api.GET('/api/v1/system/compliance/config');
      if (!response.ok) return { default_framework: '' };
      return data ?? { default_framework: '' };
    },
    staleTime: 60_000,
  });
  return q.data?.default_framework ?? '';
}

// familyOf mirrors the Go framework.FamilyOf: strip a trailing OS suffix so a
// corpus key maps to its family (stig_rhel9 -> stig); OS-agnostic keys are
// their own family. Used to resolve a family default to a host's own key and
// to mark the active "View as" chip.
const OS_SUFFIX = /_(rhel|ubuntu)[0-9]+$/;
export function familyOf(key: string): string {
  return key.replace(OS_SUFFIX, '');
}

// resolveLensForHost maps the configured default (a family or key, or "") to
// the concrete corpus key to use for THIS host, given the host's available
// framework keys. Returns "" (All rules) when the default is empty or the
// host has no key in that family.
export function resolveLensForHost(defaultLens: string, availableKeys: string[]): string {
  if (!defaultLens) return '';
  if (availableKeys.includes(defaultLens)) return defaultLens; // already a key
  const match = availableKeys.find((k) => familyOf(k) === defaultLens);
  return match ?? '';
}
