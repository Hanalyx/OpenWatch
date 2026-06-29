import { useEffect, useState } from 'react';
import api from '@/api/client';

// useVersion returns the running binary's version (e.g. "0.2.0") from
// GET /api/v1/version, the anonymous build-metadata endpoint. The version is
// always read live from the server — never hardcoded in the UI — so the landing
// and login pages reflect whatever release is actually deployed. Returns null
// until the fetch resolves (callers render the codename alone in the meantime).
export function useVersion(): string | null {
  const [version, setVersion] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const { data } = await api.GET('/api/v1/version');
        // The product version is the `openwatch` field (e.g. "0.2.0"); `kensa`,
        // `go`, `commit`, `build_time` are the other build-metadata fields.
        if (!cancelled && data?.openwatch) setVersion(data.openwatch);
      } catch {
        // Leave null on failure; the UI degrades to the codename only.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);
  return version;
}
