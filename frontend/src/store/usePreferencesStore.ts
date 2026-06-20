import { create } from 'zustand';
import { persist } from 'zustand/middleware';

import api from '@/api/client';

// Preferences store — personal UI preferences.
//
// v2.0.0: preferences are now persisted SERVER-SIDE (per-user, follows the
// user across devices) via GET/PATCH /api/v1/users/me/preferences
// (system-user-preferences). localStorage is kept as an instant-load cache
// and offline fallback: the store hydrates from it synchronously, then
// hydrateFromServer() reconciles with the account on app start, and every
// setter writes through to the server (best-effort; a failed PATCH leaves
// the local value in place).

export type Density = 'comfortable' | 'compact';
export type AccentColor = 'info' | 'ok' | 'brand2';
export type LandingPage = 'hosts' | 'dashboard' | 'reports';
export type HostsViewDefault = 'table' | 'cards';
export type DateFormat = 'us12' | 'iso24' | 'long24';

interface PreferencesState {
  density: Density;
  accentColor: AccentColor;
  landingPage: LandingPage;
  hostsViewDefault: HostsViewDefault;
  dateFormat: DateFormat;
  reduceMotion: boolean;

  setDensity: (v: Density) => void;
  setAccentColor: (v: AccentColor) => void;
  setLandingPage: (v: LandingPage) => void;
  setHostsViewDefault: (v: HostsViewDefault) => void;
  setDateFormat: (v: DateFormat) => void;
  setReduceMotion: (v: boolean) => void;

  // Reconcile local state with the server copy. Called once when the
  // authenticated shell mounts. Server values win; keys the server has not
  // set leave the local default in place.
  hydrateFromServer: () => Promise<void>;
}

// The server contract is snake_case; the store is camelCase. These two
// helpers are the only translation points.
type ApiPrefs = {
  hosts_view_default?: HostsViewDefault;
  density?: Density;
  accent_color?: AccentColor;
  landing_page?: LandingPage;
  date_format?: DateFormat;
  reduce_motion?: boolean;
};

function serverToState(p: ApiPrefs): Partial<PreferencesState> {
  const out: Partial<PreferencesState> = {};
  if (p.hosts_view_default) out.hostsViewDefault = p.hosts_view_default;
  if (p.density) out.density = p.density;
  if (p.accent_color) out.accentColor = p.accent_color;
  if (p.landing_page) out.landingPage = p.landing_page;
  if (p.date_format) out.dateFormat = p.date_format;
  if (typeof p.reduce_motion === 'boolean') out.reduceMotion = p.reduce_motion;
  return out;
}

// push writes a single changed key to the server. Best-effort: a network
// error or 401 (anonymous) is swallowed — the local value still stands and
// the next successful session will reconcile.
function push(patch: ApiPrefs): void {
  void api.PATCH('/api/v1/users/me/preferences', { body: patch }).catch(() => {});
}

export const usePreferencesStore = create<PreferencesState>()(
  persist(
    (set) => ({
      density: 'comfortable',
      accentColor: 'info',
      landingPage: 'hosts',
      hostsViewDefault: 'cards',
      dateFormat: 'us12',
      reduceMotion: false,

      setDensity: (density) => {
        set({ density });
        push({ density });
      },
      setAccentColor: (accentColor) => {
        set({ accentColor });
        push({ accent_color: accentColor });
      },
      setLandingPage: (landingPage) => {
        set({ landingPage });
        push({ landing_page: landingPage });
      },
      setHostsViewDefault: (hostsViewDefault) => {
        set({ hostsViewDefault });
        push({ hosts_view_default: hostsViewDefault });
      },
      setDateFormat: (dateFormat) => {
        set({ dateFormat });
        push({ date_format: dateFormat });
      },
      setReduceMotion: (reduceMotion) => {
        set({ reduceMotion });
        push({ reduce_motion: reduceMotion });
      },

      hydrateFromServer: async () => {
        const { data, error } = await api.GET('/api/v1/users/me/preferences');
        if (error || !data) return;
        const patch = serverToState(data as ApiPrefs);
        if (Object.keys(patch).length > 0) set(patch);
      },
    }),
    { name: 'ow-preferences' },
  ),
);
