import { create } from 'zustand';
import { persist } from 'zustand/middleware';

// Preferences store — personal UI preferences persisted to localStorage.
// No backend wiring; preferences live entirely in the browser.

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

      setDensity: (density) => set({ density }),
      setAccentColor: (accentColor) => set({ accentColor }),
      setLandingPage: (landingPage) => set({ landingPage }),
      setHostsViewDefault: (hostsViewDefault) => set({ hostsViewDefault }),
      setDateFormat: (dateFormat) => set({ dateFormat }),
      setReduceMotion: (reduceMotion) => set({ reduceMotion }),
    }),
    { name: 'ow-preferences' },
  ),
);
