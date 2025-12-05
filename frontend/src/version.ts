/**
 * OpenWatch Version Module
 *
 * Frontend version information sourced from build-time environment variable.
 * The VITE_APP_VERSION is injected during the build process from the VERSION file.
 *
 * Usage:
 *   import { APP_VERSION, CODENAME, getVersionDisplay } from './version';
 *   console.log(getVersionDisplay()); // "OpenWatch v0.1.0 Eyrie"
 *
 * See docs/core/VERSIONING.md for versioning plan.
 */

/**
 * Application version from build-time environment variable.
 * Falls back to '0.0.0-unknown' if not set.
 */
export const APP_VERSION = import.meta.env.VITE_APP_VERSION || '0.0.0-unknown';

/**
 * Current release codename.
 * Updated when major version changes.
 */
export const CODENAME = 'Eyrie';

/**
 * API version for header-based versioning (future use).
 */
export const API_VERSION = '1';

/**
 * Git commit hash (short form) from build-time.
 * Only available in production builds with CI/CD.
 */
export const GIT_COMMIT = import.meta.env.VITE_GIT_COMMIT || null;

/**
 * Build date from CI/CD pipeline.
 * Only available in production builds.
 */
export const BUILD_DATE = import.meta.env.VITE_BUILD_DATE || null;

/**
 * Get formatted version display string.
 * @returns Version string like "OpenWatch v0.1.0 Eyrie"
 */
export function getVersionDisplay(): string {
  return `OpenWatch v${APP_VERSION} ${CODENAME}`;
}

/**
 * Get version info object (matches backend /api/version response).
 */
export function getVersionInfo(): {
  version: string;
  codename: string;
  api_version: string;
  git_commit: string | null;
  build_date: string | null;
} {
  return {
    version: APP_VERSION,
    codename: CODENAME,
    api_version: API_VERSION,
    git_commit: GIT_COMMIT,
    build_date: BUILD_DATE,
  };
}

/**
 * Check if this is a development build.
 */
export function isDevelopmentBuild(): boolean {
  return APP_VERSION === '0.0.0-unknown' || import.meta.env.DEV;
}
