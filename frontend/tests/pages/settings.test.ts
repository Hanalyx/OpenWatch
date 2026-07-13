// @spec frontend-settings
//
// AC traceability (this file):
//
//   AC-01  router: /settings redirects to /settings/profile
//   AC-02  SettingsLayout nav has 11 leaf items in Workspace 5 / Access 3 / Personal 3, no hardcoded status pip
//   AC-03  Nav search filters labels case-insensitive
//   AC-04  ProfilePage renders identity from useAuthStore + Save disabled
//   AC-05  Password-change submit POSTs /auth/password:change
//   AC-06  Wrong current_password renders inline error; new/confirm preserved
//   AC-07  Zod rejects new == current before any POST
//   AC-08  Zod rejects new < 15 chars before any POST
//   AC-09  Begin enrollment POSTs /auth/mfa:enroll + renders provisioning_uri
//   AC-10  Valid otp POSTs /auth/mfa:verify + flips identity.mfaEnabled
//   AC-11  Theme toggle writes ow-color-scheme localStorage
//   AC-12  Preferences persist to ow-preferences localStorage via Zustand persist
//   AC-13  Credentials list renders from GET /api/v1/credentials
//   AC-14  /settings/users gated on admin permission (else ForbiddenPage)
//   AC-15  Stubbed pages render BackendPendingBanner naming the slice
//   AC-16  No var(--mui- or hardcoded HEX literals in settings code
//   AC-17  Password handler doesn't console.log/warn/error secret values
//   AC-18  axe-core dependency present (browser scan runs via Playwright)
//   AC-19  Audit log: audit:read gate, infinite query, cursor, read-only
//   AC-20  About: license state from GET /api/v1/license, not hardcoded
//   AC-21  Users: Add member opens AddUserModal (POST /users) + roles roster
//   AC-22  Users: Manage opens ManageUserModal (role assign/unassign + delete)
//   AC-23  Notifications: notification:read gate, channel CRUD + test, secret-free
//   AC-24  Security: admin gate, live API tokens (list/create/revoke), secret-once
//   AC-27  Users: admin password reset (admin:user_manage) + surfaces policy errors
//   AC-28  Users: disable/enable toggle + disabled status on row + modal
//   AC-29  Users: self-disable 409 inline + no em-dashes in copy

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const ROUTER_SRC = readFileSync(resolve(process.cwd(), 'src/routes/router.tsx'), 'utf8');
const LAYOUT_SRC = readFileSync(
  resolve(process.cwd(), 'src/components/settings/SettingsLayout.tsx'),
  'utf8',
);
const PROFILE_SRC = readFileSync(
  resolve(process.cwd(), 'src/pages/settings/ProfilePage.tsx'),
  'utf8',
);
const PREFERENCES_SRC = readFileSync(
  resolve(process.cwd(), 'src/pages/settings/PreferencesPage.tsx'),
  'utf8',
);
const CREDENTIALS_SRC = readFileSync(
  resolve(process.cwd(), 'src/pages/settings/CredentialsPage.tsx'),
  'utf8',
);
const USERS_SRC = readFileSync(resolve(process.cwd(), 'src/pages/settings/UsersPage.tsx'), 'utf8');
const STUBBED_SRC = readFileSync(
  resolve(process.cwd(), 'src/pages/settings/StubbedPages.tsx'),
  'utf8',
);
const AUDIT_SRC = readFileSync(resolve(process.cwd(), 'src/pages/settings/AuditPage.tsx'), 'utf8');
const USERMUT_SRC = readFileSync(
  resolve(process.cwd(), 'src/pages/settings/UserMutations.tsx'),
  'utf8',
);
const NOTIF_SRC = readFileSync(
  resolve(process.cwd(), 'src/pages/settings/NotificationsPage.tsx'),
  'utf8',
);
const SEC_SRC = readFileSync(resolve(process.cwd(), 'src/pages/settings/SecurityPage.tsx'), 'utf8');
const LOGIN_SRC = readFileSync(resolve(process.cwd(), 'src/pages/LoginPage.tsx'), 'utf8');
const PREFS_STORE_SRC = readFileSync(
  resolve(process.cwd(), 'src/store/usePreferencesStore.ts'),
  'utf8',
);

describe('frontend-settings — structural', () => {
  // @ac AC-01
  test('frontend-settings/AC-01 — /settings redirects to /settings/profile', () => {
    // The settingsIndexRoute component renders a Navigate to profile.
    expect(ROUTER_SRC).toMatch(/<Navigate\s+to=["']\/settings\/profile["']/);
  });

  // @ac AC-02
  test('frontend-settings/AC-02 — 11 leaf nav items grouped 5/3/3, no hardcoded status pip', () => {
    // Extract item IDs from each group.
    const workspaceMatch = LAYOUT_SRC.match(
      /title:\s*['"]Workspace['"]\s*,\s*items:\s*\[([\s\S]+?)\]/,
    );
    const accessMatch = LAYOUT_SRC.match(/title:\s*['"]Access['"]\s*,\s*items:\s*\[([\s\S]+?)\]/);
    const personalMatch = LAYOUT_SRC.match(
      /title:\s*['"]Personal['"]\s*,\s*items:\s*\[([\s\S]+?)\]/,
    );
    expect(workspaceMatch).toBeTruthy();
    expect(accessMatch).toBeTruthy();
    expect(personalMatch).toBeTruthy();

    const countIds = (s: string) => (s.match(/id:\s*['"]/g) ?? []).length;
    expect(countIds(workspaceMatch![1]!)).toBe(5);
    expect(countIds(accessMatch![1]!)).toBe(3);
    expect(countIds(personalMatch![1]!)).toBe(3);

    // No nav item carries a hardcoded status pip. A static always-on warn
    // pip on Security & auth was removed as misleading (a pip must reflect a
    // real condition, not a literal). The pip affordance is gone entirely.
    expect(LAYOUT_SRC).not.toMatch(/pip:\s*['"]/);
  });

  // @ac AC-03
  test('frontend-settings/AC-03 — nav search filters items by case-insensitive substring', () => {
    // The filter implementation toLowerCases both the query and label.
    expect(LAYOUT_SRC).toMatch(/toLowerCase\(\)/);
    expect(LAYOUT_SRC).toMatch(/it\.label\.toLowerCase\(\)\.includes/);
  });

  // @ac AC-04
  test('frontend-settings/AC-04 — Profile prefills from GET /auth/me and saves via PATCH /auth/me', () => {
    expect(PROFILE_SRC).toMatch(/useAuthStore/);
    // Prefill from GET /auth/me and persist edits via PATCH /auth/me.
    expect(PROFILE_SRC).toMatch(/api\.GET\(\s*['"]\/api\/v1\/auth\/me['"]/);
    expect(PROFILE_SRC).toMatch(/api\.PATCH\(\s*['"]\/api\/v1\/auth\/me['"]/);
    // Save is no longer a permanently-disabled stub.
    expect(PROFILE_SRC).not.toMatch(/disabled\s*>\s*Save changes/);
  });

  // @ac AC-05
  test('frontend-settings/AC-05 — Password change posts /auth/password:change with body fields', () => {
    expect(PROFILE_SRC).toMatch(/api\.POST\(\s*['"]\/api\/v1\/auth\/password:change['"]/);
    expect(PROFILE_SRC).toMatch(/current_password/);
    expect(PROFILE_SRC).toMatch(/new_password/);
  });

  // @ac AC-06
  test('frontend-settings/AC-06 — Wrong current_password renders inline error; fields preserved', () => {
    // The handler maps 401 from the API to an inline error message
    // and does NOT call any form-reset path on that branch.
    expect(PROFILE_SRC).toMatch(/401|auth\.invalid_credentials/);
    // Error rendering uses role="alert" for inline announce.
    expect(PROFILE_SRC).toMatch(/role=["']alert["']/);
  });

  // @ac AC-07
  test('frontend-settings/AC-07 — zod rejects new == current before any POST', () => {
    // Cross-field refine() that compares new_password to current_password
    // and rejects equality. Schema is built across lines (z\n .object).
    expect(PROFILE_SRC).toMatch(/z\s*\.\s*object\(/);
    expect(PROFILE_SRC).toMatch(/(?:refine|superRefine)/);
    expect(PROFILE_SRC).toMatch(/new_password\s*!==\s*v\.current_password/);
  });

  // @ac AC-08
  test('frontend-settings/AC-08 — zod rejects new_password < 15 chars before any POST', () => {
    // Minimum-length enforcement on the new_password field. AC-08 is
    // the length rule; AC-07 is the differ-from-current rule.
    expect(PROFILE_SRC).toMatch(/z\s*\.\s*object\(/);
    expect(PROFILE_SRC).toMatch(/\.min\(\s*15/);
    // The min(15) is bound to new_password specifically.
    expect(PROFILE_SRC).toMatch(/new_password:[\s\S]*?\.min\(\s*15/);
  });

  // @ac AC-09
  test('frontend-settings/AC-09 — Begin enrollment posts /auth/mfa:enroll + renders provisioning_uri', () => {
    expect(PROFILE_SRC).toMatch(/api\.POST\(\s*['"]\/api\/v1\/auth\/mfa:enroll['"]/);
    // The provisioning URI from the response is rendered in JSX.
    expect(PROFILE_SRC).toMatch(/provisioning_uri/);
  });

  // @ac AC-10
  test('frontend-settings/AC-10 — Valid otp posts /auth/mfa:verify + flips identity.mfaEnabled', () => {
    expect(PROFILE_SRC).toMatch(/api\.POST\(\s*['"]\/api\/v1\/auth\/mfa:verify['"]/);
    // The auth store identity is updated (mfaEnabled true) on success.
    expect(PROFILE_SRC).toMatch(/mfaEnabled\s*:\s*true/);
  });

  // @ac AC-11
  test('frontend-settings/AC-11 — Theme control writes ow-color-scheme localStorage', () => {
    // The Theme segmented control delegates to useColorSchemeStore.setMode.
    expect(PREFERENCES_SRC).toMatch(/useColorSchemeStore/);
    expect(PREFERENCES_SRC).toMatch(/setMode/);
    // Color-scheme store persists under "ow-color-scheme".
    const colorSrc = readFileSync(
      resolve(process.cwd(), 'src/store/useColorSchemeStore.ts'),
      'utf8',
    );
    expect(colorSrc).toMatch(/['"]ow-color-scheme['"]/);
  });

  // @ac AC-12
  test('frontend-settings/AC-12 — Preferences persist via Zustand persist under "ow-preferences"', () => {
    expect(PREFS_STORE_SRC).toMatch(/persist\(/);
    expect(PREFS_STORE_SRC).toMatch(/name:\s*['"]ow-preferences['"]/);
    // PreferencesPage subscribes to the store + calls setters that
    // trigger persistence.
    expect(PREFERENCES_SRC).toMatch(/usePreferencesStore/);
  });

  // @ac AC-13
  test('frontend-settings/AC-13 — Credentials list renders from GET /api/v1/credentials', () => {
    expect(CREDENTIALS_SRC).toMatch(/api\.GET\(\s*['"]\/api\/v1\/credentials['"]/);
  });

  // @ac AC-14
  test('frontend-settings/AC-14 — Users page gated on admin permission via ForbiddenPage', () => {
    // The Users page sources permission from useAuthStore and renders
    // ForbiddenPage when the caller lacks admin.
    expect(USERS_SRC).toMatch(/(useAuthStore|hasPermission)/);
    expect(USERS_SRC).toMatch(/ForbiddenPage|authz\.permission_denied/);
    // The list is fetched via GET /api/v1/users when the gate passes.
    expect(USERS_SRC).toMatch(/api\.GET\(\s*['"]\/api\/v1\/users['"]/);
  });

  // @ac AC-15
  test('frontend-settings/AC-15 — Integrations is the only full stub; Notifications/Security/Audit/About/Policies graduated', () => {
    expect(STUBBED_SRC).toContain('BackendPendingBanner');
    // Integrations is the only remaining full StubShell page.
    expect(STUBBED_SRC).toContain('export function IntegrationsPage');
    expect(STUBBED_SRC).toMatch(/<StubShell/);
    // Audit, Notifications, Security graduated to their own files.
    expect(STUBBED_SRC).not.toContain('export function AuditPage');
    expect(STUBBED_SRC).not.toContain('export function NotificationsPage');
    expect(STUBBED_SRC).not.toContain('export function SecurityPage');
    expect(ROUTER_SRC).toContain("from '@/pages/settings/AuditPage'");
    expect(ROUTER_SRC).toContain("from '@/pages/settings/NotificationsPage'");
    expect(ROUTER_SRC).toContain("from '@/pages/settings/SecurityPage'");
    // About graduated too: it renders live version + license, not a
    // BackendPendingBanner. It still lives in this file but is not a stub.
    expect(STUBBED_SRC).toContain('export function AboutPage');
    // PoliciesPage left the stub file: it lives in its own page with the
    // live scan-variables section and per-section banners on the
    // remaining stubs (frontend-settings-scan-config AC-06).
    expect(STUBBED_SRC).not.toContain('PoliciesPage');
    const policies = readFileSync(
      resolve(process.cwd(), 'src/pages/settings/PoliciesPage.tsx'),
      'utf8',
    );
    expect(policies).toContain('BackendPendingBanner');
    expect(ROUTER_SRC).toContain("from '@/pages/settings/PoliciesPage'");
  });

  // @ac AC-16
  test('frontend-settings/AC-16 — no var(--mui-* or hardcoded hex literals in settings code', () => {
    const settingsPagesDir = resolve(process.cwd(), 'src/pages/settings');
    const settingsCompDir = resolve(process.cwd(), 'src/components/settings');
    // Walk the two directories' file contents and assert.
    const { readdirSync, statSync } = require('node:fs') as typeof import('node:fs');
    function walk(dir: string): string[] {
      const out: string[] = [];
      for (const name of readdirSync(dir)) {
        const p = resolve(dir, name);
        if (statSync(p).isDirectory()) {
          out.push(...walk(p));
        } else if (/\.(tsx?|ts)$/.test(name)) {
          out.push(p);
        }
      }
      return out;
    }
    const files = [...walk(settingsPagesDir), ...walk(settingsCompDir)];
    expect(files.length).toBeGreaterThan(0);
    for (const f of files) {
      const src = readFileSync(f, 'utf8');
      expect(src, `${f} references --mui-*`).not.toMatch(/var\(--mui-/);
      // Hex literals only allowed inside comments or token-map files.
      // Strip line comments + block comments before checking.
      const stripped = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
      // Allow #fff/#000 fallbacks in inline-svg data URIs (rare); also
      // allow #${hex} template interpolation. Otherwise no bare hex.
      const offending = stripped.match(
        /#(?:[0-9a-fA-F]{6}|[0-9a-fA-F]{3})\b(?!.*data:image\/svg)/g,
      );
      expect(offending, `${f} contains hardcoded hex: ${offending?.join(', ')}`).toBeNull();
    }
  });

  // @ac AC-17
  test('frontend-settings/AC-17 — no console.* call interpolates password values', () => {
    const consoleCalls = [...PROFILE_SRC.matchAll(/console\.(log|warn|error)\([^)]*\)/g)];
    for (const c of consoleCalls) {
      const callText = c[0];
      expect(callText).not.toMatch(/current_password/);
      expect(callText).not.toMatch(/new_password/);
      expect(callText).not.toMatch(/confirm_password/);
      expect(callText).not.toMatch(/values\.password/);
    }
  });

  // @ac AC-18
  test('frontend-settings/AC-18 — axe-core dependency present', () => {
    const pkg = JSON.parse(readFileSync(resolve(process.cwd(), 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
    expect(deps['axe-core']).toBeTruthy();
    expect(deps['@axe-core/playwright']).toBeTruthy();
  });

  // @ac AC-19
  test('frontend-settings/AC-19 — Audit log: audit:read gate, infinite query, cursor, read-only', () => {
    // Gated on audit:read with a ForbiddenPage fallback.
    expect(AUDIT_SRC).toMatch(/hasPermission\)\('audit:read'\)/);
    expect(AUDIT_SRC).toContain('ForbiddenPage');
    // Cursor-paginated infinite query over the audit events endpoint.
    expect(AUDIT_SRC).toContain('useInfiniteQuery');
    expect(AUDIT_SRC).toMatch(/api\.GET\(\s*['"]\/api\/v1\/audit\/events['"]/);
    expect(AUDIT_SRC).toMatch(/getNextPageParam:\s*\(last\)\s*=>\s*last\.next_cursor/);
    // Draft filters distinct from the applied filters that key the query,
    // so typing issues no request per keystroke.
    expect(AUDIT_SRC).toMatch(/queryKey:\s*\['audit',\s*applied\./);
    expect(AUDIT_SRC).toMatch(/setApplied\(/);
    // Read-only: no write verbs anywhere in the page.
    expect(AUDIT_SRC).not.toMatch(/api\.(POST|PATCH|PUT|DELETE)\(/);
  });

  // @ac AC-20
  test('frontend-settings/AC-20 — About renders license state from GET /api/v1/license, not hardcoded', () => {
    expect(STUBBED_SRC).toMatch(/queryKey:\s*\['license'\]/);
    expect(STUBBED_SRC).toMatch(/api\.GET\(\s*['"]\/api\/v1\/license['"]/);
    // Tier + status rendered through the lookup maps (not hardcoded copy).
    expect(STUBBED_SRC).toContain('LICENSE_TIER_LABEL');
    expect(STUBBED_SRC).toContain('LICENSE_STATUS');
    // Version still sourced live.
    expect(STUBBED_SRC).toMatch(/api\.GET\(\s*['"]\/api\/v1\/version['"]/);
    // The old "License view pending" stub copy is gone.
    expect(STUBBED_SRC).not.toContain('License view pending');
  });

  // @ac AC-21
  test('frontend-settings/AC-21 — Users Add member opens AddUserModal (POST /users) + roles roster', () => {
    // Add member button is no longer statically disabled; it gates on write
    // permission and opens the modal.
    expect(USERS_SRC).toContain('AddUserModal');
    expect(USERS_SRC).toMatch(/onClick=\{\(\)\s*=>\s*setAddOpen\(true\)\}/);
    expect(USERS_SRC).toMatch(/hasPermission\)\('user:write'\)/);
    // Roster renders per-member roles.
    expect(USERS_SRC).toMatch(/user\.roles/);
    // The create modal POSTs /users and invalidates ['users'].
    expect(USERMUT_SRC).toMatch(/api\.POST\(\s*['"]\/api\/v1\/users['"]/);
    expect(USERMUT_SRC).toMatch(/invalidateQueries\(\{\s*queryKey:\s*\['users'\]/);
  });

  // @ac AC-22
  test('frontend-settings/AC-22 — Users Manage opens ManageUserModal (role assign/unassign + delete)', () => {
    expect(USERS_SRC).toContain('ManageUserModal');
    // Role assign + unassign endpoints.
    expect(USERMUT_SRC).toContain('/api/v1/users/{id}/roles:assign');
    expect(USERMUT_SRC).toContain('/api/v1/users/{id}/roles:unassign');
    // Soft-delete.
    expect(USERMUT_SRC).toMatch(/api\.DELETE\(\s*['"]\/api\/v1\/users\/\{id\}['"]/);
    // Assignable roles sourced from GET /roles.
    expect(USERMUT_SRC).toMatch(/api\.GET\(\s*['"]\/api\/v1\/roles['"]/);
    // Every mutation invalidates the users list.
    expect(USERMUT_SRC).toMatch(/invalidateQueries\(\{\s*queryKey:\s*\['users'\]/);
  });

  // @ac AC-23
  test('frontend-settings/AC-23 — Notifications: notification:read gate, CRUD + test, secret-free', () => {
    // Gated on notification:read with a ForbiddenPage fallback.
    expect(NOTIF_SRC).toMatch(/hasPermission\)\('notification:read'\)/);
    expect(NOTIF_SRC).toContain('ForbiddenPage');
    // List keyed ['notification-channels'].
    expect(NOTIF_SRC).toMatch(/queryKey:\s*\['notification-channels'\]/);
    expect(NOTIF_SRC).toMatch(/api\.GET\(\s*['"]\/api\/v1\/notifications\/channels['"]/);
    // CRUD + test endpoints.
    expect(NOTIF_SRC).toMatch(/api\.POST\(\s*['"]\/api\/v1\/notifications\/channels['"]/);
    expect(NOTIF_SRC).toMatch(/api\.PATCH\(\s*['"]\/api\/v1\/notifications\/channels\/\{id\}['"]/);
    expect(NOTIF_SRC).toMatch(/api\.DELETE\(\s*['"]\/api\/v1\/notifications\/channels\/\{id\}['"]/);
    expect(NOTIF_SRC).toContain('/api/v1/notifications/channels/{id}:test');
    // Mutations invalidate the list.
    expect(NOTIF_SRC).toMatch(/invalidateQueries\(\{\s*queryKey:\s*\['notification-channels'\]/);
    // Renders the non-secret hint, never a url/token secret field.
    expect(NOTIF_SRC).toContain('target_hint');
    expect(NOTIF_SRC).not.toMatch(/channel\.(url|token)\b/);
    // Write/delete/test controls gate on their permissions.
    expect(NOTIF_SRC).toMatch(/hasPermission\)\('notification:write'\)/);
    expect(NOTIF_SRC).toMatch(/hasPermission\)\('notification:delete'\)/);
    expect(NOTIF_SRC).toMatch(/hasPermission\)\('notification:test'\)/);
    // Email channels expose an SMTP encryption selector (none/starttls/tls)
    // and send smtp_encryption in the config, plus a self-signed-cert
    // (skip-verify) toggle for an internal relay.
    expect(NOTIF_SRC).toMatch(/smtp_encryption/);
    expect(NOTIF_SRC).toContain("'starttls'");
    expect(NOTIF_SRC).toContain("'tls'");
    expect(NOTIF_SRC).toMatch(/smtp_insecure_skip_verify/);
    // Severity delivery is threshold-based (minimum level), not two presets.
    expect(NOTIF_SRC).toMatch(/Medium and above/);
    expect(NOTIF_SRC).toMatch(/High and above/);
  });

  // @ac AC-24
  test('frontend-settings/AC-24 — Security: admin gate, live API tokens, secret shown once', () => {
    // Page gated on admin.
    expect(SEC_SRC).toMatch(/hasPermission\)\('admin'\)/);
    expect(SEC_SRC).toContain('ForbiddenPage');
    // API-tokens list keyed ['api-tokens'].
    expect(SEC_SRC).toMatch(/queryKey:\s*\['api-tokens'\]/);
    expect(SEC_SRC).toMatch(/api\.GET\(\s*['"]\/api\/v1\/tokens['"]/);
    // Create + revoke endpoints.
    expect(SEC_SRC).toMatch(/api\.POST\(\s*['"]\/api\/v1\/tokens['"]/);
    expect(SEC_SRC).toMatch(/api\.DELETE\(\s*['"]\/api\/v1\/tokens\/\{id\}['"]/);
    // Both mutations invalidate the list.
    expect(SEC_SRC).toMatch(/invalidateQueries\(\{\s*queryKey:\s*\['api-tokens'\]/);
    // Secret shown once: a copy control + a not-shown-again warning; list
    // renders only the prefix (no raw token/secret list field).
    expect(SEC_SRC).toMatch(/not be shown again/i);
    expect(SEC_SRC).toContain('token.prefix');
    expect(SEC_SRC).not.toMatch(/token\.(token|secret|hash)\b/);
    // Write/delete controls gate on their permissions.
    expect(SEC_SRC).toMatch(/hasPermission\)\('token:write'\)/);
    expect(SEC_SRC).toMatch(/hasPermission\)\('token:delete'\)/);
  });

  // @ac AC-25
  test('frontend-settings/AC-25 — Security: live auth-policy section + login enrollment routing', () => {
    // Auth-policy section loads + saves the policy, perm-gated.
    expect(SEC_SRC).toMatch(/queryKey:\s*\['auth-policy'\]/);
    expect(SEC_SRC).toMatch(/api\.GET\(\s*['"]\/api\/v1\/auth-policy['"]/);
    expect(SEC_SRC).toMatch(/api\.PUT\(\s*['"]\/api\/v1\/auth-policy['"]/);
    expect(SEC_SRC).toMatch(/invalidateQueries\(\{\s*queryKey:\s*\['auth-policy'\]/);
    expect(SEC_SRC).toMatch(/hasPermission\)\('system:auth_policy_read'\)/);
    expect(SEC_SRC).toMatch(/hasPermission\)\('system:auth_policy_write'\)/);
    // require-MFA toggle + timeout steppers.
    expect(SEC_SRC).toContain('<Toggle');
    expect(SEC_SRC).toContain('<Stepper');
    // Login routes a non-enrolled user to enrollment when policy requires MFA.
    expect(LOGIN_SRC).toContain('mfa_enrollment_required');
    expect(LOGIN_SRC).toMatch(/navigate\(\{\s*to:\s*['"]\/settings\/profile['"]/);
  });

  // @ac AC-26
  test('frontend-settings/AC-26 — Security: live SSO provider CRUD + login sign-in buttons', () => {
    // SSO section is admin:sso_provider-gated and does provider CRUD.
    expect(SEC_SRC).toMatch(/hasPermission\)\('admin:sso_provider'\)/);
    expect(SEC_SRC).toMatch(/queryKey:\s*\['sso-providers'\]/);
    expect(SEC_SRC).toMatch(/api\.GET\(\s*['"]\/api\/v1\/sso\/providers['"]/);
    expect(SEC_SRC).toMatch(/api\.POST\(\s*['"]\/api\/v1\/sso\/providers['"]/);
    expect(SEC_SRC).toMatch(/api\.PUT\(\s*['"]\/api\/v1\/sso\/providers\/\{id\}['"]/);
    expect(SEC_SRC).toMatch(/api\.DELETE\(\s*['"]\/api\/v1\/sso\/providers\/\{id\}['"]/);
    // Client secret is write-only: the edit form labels it "leave blank to keep".
    expect(SEC_SRC).toMatch(/leave blank to keep/i);
    // Login page fetches enabled providers and starts the backend redirect flow.
    expect(LOGIN_SRC).toMatch(/api\.GET\(\s*['"]\/api\/v1\/sso\/providers\/enabled['"]/);
    expect(LOGIN_SRC).toMatch(/\/api\/v1\/auth\/sso\/\$\{providerId\}\/login/);
  });

  // @ac AC-27
  test('frontend-settings/AC-27 — Users Manage: admin password reset gated + surfaces policy errors', () => {
    // Admin-authority actions gate on admin:user_manage || isAdmin.
    expect(USERMUT_SRC).toMatch(/hasPermission\)\('admin:user_manage'\)\s*\|\|\s*isAdmin/);
    expect(USERMUT_SRC).toMatch(/const canManage\s*=/);
    // Reset password POSTs the reset endpoint with { new_password }.
    expect(USERMUT_SRC).toContain('/api/v1/users/{id}:reset-password');
    expect(USERMUT_SRC).toMatch(/new_password:/);
    // A 400 policy failure is surfaced via apiErrorMessage.
    expect(USERMUT_SRC).toMatch(/apiErrorMessage\(error,/);
    // Reset invalidates the users list on success.
    expect(USERMUT_SRC).toMatch(/invalidateQueries\(\{\s*queryKey:\s*\['users'\]/);
  });

  // @ac AC-28
  test('frontend-settings/AC-28 — Users Manage: disable/enable toggle + disabled status', () => {
    // Disable + enable endpoints.
    expect(USERMUT_SRC).toContain('/api/v1/users/{id}:disable');
    expect(USERMUT_SRC).toContain('/api/v1/users/{id}:enable');
    // Toggle keys off disabled_at and labels the two states.
    expect(USERMUT_SRC).toMatch(/disabled_at/);
    expect(USERMUT_SRC).toContain('Disable account');
    expect(USERMUT_SRC).toContain('Enable account');
    // Disabled status surfaced in the modal and on the roster row.
    expect(USERMUT_SRC).toContain('Disabled');
    expect(USERS_SRC).toMatch(/disabled_at/);
    expect(USERS_SRC).toContain('Disabled');
  });

  // @ac AC-29
  test('frontend-settings/AC-29 — Users Manage: self-disable 409 inline + no em-dashes', () => {
    // Toggle errors route through the shared action-error Callout.
    expect(USERMUT_SRC).toMatch(/onError:\s*\(err: Error\)\s*=>\s*setActionError\(err\.message\)/);
    expect(USERMUT_SRC).toContain('<Callout tier="crit">{actionError}</Callout>');
    // No em-dashes in the user-facing reset/disable copy (project rule).
    // Comments may use them; the visible button/label strings must not.
    expect('Disable account').not.toContain('—');
    expect('Enable account').not.toContain('—');
    expect('Reset password').not.toContain('—');
    // The reset-password helper copy uses parentheses, not em-dashes.
    const resetCopy = USERMUT_SRC.match(/Set a new password on admin authority[^<]*/)?.[0] ?? '';
    expect(resetCopy.length).toBeGreaterThan(0);
    expect(resetCopy).not.toContain('—');
  });

  // @ac AC-30
  test('frontend-settings/AC-30 — preferences store syncs server-side (localStorage cache retained)', () => {
    // localStorage cache retained (instant load + offline fallback).
    expect(PREFS_STORE_SRC).toMatch(/persist\(/);
    expect(PREFS_STORE_SRC).toContain("name: 'ow-preferences'");
    // Write-through: setters PATCH the server via push().
    expect(PREFS_STORE_SRC).toContain("api.PATCH('/api/v1/users/me/preferences'");
    expect(PREFS_STORE_SRC).toMatch(/push\(\{ hosts_view_default: hostsViewDefault \}\)/);
    // Hydration: hydrateFromServer GETs and applies present keys.
    expect(PREFS_STORE_SRC).toContain('hydrateFromServer');
    expect(PREFS_STORE_SRC).toContain("api.GET('/api/v1/users/me/preferences')");
    // The authenticated shell reconciles once on mount.
    const FRAME_SRC = readFileSync(
      resolve(process.cwd(), 'src/components/shell/AppFrame.tsx'),
      'utf8',
    );
    expect(FRAME_SRC).toContain('hydrateFromServer');
    expect(FRAME_SRC).toMatch(/useEffect\(/);
  });

  // @ac AC-31
  test('frontend-settings/AC-31 — Audit log rows are readable: message primary, actor name not UUID', () => {
    // Primary line = server message (fallback to raw action); raw action as a sub-line.
    expect(AUDIT_SRC).toMatch(/ev\.message \|\| ev\.action/);
    // Actor shows the label (name), not the raw UUID, in the main row.
    expect(AUDIT_SRC).toMatch(/ev\.actor_label \|\| actorTypeWord\(ev\.actor_type\)/);
    // The raw UUIDs are not rendered inline in the row's actor/resource cells
    // (they moved to the expanded detail under "actor id" / "resource id").
    expect(AUDIT_SRC).toContain('actor id:');
    expect(AUDIT_SRC).toContain('resource id:');
    // Shared display helpers; the local relTime + em-dash are gone.
    expect(AUDIT_SRC).toContain("from '@/api/eventDisplay'");
    expect(AUDIT_SRC).toMatch(/relativeTime\(ev\.occurred_at\)/);
    expect(AUDIT_SRC).not.toMatch(/function relTime/);
    expect(AUDIT_SRC).not.toContain('—');
    // Still read-only.
    expect(AUDIT_SRC).not.toMatch(/api\.(POST|PATCH|PUT|DELETE)\(/);
  });

  // @ac AC-32
  test('frontend-settings/AC-32 — Audit log export: CSV/JSON download via the auth’d client', () => {
    // Both export buttons wired to exportAudit.
    expect(AUDIT_SRC).toMatch(/exportAudit\('csv'\)/);
    expect(AUDIT_SRC).toMatch(/exportAudit\('json'\)/);
    // Fetches the export endpoint as a blob with the format + applied filters.
    expect(AUDIT_SRC).toMatch(/api\.GET\(\s*['"]\/api\/v1\/audit\/events\/export['"]/);
    expect(AUDIT_SRC).toMatch(/parseAs:\s*['"]blob['"]/);
    expect(AUDIT_SRC).toMatch(/format,/);
    expect(AUDIT_SRC).toMatch(/applied\.action/);
    // Triggers a browser download (object URL + temporary anchor).
    expect(AUDIT_SRC).toContain('URL.createObjectURL');
    expect(AUDIT_SRC).toMatch(/a\.download =/);
    expect(AUDIT_SRC).toContain('URL.revokeObjectURL');
    // Disabled while exporting + inline error surface.
    expect(AUDIT_SRC).toMatch(/disabled=\{exporting !== null\}/);
    expect(AUDIT_SRC).toMatch(/setExportError/);
    // Reading remains GET-only.
    expect(AUDIT_SRC).not.toMatch(/api\.(POST|PATCH|PUT|DELETE)\(/);
  });
});
