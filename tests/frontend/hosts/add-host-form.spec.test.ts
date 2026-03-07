// Spec: specs/frontend/add-host-form.spec.yaml
/**
 * Spec-enforcement tests for Add Host form behavior.
 *
 * Verifies auth method field visibility, test connection adapter accuracy,
 * button disabled states, absence of dead UI elements, and error handling.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SRC = path.resolve(__dirname, '../../../frontend/src');

function readSource(relativePath: string): string {
  return fs.readFileSync(path.join(SRC, relativePath), 'utf8');
}

const ADD_HOST = readSource('pages/hosts/AddHost.tsx');
const QUICK_FORM = readSource('pages/hosts/components/QuickAddHostForm.tsx');
const HOOK = readSource('pages/hosts/hooks/useAddHostForm.ts');
const ADAPTER = readSource('services/adapters/hostAdapter.ts');

// ---------------------------------------------------------------------------
// AC-1: System Default hides Username field
// ---------------------------------------------------------------------------

describe('AC-1: System Default hides Username and credential fields', () => {
  /**
   * AC-1: When auth_method is system_default, QuickAddHostForm MUST NOT
   * render a Username input field.
   */

  it('username field is conditionally hidden for system_default', () => {
    // The form should check authMethod !== 'system_default' before rendering username
    expect(QUICK_FORM).toContain("system_default");
    // Username field should be wrapped in a conditional that excludes system_default
    expect(QUICK_FORM).toMatch(/authMethod\s*!==\s*['"]system_default['"]/);
  });

  it('system credential info box is shown for system_default', () => {
    expect(QUICK_FORM).toContain('Using System Default Credentials');
  });
});

// ---------------------------------------------------------------------------
// AC-2: SSH Key shows Username and SSH Private Key
// ---------------------------------------------------------------------------

describe('AC-2: SSH Key shows Username and SSH Private Key fields', () => {
  it('SSH Private Key textarea is rendered for ssh_key method', () => {
    expect(QUICK_FORM).toContain('SSH Private Key');
  });

  it('username field is rendered for ssh_key method', () => {
    // Username renders for non-system_default methods
    expect(QUICK_FORM).toContain('Username');
  });
});

// ---------------------------------------------------------------------------
// AC-3: Password shows Username and Password fields
// ---------------------------------------------------------------------------

describe('AC-3: Password shows Username and Password fields', () => {
  it('password field is rendered for password method', () => {
    expect(QUICK_FORM).toContain('Enter password for authentication');
  });

  it('password field has show/hide toggle', () => {
    // Visibility toggle for password
    expect(QUICK_FORM).toContain('showPassword') ;
    expect(QUICK_FORM).toMatch(/Visibility(Off)?/);
  });
});

// ---------------------------------------------------------------------------
// AC-4: Both mode shows Username, SSH Key, and Password
// ---------------------------------------------------------------------------

describe('AC-4: SSH Key + Password (Fallback) shows all three fields', () => {
  it('info banner explains fallback behavior', () => {
    expect(QUICK_FORM).toContain('SSH Key + Password Fallback');
    expect(QUICK_FORM).toContain('automatically fallback to password');
  });

  it('SSH Private Key (Primary) label is shown for both mode', () => {
    expect(QUICK_FORM).toContain('SSH Private Key (Primary)');
  });

  it('Password (Fallback) label is shown for both mode', () => {
    expect(QUICK_FORM).toContain('Password (Fallback)');
  });
});

// ---------------------------------------------------------------------------
// AC-5: Test Connection disabled states
// ---------------------------------------------------------------------------

describe('AC-5: Test Connection button disabled states', () => {
  it('disabled when hostname is empty', () => {
    expect(QUICK_FORM).toContain('!formData.hostname');
  });

  it('disabled when username is empty and not system_default', () => {
    // Should check: !formData.username && formData.authMethod !== 'system_default'
    expect(QUICK_FORM).toMatch(/!formData\.username.*system_default/s);
  });
});

// ---------------------------------------------------------------------------
// AC-6: System Default sends no credentials to backend
// ---------------------------------------------------------------------------

describe('AC-6: System Default sends auth_method=system_default with no credentials', () => {
  it('handleTestConnection sends auth_method from formData', () => {
    expect(HOOK).toContain('auth_method: formData.authMethod');
  });

  it('password only sent for password or both methods', () => {
    expect(HOOK).toContain("authMethod === 'password'");
    expect(HOOK).toContain("authMethod === 'both'");
  });

  it('ssh_key only sent for ssh_key or both methods', () => {
    expect(HOOK).toContain("authMethod === 'ssh_key'");
  });
});

// ---------------------------------------------------------------------------
// AC-7: Adapter maps correct backend field names
// ---------------------------------------------------------------------------

describe('AC-7: adaptConnectionTest maps correct backend field names', () => {
  it('maps network_connectivity (not network_reachable)', () => {
    expect(ADAPTER).toContain('response.network_connectivity');
    expect(ADAPTER).not.toContain('response.network_reachable');
  });

  it('maps authentication (not auth_successful)', () => {
    expect(ADAPTER).toContain('response.authentication');
    expect(ADAPTER).not.toContain('response.auth_successful');
  });

  it('maps detected_version (not os_version)', () => {
    expect(ADAPTER).toContain('response.detected_version');
    expect(ADAPTER).not.toContain('response.os_version');
  });
});

// ---------------------------------------------------------------------------
// AC-8: Adapter defaults to false, not true
// ---------------------------------------------------------------------------

describe('AC-8: adaptConnectionTest defaults booleans to false', () => {
  it('success defaults to false', () => {
    expect(ADAPTER).toMatch(/response\.success\s*\?\?\s*false/);
  });

  it('networkConnectivity defaults to false', () => {
    expect(ADAPTER).toMatch(/response\.network_connectivity\s*\?\?\s*false/);
  });

  it('authentication defaults to false', () => {
    expect(ADAPTER).toMatch(/response\.authentication\s*\?\?\s*false/);
  });
});

// ---------------------------------------------------------------------------
// AC-9: Connection status reflects backend success field
// ---------------------------------------------------------------------------

describe('AC-9: Connection status set from adapted result.success', () => {
  it('connectionStatus set based on adapted.success', () => {
    expect(HOOK).toContain("adapted.success ? 'success' : 'failed'");
  });

  it('does not hardcode connectionStatus to success', () => {
    // The hook should NOT set connectionStatus('success') unconditionally
    // before checking the result
    const lines = HOOK.split('\n');
    const testConnSection = HOOK.substring(
      HOOK.indexOf('handleTestConnection'),
      HOOK.indexOf('handleSubmit')
    );
    // Should not have setConnectionStatus('success') without checking result
    const unconditionalSuccess = testConnSection.match(
      /setConnectionStatus\(['"]success['"]\)\s*;?\s*\n\s*\n\s*\/\//
    );
    expect(unconditionalSuccess).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// AC-10: No StatCards or Quick Start Templates
// ---------------------------------------------------------------------------

describe('AC-10: AddHost.tsx has no dead UI elements', () => {
  it('does not contain StatCard', () => {
    expect(ADD_HOST).not.toContain('StatCard');
  });

  it('does not contain Quick Start Templates', () => {
    expect(ADD_HOST).not.toContain('Quick Start');
    expect(ADD_HOST).not.toContain('Template');
  });

  it('does not import Grid or Card from MUI', () => {
    expect(ADD_HOST).not.toContain("import { Grid");
    expect(ADD_HOST).not.toContain("Card,");
    expect(ADD_HOST).not.toContain("CardContent");
  });
});

// ---------------------------------------------------------------------------
// AC-11: Detected OS only shown when non-empty
// ---------------------------------------------------------------------------

describe('AC-11: Detected OS line only shown when detectedOS is non-empty', () => {
  it('detectedOS display is conditionally rendered', () => {
    // Should have a check like: connectionTestResults.detectedOS && (
    expect(QUICK_FORM).toMatch(/connectionTestResults\.detectedOS\s*&&/);
  });
});

// ---------------------------------------------------------------------------
// AC-12: handleSubmit does not navigate on error
// ---------------------------------------------------------------------------

describe('AC-12: handleSubmit shows error instead of navigating', () => {
  it('catch block sets connectionStatus to failed', () => {
    const submitSection = HOOK.substring(
      HOOK.indexOf('handleSubmit'),
      HOOK.indexOf('fetchSystemCredentials')
    );
    expect(submitSection).toContain("setConnectionStatus('failed')");
  });

  it('catch block sets connectionTestResults with error', () => {
    const submitSection = HOOK.substring(
      HOOK.indexOf('handleSubmit'),
      HOOK.indexOf('fetchSystemCredentials')
    );
    expect(submitSection).toContain('setConnectionTestResults');
    expect(submitSection).toContain('success: false');
  });

  it('navigate only called in try block (on success)', () => {
    const submitSection = HOOK.substring(
      HOOK.indexOf('handleSubmit'),
      HOOK.indexOf('fetchSystemCredentials')
    );
    // navigate('/hosts') should only appear in try, not catch
    const catchBlock = submitSection.substring(submitSection.indexOf('catch'));
    expect(catchBlock).not.toContain("navigate('/hosts')");
  });
});
