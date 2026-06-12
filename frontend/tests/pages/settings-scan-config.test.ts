// @spec frontend-settings-scan-config
//
// AC traceability (this file — source inspection over ScanningPage.tsx,
// same pattern as settings.test.ts):
//
//   AC-01  endpoints + query keys + invalidation
//   AC-02  six-state seeds in ladder order + *_mins key map
//   AC-03  clamp-echo re-anchor vs live-config reset + scanDirty SaveBar
//   AC-04  no dead controls; live badge; ScheduleStrip
//   AC-05  Advanced: rate_limit stepper 1..100 + maintenance_global toggle

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const SRC = readFileSync(resolve(process.cwd(), 'src/pages/settings/ScanningPage.tsx'), 'utf8');

describe('frontend-settings-scan-config — source inspection', () => {
  // @ac AC-01
  test('frontend-settings-scan-config/AC-01 — three queries with stable keys; PUT invalidates config + preview', () => {
    expect(SRC).toContain("queryKey: ['system', 'scan', 'config']");
    expect(SRC).toContain("api.GET('/api/v1/system/scan/config'");
    expect(SRC).toContain("queryKey: ['fleet', 'compliance', 'states']");
    expect(SRC).toContain("api.GET('/api/v1/fleet/compliance/states'");
    expect(SRC).toContain("queryKey: ['system', 'scan', 'schedule_preview']");
    expect(SRC).toContain("api.GET('/api/v1/system/scan/schedule-preview'");
    expect(SRC).toContain("api.PUT('/api/v1/system/scan/config'");
    expect(SRC).toContain(
      "queryClient.invalidateQueries({ queryKey: ['system', 'scan', 'config'] })",
    );
    expect(SRC).toContain(
      "queryClient.invalidateQueries({ queryKey: ['system', 'scan', 'schedule_preview'] })",
    );
  });

  // @ac AC-02
  test('frontend-settings-scan-config/AC-02 — six states in ladder order mapped to *_mins keys', () => {
    // Seeds in exact ladder order (backend scheduler.AllStates()).
    const seedOrder = [
      "id: 'critical'",
      "id: 'non_compliant'",
      "id: 'partial'",
      "id: 'mostly_compliant'",
      "id: 'compliant'",
      "id: 'unknown'",
    ];
    const seedsBlock = SRC.slice(SRC.indexOf('COMPLIANCE_ROW_SEEDS'), SRC.indexOf('SCAN_MINS_KEY'));
    let last = -1;
    for (const marker of seedOrder) {
      const at = seedsBlock.indexOf(marker);
      expect(at, `${marker} present in seeds`).toBeGreaterThan(-1);
      expect(at, `${marker} in ladder order`).toBeGreaterThan(last);
      last = at;
    }
    // Key map covers every state with its matching ScanConfig key.
    for (const [id, key] of [
      ['critical', 'critical_mins'],
      ['non_compliant', 'non_compliant_mins'],
      ['partial', 'partial_mins'],
      ['mostly_compliant', 'mostly_compliant_mins'],
      ['compliant', 'compliant_mins'],
      ['unknown', 'unknown_mins'],
    ]) {
      expect(SRC).toMatch(new RegExp(`${id}:\\s*'${key}'`));
    }
    // Steppers edit the draft, not the network.
    expect(SRC).toContain('setScanDraft((d) => (d ? { ...d, [SCAN_MINS_KEY[seed.id]]: v } : d))');
  });

  // @ac AC-03
  test('frontend-settings-scan-config/AC-03 — save re-anchors on the clamped echo; reset on live config; SaveBar gates on scanDirty', () => {
    // onSuccess re-anchors from the PUT response (clamp echo).
    expect(SRC).toMatch(
      /onSuccess:\s*\(saved\)\s*=>\s*\{[\s\S]*?setScanDraft\(\{\s*\.\.\.saved\s*\}\)/,
    );
    // Reset path re-anchors from the live config — a distinct closure.
    expect(SRC).toContain('setScanDraft({ ...scanConfigQuery.data.config })');
    // SaveBar covers the scan draft.
    expect(SRC).toContain('{(dirty || scanDirty) && (');
    expect(SRC).toMatch(/if \(scanDirty && scanDraft\) saveScanMutation\.mutate\(scanDraft\)/);
  });

  // @ac AC-04
  test('frontend-settings-scan-config/AC-04 — no dead controls; live badge; ScheduleStrip renders the preview', () => {
    // The compliance section block (Section open to the next section).
    const section = SRC.slice(
      SRC.indexOf('Compliance scanner (LIVE)'),
      SRC.indexOf('Host connectivity monitor'),
    );
    expect(section.length).toBeGreaterThan(0);
    expect(section).not.toContain('BackendPendingBanner');
    expect(section).not.toContain('UI only');
    expect(section).not.toContain('Quiet hours');
    expect(section).toContain("badge={scanPaused ? 'Paused' : 'Running'}");
    expect(section).toContain('<ScheduleStrip buckets={preview?.buckets} />');
    // Badge pause state derives from enabled + maintenance_global.
    expect(SRC).toMatch(
      /scanPaused = !\(scanDraft\?\.enabled \?\? true\) \|\| \(scanDraft\?\.maintenance_global \?\? false\)/,
    );
  });

  // @ac AC-05
  test('frontend-settings-scan-config/AC-05 — Advanced wires rate_limit (1..100) and maintenance_global to the draft', () => {
    const advanced = SRC.slice(
      SRC.indexOf('Advanced: dispatch rate limit and global pause'),
      SRC.indexOf('Host connectivity monitor'),
    );
    expect(advanced).toContain('value={scanDraft?.rate_limit ?? 25}');
    expect(advanced).toMatch(/min=\{1\}\s*\n?\s*max=\{100\}/);
    expect(advanced).toContain('setScanDraft((d) => (d ? { ...d, rate_limit: v } : d))');
    expect(advanced).toContain('value={scanDraft?.maintenance_global ?? false}');
    expect(advanced).toContain('setScanDraft((d) => (d ? { ...d, maintenance_global: v } : d))');
  });
});

describe('frontend-settings-scan-config v1.1.0 — scan variables card (Compliance policies page)', () => {
  // @ac AC-06
  test('frontend-settings-scan-config/AC-06 — variables card: query key, default-skipping PUT, configure-me chip, labeled inputs; mounted on PoliciesPage only', () => {
    const card = readFileSync(
      resolve(process.cwd(), 'src/components/settings/ScanVariablesCard.tsx'),
      'utf8',
    );
    expect(card).toContain("queryKey: ['system', 'scan', 'variables']");
    expect(card).toContain("api.GET('/api/v1/system/scan/variables'");
    expect(card).toContain("api.PUT('/api/v1/system/scan/variables'");
    expect(card).toContain(
      "queryClient.invalidateQueries({ queryKey: ['system', 'scan', 'variables'] })",
    );
    // PUT body skips default-equal values; edits-only state clears on save.
    expect(card).toContain('if (value !== v.default) overrides[v.name] = value;');
    expect(card).toContain('setEdits({});');
    // Chip only for unconfigured placeholders.
    expect(card).toContain('v.configure_me && !v.overridden');
    expect(card).toContain('Configure me');
    // Inputs are labeled per variable.
    expect(card).toContain('aria-label={`Value for ${v.name}`}');
    // Home: the Compliance policies page mounts it; Scanning does not
    // (variable values are policy content, not cadence).
    const policies = readFileSync(
      resolve(process.cwd(), 'src/pages/settings/PoliciesPage.tsx'),
      'utf8',
    );
    expect(policies).toContain('<ScanVariablesCard />');
    expect(SRC).not.toContain('ScanVariablesCard');
  });
});
