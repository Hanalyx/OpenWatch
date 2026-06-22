// @spec frontend-reports
//
// AC traceability (source inspection over ReportsPage):
//   AC-01  single ['reports'] query against GET /api/v1/reports; Library
//          columns (title/kind/scope/data_as_of/generated_by/format);
//          route mounted at "reports"; sidebar Reports entry enabled
//   AC-02  Generate POSTs /api/v1/reports:generate, invalidates ['reports'],
//          gated on hasPermission('host:write')
//   AC-03  Templates + Scheduled tabs as deferred ComingSoon states;
//          honest loading / empty / error states via apiErrorMessage
//   AC-04  only mutation is the generate POST (no PUT/DELETE); --ow-* tokens;
//          no prose em-dash
//   AC-10  report-kind selector (executive/attestation) drives the generate
//          body; kind-aware primary download (csv for attestation, pdf
//          otherwise); kindLabel maps attestation -> "Attestation"
//   AC-11  secondaryFaces surfaces the attestation PDF + OSCAL SAR downloads
//          (executive none); downloadReportFace accepts 'oscal_sar'
//   AC-12  detail body is kind-aware: AttestationBody(asAttestationContent)
//          for attestation, ExecutiveBody(asExecutiveContent) otherwise
//   AC-13  exception register kind: selector option + ExceptionBody(asExceptionContent)

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const PAGE_SRC = readFileSync(resolve(process.cwd(), 'src/pages/reports/ReportsPage.tsx'), 'utf8');
const ROUTER_SRC = readFileSync(resolve(process.cwd(), 'src/routes/router.tsx'), 'utf8');
const SIDEBAR_SRC = readFileSync(
  resolve(process.cwd(), 'src/components/shell/Sidebar.tsx'),
  'utf8',
);

function stripComments(s: string): string {
  return s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

describe('frontend-reports — reports library page', () => {
  // @ac AC-01
  test('frontend-reports/AC-01 — reports query, Library columns, route + sidebar', () => {
    // One query keyed ['reports'] against the list endpoint.
    expect(PAGE_SRC).toContain("queryKey: ['reports']");
    expect(PAGE_SRC).toContain("api.GET('/api/v1/reports'");
    // Library table is rendered off the response reports.
    expect(PAGE_SRC).toContain('reportsQ.data?.reports');
    // Each row reads the report fields off the row.
    expect(PAGE_SRC).toMatch(/r\.title/);
    expect(PAGE_SRC).toMatch(/r\.kind/);
    expect(PAGE_SRC).toMatch(/r\.scope_label/);
    expect(PAGE_SRC).toMatch(/r\.data_as_of/);
    expect(PAGE_SRC).toMatch(/r\.generated_by/);
    expect(PAGE_SRC).toMatch(/r\.format/);
    // kind renders as a type chip.
    expect(PAGE_SRC).toContain('<KindChip');
    // Route mounted at path 'reports' under protectedRoute.
    const route = ROUTER_SRC.match(/const reportsRoute = createRoute\(\{[\s\S]*?\}\);/);
    expect(route).toBeTruthy();
    expect(route![0]).toMatch(/path:\s*'reports'/);
    expect(route![0]).toMatch(/getParentRoute:\s*\(\)\s*=>\s*protectedRoute/);
    // Sidebar Reports entry is enabled.
    expect(SIDEBAR_SRC).toMatch(/label: 'Reports'[^\n]*enabled: true/);
  });

  // @ac AC-02
  test('frontend-reports/AC-02 — Generate POST, invalidation, host:write gate', () => {
    // Generate posts the action endpoint.
    expect(PAGE_SRC).toContain("api.POST('/api/v1/reports:generate'");
    // On success it invalidates the single reports query.
    expect(PAGE_SRC).toContain("invalidateQueries({ queryKey: ['reports'] })");
    // The control is gated on host:write via useAuthStore.hasPermission.
    expect(PAGE_SRC).toContain("hasPermission('host:write')");
    expect(PAGE_SRC).toContain('canGenerate');
    // The button is disabled when the caller cannot generate.
    expect(PAGE_SRC).toContain('disabled={!canGenerate');
  });

  // @ac AC-03
  test('frontend-reports/AC-03 — deferred Templates/Scheduled + honest states', () => {
    // Templates and Scheduled tabs render the deferred ComingSoon state.
    expect(PAGE_SRC).toContain('ComingSoon');
    expect(PAGE_SRC).toContain('what="Templates"');
    expect(PAGE_SRC).toContain('what="Scheduled"');
    expect(PAGE_SRC.toLowerCase()).toContain('coming soon');
    // Honest loading / empty / error states wired off the query.
    expect(PAGE_SRC).toContain('reportsQ.isPending');
    expect(PAGE_SRC).toContain('reportsQ.isError');
    expect(PAGE_SRC).toContain('apiErrorMessage');
    expect(PAGE_SRC).toContain('kind="loading"');
    expect(PAGE_SRC).toContain('kind="empty"');
    expect(PAGE_SRC).toContain('kind="error"');
  });

  // @ac AC-05
  test('frontend-reports/AC-05 — scope picker (group select) drives the generate body', () => {
    // A scope select bound to scopeGroupId, defaulting to "All hosts".
    expect(PAGE_SRC).toContain('scopeGroupId');
    expect(PAGE_SRC).toMatch(/<select[\s\S]*?value=\{scopeGroupId\}/);
    expect(PAGE_SRC).toContain('<option value="">All hosts</option>');
    // Options come from a ['groups'] query against the groups endpoint.
    expect(PAGE_SRC).toContain("queryKey: ['groups']");
    expect(PAGE_SRC).toContain("api.GET('/api/v1/groups'");
    // The groups query is a host:write affordance (enabled on canGenerate).
    expect(PAGE_SRC).toMatch(/enabled:\s*canGenerate/);
    // The generate body includes group_id only when a group is chosen.
    expect(PAGE_SRC).toMatch(/if \(scopeGroupId\) body\.group_id = scopeGroupId/);
  });

  // @ac AC-06
  test('frontend-reports/AC-06 — coverage caveat discloses stale/unreachable hosts', () => {
    // A CoverageCaveat component reading the coverage counts.
    expect(PAGE_SRC).toContain('function CoverageCaveat');
    expect(PAGE_SRC).toContain('hosts_stale');
    expect(PAGE_SRC).toContain('hosts_unreachable');
    // Renders nothing when the fleet is fully fresh + reachable.
    expect(PAGE_SRC).toMatch(/hosts_stale === 0 && hosts_unreachable === 0\) return null/);
    // ExecutiveBody narrows coverage and renders the caveat.
    expect(PAGE_SRC).toContain('asCoverage');
    expect(PAGE_SRC).toContain('<CoverageCaveat');
  });

  // @ac AC-07
  test('frontend-reports/AC-07 — report detail download controls (pdf/json export)', () => {
    // A downloadReportFace helper hits the export endpoint with the format.
    expect(PAGE_SRC).toContain('function downloadReportFace');
    expect(PAGE_SRC).toMatch(/\/api\/v1\/reports\/\$\{id\}\/export\?format=\$\{format\}/);
    // Cookie auth (same-origin credentials), no bearer token / Authorization.
    expect(PAGE_SRC).toContain("credentials: 'same-origin'");
    expect(PAGE_SRC.includes('Authorization')).toBe(false);
    // The blob is saved via an object URL.
    expect(PAGE_SRC).toContain('URL.createObjectURL');
    // The detail renders a primary (kind-aware) download + a JSON control
    // calling onDownload, with an in-flight disabled state and an error
    // surface. (The primary face is computed from the report kind in B1b;
    // the literal "Download PDF" label still appears for executive reports.)
    expect(PAGE_SRC).toContain('Download PDF');
    expect(PAGE_SRC).toMatch(/onDownload\(primaryFace\)/);
    expect(PAGE_SRC).toMatch(/onDownload\('json'\)/);
    expect(PAGE_SRC).toContain('downloading');
    expect(PAGE_SRC).toContain('downloadError');
  });

  // @ac AC-08
  test('frontend-reports/AC-08 — signed badge + offline Verify (hash + Ed25519)', () => {
    // A verifyReport helper fetches the signing key, re-hashes the json
    // face, and Ed25519-verifies the signature offline.
    expect(PAGE_SRC).toContain('function verifyReport');
    expect(PAGE_SRC).toContain("fetch('/api/v1/reports/signing-key'");
    expect(PAGE_SRC).toMatch(/export\?format=json/);
    expect(PAGE_SRC).toContain("crypto.subtle.digest('SHA-256'");
    expect(PAGE_SRC).toContain('content_sha256');
    expect(PAGE_SRC).toContain('crypto.subtle.verify');
    expect(PAGE_SRC).toContain('openwatch/report-snapshot/v1');
    // The detail renders a Signed badge + a Verify control gated on the
    // signature, calling onVerify and surfacing a verifyResult.
    expect(PAGE_SRC).toContain('Signed');
    expect(PAGE_SRC).toMatch(/onVerify\(resolved\)/);
    expect(PAGE_SRC).toContain('verifyResult');
  });

  // @ac AC-09
  test('frontend-reports/AC-09 — framework lens picker (fleet catalog)', () => {
    // A framework select bound to scopeFramework, defaulting to "All frameworks".
    expect(PAGE_SRC).toContain('scopeFramework');
    expect(PAGE_SRC).toMatch(/<select[\s\S]*?value=\{scopeFramework\}/);
    expect(PAGE_SRC).toContain('<option value="">All frameworks</option>');
    // Options come from a ['report-frameworks'] query against the catalog.
    expect(PAGE_SRC).toContain("queryKey: ['report-frameworks']");
    expect(PAGE_SRC).toContain("api.GET('/api/v1/reports/frameworks'");
    // The generate body sets framework when chosen (alongside group_id).
    expect(PAGE_SRC).toMatch(/if \(scopeFramework\) body\.framework = scopeFramework/);
  });

  // @ac AC-10
  test('frontend-reports/AC-10 — report-kind selector + kind-aware download', () => {
    // A kind select bound to reportKind, defaulting to executive.
    expect(PAGE_SRC).toContain('reportKind');
    expect(PAGE_SRC).toMatch(/<select[\s\S]*?value=\{reportKind\}/);
    expect(PAGE_SRC).toContain('aria-label="Report kind"');
    // The generate body sets kind for any non-executive kind (executive is
    // the implicit default).
    expect(PAGE_SRC).toMatch(/if \(reportKind !== 'executive'\) body\.kind = reportKind/);
    // The primary download is kind-aware: csv face for the csv-led kinds
    // (attestation, exception), pdf otherwise, with a label switch.
    expect(PAGE_SRC).toMatch(/primaryFace[^\n]*csvLed \? 'csv' : 'pdf'/);
    expect(PAGE_SRC).toContain('Download CSV');
    // downloadReportFace accepts the csv format.
    expect(PAGE_SRC).toMatch(/format: 'pdf' \| 'json' \| 'csv'/);
    // The type chip labels attestation reports "Attestation".
    expect(PAGE_SRC).toMatch(/kind === 'attestation'\) return 'Attestation'/);
  });

  // @ac AC-11
  test('frontend-reports/AC-11 — secondary attestation faces (PDF + OSCAL SAR)', () => {
    // A secondaryFaces list keyed on the report kind.
    expect(PAGE_SRC).toContain('secondaryFaces');
    expect(PAGE_SRC).toMatch(/secondaryFaces[\s\S]*?kind === 'attestation'/);
    // It offers the PDF cover and the OSCAL SAR faces.
    expect(PAGE_SRC).toMatch(/face: 'pdf'/);
    expect(PAGE_SRC).toMatch(/face: 'oscal_sar'/);
    expect(PAGE_SRC).toContain('OSCAL SAR');
    // Rendered as buttons wired to the shared onDownload + downloading state.
    expect(PAGE_SRC).toMatch(/secondaryFaces\.map/);
    expect(PAGE_SRC).toMatch(/onDownload\(f\.face\)/);
    // downloadReportFace's format union includes oscal_sar.
    expect(PAGE_SRC).toMatch(/format: 'pdf' \| 'json' \| 'csv' \| 'oscal_sar'/);
  });

  // @ac AC-12
  test('frontend-reports/AC-12 — kind-aware body renders the frozen attestation rollup', () => {
    // The detail body branches on the resolved kind.
    expect(PAGE_SRC).toMatch(/resolved\.kind === 'attestation' \?/);
    expect(PAGE_SRC).toMatch(
      /<AttestationBody content=\{asAttestationContent\(resolved\.content\)\}/,
    );
    expect(PAGE_SRC).toMatch(/<ExecutiveBody content=\{asExecutiveContent\(resolved\.content\)\}/);
    // asAttestationContent narrows the attestation keys incl. the frozen rollup.
    expect(PAGE_SRC).toContain('function asAttestationContent');
    expect(PAGE_SRC).toMatch(/hosts_attested:/);
    expect(PAGE_SRC).toContain('function asAttestationRollup');
    // AttestationBody reads the rollup and renders compliance + pass/fail +
    // the top-failing table (not the executive content keys).
    expect(PAGE_SRC).toContain('function AttestationBody');
    expect(PAGE_SRC).toMatch(/const r = content\.rollup/);
    expect(PAGE_SRC).toContain('Hosts attested');
    expect(PAGE_SRC).toContain('Framework');
    expect(PAGE_SRC).toMatch(/r\.compliance_pct/);
    expect(PAGE_SRC).toMatch(/r\.passing/);
    expect(PAGE_SRC).toMatch(/r\.failing/);
    expect(PAGE_SRC).toMatch(/r\.top_failing\.map/);
  });

  // @ac AC-13
  test('frontend-reports/AC-13 — exception register kind (selector option + body)', () => {
    // The kind selector offers the Exception Register option.
    expect(PAGE_SRC).toContain('<option value="exception">Exception Register</option>');
    // kindLabel maps exception to "Exception Register".
    expect(PAGE_SRC).toMatch(/kind === 'exception'\) return 'Exception Register'/);
    // The detail body branches to ExceptionBody for the exception kind.
    expect(PAGE_SRC).toMatch(/resolved\.kind === 'exception' \?/);
    expect(PAGE_SRC).toMatch(/<ExceptionBody content=\{asExceptionContent\(resolved\.content\)\}/);
    // asExceptionContent narrows the register keys; ExceptionBody renders the
    // waiver summary + the soonest-expiring list (not executive/attestation keys).
    expect(PAGE_SRC).toContain('function asExceptionContent');
    expect(PAGE_SRC).toContain('function ExceptionBody');
    expect(PAGE_SRC).toMatch(/content\.summary/);
    expect(PAGE_SRC).toContain('Total waivers');
    expect(PAGE_SRC).toContain('Pending review');
    // The exception kind leads with the CSV register (csvLed covers it).
    expect(PAGE_SRC).toMatch(/csvLed = kind === 'attestation' \|\| kind === 'exception'/);
  });

  // @ac AC-04
  test('frontend-reports/AC-04 — generate is the only mutation, tokens, no em-dash', () => {
    // The only mutating call is the generate POST; no PUT/DELETE.
    expect(PAGE_SRC.includes('api.PUT')).toBe(false);
    expect(PAGE_SRC.includes('api.DELETE')).toBe(false);
    const posts = PAGE_SRC.split('api.POST(').length - 1;
    expect(posts).toBe(1);
    // Chrome is styled with --ow-* tokens, not raw hex literals.
    expect(PAGE_SRC).toContain('var(--ow-bg-1)');
    expect(PAGE_SRC).toContain('var(--ow-line)');
    // No prose copy carries an em-dash (the one em-dash is a leading code
    // comment, which is exempt and stripped before the assertion).
    expect(stripComments(PAGE_SRC).includes('—')).toBe(false);
  });
});
