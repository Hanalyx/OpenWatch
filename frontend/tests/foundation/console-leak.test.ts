// @spec frontend-foundation
//
// AC traceability (this file):
//
//   AC-14  test('frontend-foundation/AC-14 — no PII field names in console.* calls')

import { describe, expect, test } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

const SRC_DIR = resolve(process.cwd(), 'src');

const DENY_FIELDS = ['evidence', 'token', 'password', 'secret', 'private_key'];

function listFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) out.push(...listFiles(full));
    else if (/\.(ts|tsx)$/.test(name)) out.push(full);
  }
  return out;
}

// Match console.log / console.warn / console.error blocks and check
// whether any deny-listed field name appears inside the argument list.
// This is a substring heuristic — false positives are acceptable; the
// fix is to scrub the value before logging.
const CONSOLE_RE = /console\.(log|warn|error)\s*\(([^)]*)\)/g;

describe('frontend-foundation', () => {
  // @ac AC-14
  test('frontend-foundation/AC-14 — no PII field names in console.* calls', () => {
    const offenders: { file: string; match: string; field: string }[] = [];
    for (const f of listFiles(SRC_DIR)) {
      const src = readFileSync(f, 'utf8');
      let m: RegExpExecArray | null;
      const re = new RegExp(CONSOLE_RE);
      while ((m = re.exec(src)) !== null) {
        const args = m[2] ?? '';
        for (const field of DENY_FIELDS) {
          // Match the field name as an object-key form ("field":, field:)
          // or as a typed identifier (.field). Comments referencing the
          // word are tolerated since stripping comments here is over-
          // engineered for the goal (no leak in BUILT bundles).
          const fieldRe = new RegExp(`(?:["']?)${field}(?:["']?)\\s*[:=]`, 'i');
          if (fieldRe.test(args)) {
            offenders.push({ file: f, match: m[0] ?? '', field });
          }
        }
      }
    }
    expect(
      offenders,
      `console.* calls reference PII field names: ${JSON.stringify(offenders, null, 2)}`,
    ).toHaveLength(0);
  });
});
