import type { CSVAnalysis, FieldAnalysis } from './types';

// CSV parsing, type detection, auto-mapping, and template matching.
//
// All work happens client-side. The Python backend exposed
// /api/bulk/hosts/analyze-csv with a richer template registry; the Go
// rebuild has no equivalent endpoint so this module ships an honest
// subset (~7 source patterns, basic templates). See BACKLOG.md for
// the deferred backend endpoint that would unlock the full surface.

// ─────────────────────────────────────────────────────────────────────────
// CSV parser — RFC 4180-ish, handles quoted fields with embedded commas
// ─────────────────────────────────────────────────────────────────────────

export function parseCSV(text: string): { headers: string[]; rows: string[][] } {
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  const out: string[][] = [];
  for (const line of lines) {
    if (line.length === 0) continue;
    out.push(parseRow(line));
  }
  if (out.length === 0) return { headers: [], rows: [] };
  const headers = (out[0] ?? []).map((h) => h.trim());
  const rows = out.slice(1).filter((r) => r.some((c) => c.trim().length > 0));
  return { headers, rows };
}

function parseRow(line: string): string[] {
  const cells: string[] = [];
  let i = 0;
  while (i < line.length) {
    if (line[i] === '"') {
      // Quoted field
      i++;
      let v = '';
      while (i < line.length) {
        if (line[i] === '"') {
          if (line[i + 1] === '"') {
            // Escaped quote
            v += '"';
            i += 2;
          } else {
            i++;
            break;
          }
        } else {
          v += line[i];
          i++;
        }
      }
      cells.push(v);
      // Consume trailing comma if present
      if (line[i] === ',') i++;
    } else {
      // Unquoted field — read until comma
      let v = '';
      while (i < line.length && line[i] !== ',') {
        v += line[i];
        i++;
      }
      cells.push(v);
      if (line[i] === ',') i++;
    }
  }
  return cells;
}

// ─────────────────────────────────────────────────────────────────────────
// Type detection
// ─────────────────────────────────────────────────────────────────────────

const RE_IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const RE_IPV6 = /^[0-9a-fA-F:]{2,}$/;
const RE_HOSTNAME = /^[a-zA-Z0-9]([a-zA-Z0-9-.]*[a-zA-Z0-9])?$/;
const RE_UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const RE_INTEGER = /^-?\d+$/;
const RE_BOOLEAN = /^(true|false|yes|no|y|n|1|0)$/i;

export function detectType(values: string[]): { type: string; confidence: number } {
  const cleaned = values.filter((v) => v.trim().length > 0).slice(0, 100);
  if (cleaned.length === 0) return { type: 'text', confidence: 0 };

  let ipv4 = 0;
  let ipv6 = 0;
  let hostname = 0;
  let uuid = 0;
  let integer = 0;
  let bool = 0;

  for (const v of cleaned) {
    const trimmed = v.trim();
    if (RE_IPV4.test(trimmed)) ipv4++;
    else if (RE_IPV6.test(trimmed) && trimmed.includes(':')) ipv6++;
    if (RE_HOSTNAME.test(trimmed)) hostname++;
    if (RE_UUID.test(trimmed)) uuid++;
    if (RE_INTEGER.test(trimmed)) integer++;
    if (RE_BOOLEAN.test(trimmed)) bool++;
  }

  const total = cleaned.length;
  const candidates: { type: string; score: number }[] = [
    { type: 'ip_address', score: (ipv4 + ipv6) / total },
    { type: 'uuid', score: uuid / total },
    { type: 'integer', score: integer / total },
    { type: 'boolean', score: bool / total },
    { type: 'hostname', score: hostname / total },
  ];
  candidates.sort((a, b) => b.score - a.score);
  const top = candidates[0];
  if (!top || top.score < 0.5) return { type: 'text', confidence: 0.3 };
  return { type: top.type, confidence: top.score };
}

// ─────────────────────────────────────────────────────────────────────────
// Auto-mapping
// ─────────────────────────────────────────────────────────────────────────

// Source-column patterns we recognize, in priority order. Matching is
// case-insensitive substring against the normalized header.
const COLUMN_PATTERNS: Array<{ target: string; patterns: RegExp[] }> = [
  {
    target: 'hostname',
    patterns: [
      /^hostname$/i,
      /^host$/i,
      /^name$/i,
      /^server[\s_-]?name$/i,
      /^vm[\s_-]?name$/i,
      /^machine[\s_-]?name$/i,
      /^fqdn$/i,
      /^instance[\s_-]?name$/i,
    ],
  },
  {
    target: 'ip_address',
    patterns: [
      /^ip[\s_-]?address$/i,
      /^ip$/i,
      /^ipv4$/i,
      /^private[\s_-]?ip[\s_-]?address$/i,
      /^internal[\s_-]?ip$/i,
      /^primary[\s_-]?ip$/i,
      /^management[\s_-]?ip$/i,
    ],
  },
  {
    target: 'display_name',
    patterns: [/^display[\s_-]?name$/i, /^friendly[\s_-]?name$/i, /^alias$/i, /^label$/i],
  },
  {
    target: 'port',
    patterns: [/^port$/i, /^ssh[\s_-]?port$/i, /^connection[\s_-]?port$/i, /^tcp[\s_-]?port$/i],
  },
  {
    target: 'username',
    patterns: [/^user(name)?$/i, /^ssh[\s_-]?user(name)?$/i, /^login$/i, /^account$/i],
  },
  {
    target: 'environment',
    patterns: [/^environment$/i, /^env$/i, /^stage$/i, /^tier$/i],
  },
  {
    target: 'tags',
    patterns: [/^tags?$/i, /^labels?$/i, /^categories$/i],
  },
  {
    target: 'description',
    patterns: [/^description$/i, /^notes?$/i, /^comments?$/i, /^remarks?$/i],
  },
  {
    target: 'group_id',
    patterns: [/^group[\s_-]?id$/i, /^groupid$/i, /^team[\s_-]?id$/i],
  },
];

function autoMapColumn(columnName: string): string | null {
  for (const { target, patterns } of COLUMN_PATTERNS) {
    for (const re of patterns) {
      if (re.test(columnName.trim())) return target;
    }
  }
  return null;
}

// ─────────────────────────────────────────────────────────────────────────
// Template detection
// ─────────────────────────────────────────────────────────────────────────

const TEMPLATES: Array<{ name: string; required: string[]; bonus?: string[] }> = [
  {
    name: 'VMware vCenter',
    required: ['vm name', 'hostname'],
    bonus: ['power state', 'guest os', 'host', 'cluster'],
  },
  {
    name: 'Red Hat Satellite',
    required: ['name', 'ip'],
    bonus: ['organization', 'location', 'subscription_status', 'lifecycle environment'],
  },
  {
    name: 'AWS EC2',
    required: ['instanceid', 'privateipaddress'],
    bonus: ['publicdnsname', 'vpcid', 'subnetid', 'instancetype', 'availabilityzone'],
  },
  {
    name: 'Azure VMs',
    required: ['name', 'resource group'],
    bonus: ['private ip address', 'public ip address', 'subscription', 'location'],
  },
  {
    name: 'Generic CSV',
    required: ['hostname', 'ip_address'],
  },
];

function detectTemplates(headers: string[]): string[] {
  const normalizedHeaders = new Set(headers.map((h) => h.toLowerCase().trim()));
  const matches: string[] = [];
  for (const tmpl of TEMPLATES) {
    if (tmpl.required.every((r) => normalizedHeaders.has(r))) {
      matches.push(tmpl.name);
    }
  }
  return matches;
}

// ─────────────────────────────────────────────────────────────────────────
// Public entrypoint
// ─────────────────────────────────────────────────────────────────────────

export function analyzeCSV(text: string): CSVAnalysis {
  const { headers, rows } = parseCSV(text);
  const auto_mappings: Record<string, string> = {};
  const field_analyses: FieldAnalysis[] = [];

  for (let i = 0; i < headers.length; i++) {
    const col = headers[i] ?? '';
    const values = rows.map((r) => r[i] ?? '');
    const nonEmpty = values.filter((v) => v.trim().length > 0);
    const { type, confidence } = detectType(values);
    const target = autoMapColumn(col);
    if (target) auto_mappings[col] = target;
    const seen = new Set(nonEmpty);
    field_analyses.push({
      column_name: col,
      detected_type: type,
      confidence,
      sample_values: nonEmpty.slice(0, 3),
      unique_count: seen.size,
      null_count: values.length - nonEmpty.length,
      suggestions: target ? [target] : [],
    });
  }

  return {
    total_rows: rows.length,
    total_columns: headers.length,
    headers,
    field_analyses,
    auto_mappings,
    template_matches: detectTemplates(headers),
  };
}
