import { z } from 'zod';
import type { FieldMapping } from './types';
import { parseCSV } from './csvAnalysis';

// Apply field mappings to raw CSV → typed host-create payloads, with
// per-row validation against the same zod schema the single-host form
// uses. Pure: no I/O, no fetches.

const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const ipv6 = /^[0-9a-fA-F:]+$/;
const hostnameRe = /^[a-zA-Z0-9]([a-zA-Z0-9-.]*[a-zA-Z0-9])?$/;

const hostCreateSchema = z.object({
  hostname: z.string().min(1).max(256).regex(hostnameRe, 'Invalid hostname'),
  ip_address: z
    .string()
    .min(1)
    .max(64)
    .refine((v) => ipv4.test(v) || ipv6.test(v), 'Invalid IP'),
  port: z.number().int().min(1).max(65535).optional(),
  display_name: z.string().max(256).optional(),
  environment: z.string().max(64).optional(),
  username: z.string().max(256).optional(),
  tags: z.array(z.string().max(64)).optional(),
  description: z.string().max(1024).optional(),
  group_id: z.string().uuid().nullable().optional(),
});

export type HostCreatePayload = z.infer<typeof hostCreateSchema>;

export interface MappedRow {
  index: number;
  rawRow: Record<string, string>;
  payload?: HostCreatePayload;
  validationError?: string;
}

export function applyMappings(csvText: string, mappings: FieldMapping[]): MappedRow[] {
  const { headers, rows } = parseCSV(csvText);
  const headerIndex = new Map<string, number>();
  headers.forEach((h, i) => headerIndex.set(h, i));

  const out: MappedRow[] = [];

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i] ?? [];
    const rawRow: Record<string, string> = {};
    for (const [col, idx] of headerIndex) {
      rawRow[col] = row[idx] ?? '';
    }

    // Build the candidate payload by reading each mapped source column.
    const candidate: Record<string, unknown> = {};
    for (const m of mappings) {
      if (!m.target_field) continue; // operator chose "(skip)"
      const idx = headerIndex.get(m.source_column);
      if (idx === undefined) continue;
      const value = (row[idx] ?? '').trim();
      if (value.length === 0) continue;

      switch (m.target_field) {
        case 'port':
          candidate.port = Number(value);
          break;
        case 'tags':
          candidate.tags = value.split(/\s*,\s*/).filter((s) => s.length > 0);
          break;
        case 'group_id':
          candidate.group_id = value;
          break;
        default:
          candidate[m.target_field] = value;
      }
    }

    const parse = hostCreateSchema.safeParse(candidate);
    if (parse.success) {
      out.push({ index: i, rawRow, payload: parse.data });
    } else {
      const issue = parse.error.issues[0];
      out.push({
        index: i,
        rawRow,
        validationError: issue
          ? `${issue.path.join('.') || 'row'}: ${issue.message}`
          : 'validation failed',
      });
    }
  }

  return out;
}

export function downloadFailedRowsCSV(rows: MappedRow[]): void {
  const headers = ['hostname', 'ip_address', 'environment', 'failure_reason'];
  const lines = [headers.join(',')];
  for (const r of rows) {
    if (!r.validationError) continue;
    const row = [
      r.rawRow['hostname'] ?? r.payload?.hostname ?? '',
      r.rawRow['ip_address'] ?? r.payload?.ip_address ?? '',
      r.rawRow['environment'] ?? r.payload?.environment ?? '',
      `"${r.validationError.replace(/"/g, '""')}"`,
    ];
    lines.push(row.join(','));
  }
  const csv = lines.join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'failed-rows.csv';
  a.click();
  URL.revokeObjectURL(url);
}
