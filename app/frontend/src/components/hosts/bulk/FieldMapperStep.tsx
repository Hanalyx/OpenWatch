import { useMemo } from 'react';
import { AlertCircle, CheckCircle2 } from 'lucide-react';
import type { CSVAnalysis, FieldMapping } from './types';
import { TARGET_FIELDS } from './types';
import { card, cardBody, cardHeader, errorPanel, infoPanel, select, td, th } from './wizardStyles';

// Step 2: operator reviews / overrides field mappings.
//
// One row per source column. Each row gets a <select> populated with the
// 9 target fields plus "(skip)". hostname + ip_address are required —
// the wizard blocks Next until both are mapped.

interface Props {
  analysis: CSVAnalysis;
  mappings: FieldMapping[];
  onChange: (mappings: FieldMapping[]) => void;
}

const SKIP = '';

export function FieldMapperStep({ analysis, mappings, onChange }: Props) {
  // mappings are keyed by source column. Initialize from auto_mappings on
  // first render if the parent hasn't seeded anything yet.
  const indexed = useMemo(() => {
    const m = new Map<string, string>();
    for (const fm of mappings) m.set(fm.source_column, fm.target_field);
    return m;
  }, [mappings]);

  const updateMapping = (source: string, target: string) => {
    const next: FieldMapping[] = analysis.headers.map((col) => ({
      source_column: col,
      target_field: col === source ? target : indexed.get(col) ?? '',
    }));
    onChange(next);
  };

  // Validation: every required target field must be mapped exactly once.
  const targetCounts = new Map<string, number>();
  for (const fm of mappings) {
    if (fm.target_field === SKIP) continue;
    targetCounts.set(fm.target_field, (targetCounts.get(fm.target_field) ?? 0) + 1);
  }
  const missingRequired = TARGET_FIELDS.filter((t) => t.required && !targetCounts.has(t.value));
  const duplicates = [...targetCounts.entries()].filter(([, c]) => c > 1).map(([k]) => k);

  return (
    <>
      <section style={card}>
        <header style={cardHeader}>Map fields</header>
        <div style={cardBody}>
          <p style={{ margin: '0 0 12px', fontSize: 12, color: 'var(--ow-fg-2)' }}>
            Match each source column to a destination field on the host record. Auto-mapped fields are pre-filled;
            override any row that looks wrong, or pick <em>(skip)</em> to ignore a column.
          </p>

          {missingRequired.length > 0 && (
            <div role="alert" style={errorPanel}>
              <AlertCircle size={12} style={{ verticalAlign: 'middle', marginRight: 6 }} />
              Missing required field{missingRequired.length === 1 ? '' : 's'}:{' '}
              {missingRequired.map((f) => f.label).join(', ')}.
            </div>
          )}
          {duplicates.length > 0 && (
            <div role="alert" style={errorPanel}>
              <AlertCircle size={12} style={{ verticalAlign: 'middle', marginRight: 6 }} />
              These target fields are mapped from more than one column:{' '}
              <code style={{ fontFamily: 'var(--ow-font-mono)' }}>{duplicates.join(', ')}</code>. Pick only one source
              for each.
            </div>
          )}
          {missingRequired.length === 0 && duplicates.length === 0 && (
            <div style={infoPanel}>
              <CheckCircle2
                size={12}
                color="var(--ow-ok)"
                style={{ verticalAlign: 'middle', marginRight: 6 }}
              />
              Mapping is valid. Continue to preview the rows.
            </div>
          )}

          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ background: 'var(--ow-bg-2)' }}>
                <th style={th}>Source column</th>
                <th style={th}>Sample</th>
                <th style={th}>Maps to</th>
              </tr>
            </thead>
            <tbody>
              {analysis.field_analyses.map((f) => {
                const current = indexed.get(f.column_name) ?? SKIP;
                return (
                  <tr key={f.column_name} style={{ borderTop: '1px solid var(--ow-line)' }}>
                    <td style={{ ...td, fontFamily: 'var(--ow-font-mono)', color: 'var(--ow-fg-0)' }}>
                      {f.column_name}
                    </td>
                    <td style={{ ...td, fontFamily: 'var(--ow-font-mono)', color: 'var(--ow-fg-2)' }}>
                      {f.sample_values[0] ?? '—'}
                    </td>
                    <td style={td}>
                      <select
                        aria-label={`Map ${f.column_name} to`}
                        value={current}
                        onChange={(e) => updateMapping(f.column_name, e.target.value)}
                        style={select}
                      >
                        <option value={SKIP}>(skip)</option>
                        {TARGET_FIELDS.map((t) => (
                          <option key={t.value} value={t.value}>
                            {t.label}
                            {t.required ? ' *' : ''}
                          </option>
                        ))}
                      </select>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      <section style={card}>
        <header style={cardHeader}>Target field reference</header>
        <div style={{ ...cardBody, padding: 0 }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ background: 'var(--ow-bg-2)' }}>
                <th style={th}>Field</th>
                <th style={th}>Required</th>
                <th style={th}>Description</th>
              </tr>
            </thead>
            <tbody>
              {TARGET_FIELDS.map((t) => (
                <tr key={t.value} style={{ borderTop: '1px solid var(--ow-line)' }}>
                  <td style={{ ...td, fontFamily: 'var(--ow-font-mono)', color: 'var(--ow-fg-0)' }}>{t.value}</td>
                  <td style={td}>
                    {t.required ? (
                      <span style={{ color: 'var(--ow-crit)' }}>required</span>
                    ) : (
                      <span style={{ color: 'var(--ow-fg-3)' }}>optional</span>
                    )}
                  </td>
                  <td style={td}>{t.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}

export function mappingsAreValid(mappings: FieldMapping[]): boolean {
  const set = new Set<string>();
  const dups = new Set<string>();
  for (const fm of mappings) {
    if (fm.target_field === '') continue;
    if (set.has(fm.target_field)) dups.add(fm.target_field);
    set.add(fm.target_field);
  }
  if (dups.size > 0) return false;
  return TARGET_FIELDS.filter((t) => t.required).every((t) => set.has(t.value));
}
