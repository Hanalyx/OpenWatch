import { useCallback, useState } from 'react';
import { useDropzone } from 'react-dropzone';
import { Upload, FileText, CheckCircle2, AlertCircle } from 'lucide-react';
import type { CSVAnalysis } from './types';
import { analyzeCSV } from './csvAnalysis';
import { card, cardBody, cardHeader, errorPanel, infoPanel, td, th } from './wizardStyles';

// Step 1 of the bulk-import wizard: file drop + client-side CSV analysis.
//
// Mirrors the Python frontend's CSVAnalyzer.tsx UX (drag-drop area, per-
// column type detection table, template-match callouts) but analysis runs
// fully in the browser — the Go backend has no /analyze-csv endpoint.

interface Props {
  initialFileName: string | null;
  onAnalyzed: (csvText: string, fileName: string, analysis: CSVAnalysis) => void;
}

const MAX_BYTES = 5 * 1024 * 1024; // 5 MB — matches the Python upload cap.

export function CSVUploadStep({ initialFileName, onAnalyzed }: Props) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [fileName, setFileName] = useState<string | null>(initialFileName);
  const [analysis, setAnalysis] = useState<CSVAnalysis | null>(null);

  const ingest = useCallback(
    async (file: File) => {
      setError(null);
      if (file.size > MAX_BYTES) {
        setError(
          `File is larger than 5 MB (${(file.size / 1024 / 1024).toFixed(1)} MB). Split it into smaller files.`,
        );
        return;
      }
      setBusy(true);
      try {
        const text = await file.text();
        if (text.trim().length === 0) {
          setError('File is empty.');
          return;
        }
        const result = analyzeCSV(text);
        if (result.headers.length === 0) {
          setError('No header row detected. The first non-empty line must contain column names.');
          return;
        }
        if (result.total_rows === 0) {
          setError('Header row found, but no data rows. Add at least one host row.');
          return;
        }
        setFileName(file.name);
        setAnalysis(result);
        onAnalyzed(text, file.name, result);
      } catch (e) {
        setError(`Failed to analyze CSV: ${(e as Error).message}`);
      } finally {
        setBusy(false);
      }
    },
    [onAnalyzed],
  );

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    accept: { 'text/csv': ['.csv'], 'text/plain': ['.txt'] },
    multiple: false,
    onDrop: (accepted) => {
      const f = accepted[0];
      if (f) void ingest(f);
    },
  });

  return (
    <>
      <section style={card}>
        <header style={cardHeader}>Upload CSV</header>
        <div style={cardBody}>
          <div
            {...getRootProps()}
            style={{
              border: `2px dashed ${isDragActive ? 'var(--ow-info)' : 'var(--ow-line)'}`,
              borderRadius: 'var(--ow-radius)',
              padding: '32px 16px',
              textAlign: 'center',
              cursor: 'pointer',
              background: isDragActive ? 'var(--ow-bg-2)' : 'transparent',
              transition: 'background 120ms ease, border-color 120ms ease',
            }}
          >
            <input {...getInputProps()} />
            <Upload size={28} color="var(--ow-fg-2)" />
            <div style={{ marginTop: 10, fontSize: 14, color: 'var(--ow-fg-0)' }}>
              {busy
                ? 'Analyzing…'
                : isDragActive
                  ? 'Drop the file to upload'
                  : 'Drag and drop a CSV file, or click to choose one'}
            </div>
            <div style={{ marginTop: 4, fontSize: 12, color: 'var(--ow-fg-3)' }}>
              Up to 5 MB. The first row must contain column names.
            </div>
          </div>

          {fileName && !error && (
            <div style={infoPanel}>
              <FileText size={12} style={{ verticalAlign: 'middle', marginRight: 6 }} />
              <strong>{fileName}</strong>
              {analysis && (
                <span style={{ color: 'var(--ow-fg-2)' }}>
                  {' '}
                  — {analysis.total_rows} row{analysis.total_rows === 1 ? '' : 's'},{' '}
                  {analysis.total_columns} column
                  {analysis.total_columns === 1 ? '' : 's'}
                </span>
              )}
            </div>
          )}

          {error && (
            <div role="alert" style={errorPanel}>
              <AlertCircle size={12} style={{ verticalAlign: 'middle', marginRight: 6 }} />
              {error}
            </div>
          )}
        </div>
      </section>

      {analysis && analysis.template_matches.length > 0 && (
        <section style={card}>
          <header style={cardHeader}>Detected templates</header>
          <div style={cardBody}>
            <p style={{ margin: '0 0 10px', fontSize: 12, color: 'var(--ow-fg-2)' }}>
              These headers look like exports from the following sources. We'll pre-fill mappings on
              the next step.
            </p>
            <ul style={{ margin: 0, paddingLeft: 18, fontSize: 13 }}>
              {analysis.template_matches.map((t) => (
                <li key={t} style={{ marginBottom: 4 }}>
                  <CheckCircle2
                    size={12}
                    color="var(--ow-ok)"
                    style={{ verticalAlign: 'middle', marginRight: 6 }}
                  />
                  {t}
                </li>
              ))}
            </ul>
          </div>
        </section>
      )}

      {analysis && (
        <section style={card}>
          <header style={cardHeader}>Column analysis</header>
          <div style={{ ...cardBody, padding: 0 }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ background: 'var(--ow-bg-2)' }}>
                  <th style={th}>Column</th>
                  <th style={th}>Detected type</th>
                  <th style={th}>Auto-mapped to</th>
                  <th style={th}>Sample values</th>
                </tr>
              </thead>
              <tbody>
                {analysis.field_analyses.map((f) => {
                  const mapped = analysis.auto_mappings[f.column_name];
                  const confidencePct = Math.round(f.confidence * 100);
                  const confColor =
                    f.confidence >= 0.8
                      ? 'var(--ow-ok)'
                      : f.confidence >= 0.5
                        ? 'var(--ow-warn)'
                        : 'var(--ow-fg-3)';
                  return (
                    <tr key={f.column_name} style={{ borderTop: '1px solid var(--ow-line)' }}>
                      <td
                        style={{
                          ...td,
                          fontFamily: 'var(--ow-font-mono)',
                          color: 'var(--ow-fg-0)',
                        }}
                      >
                        {f.column_name}
                      </td>
                      <td style={td}>
                        <span style={{ color: 'var(--ow-fg-0)' }}>{f.detected_type}</span>
                        {f.confidence > 0 && (
                          <span style={{ marginLeft: 6, color: confColor, fontSize: 11 }}>
                            {confidencePct}%
                          </span>
                        )}
                      </td>
                      <td style={td}>
                        {mapped ? (
                          <code
                            style={{ fontFamily: 'var(--ow-font-mono)', color: 'var(--ow-info)' }}
                          >
                            {mapped}
                          </code>
                        ) : (
                          <span style={{ color: 'var(--ow-fg-3)' }}>—</span>
                        )}
                      </td>
                      <td
                        style={{
                          ...td,
                          fontFamily: 'var(--ow-font-mono)',
                          color: 'var(--ow-fg-2)',
                        }}
                      >
                        {f.sample_values.length > 0 ? f.sample_values.join(', ') : '—'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </>
  );
}
