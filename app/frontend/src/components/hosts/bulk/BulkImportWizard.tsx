import { useState } from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import type { CSVAnalysis, FieldMapping, ImportOptions } from './types';
import { CSVUploadStep } from './CSVUploadStep';
import { FieldMapperStep, mappingsAreValid } from './FieldMapperStep';
import { PreviewImportStep } from './PreviewImportStep';
import { ghostBtn, primaryBtn } from './wizardStyles';

// 3-step bulk-import wizard. Mirrors the Python frontend's
// EnhancedBulkImportDialog flow: Upload → Map → Preview & Import.

type StepIdx = 0 | 1 | 2;

const STEP_LABELS = ['Upload CSV', 'Map fields', 'Preview & import'] as const;

export function BulkImportWizard() {
  const [step, setStep] = useState<StepIdx>(0);
  const [csvText, setCsvText] = useState<string>('');
  const [fileName, setFileName] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<CSVAnalysis | null>(null);
  const [mappings, setMappings] = useState<FieldMapping[]>([]);
  const [options, setOptions] = useState<ImportOptions>({ dryRun: false, updateExisting: false });

  const handleAnalyzed = (text: string, name: string, a: CSVAnalysis) => {
    setCsvText(text);
    setFileName(name);
    setAnalysis(a);
    // Seed mappings from auto_mappings.
    const seeded: FieldMapping[] = a.headers.map((col) => ({
      source_column: col,
      target_field: a.auto_mappings[col] ?? '',
    }));
    setMappings(seeded);
  };

  const canNext =
    (step === 0 && analysis !== null) ||
    (step === 1 && mappingsAreValid(mappings)) ||
    step === 2;

  return (
    <div>
      <Stepper currentStep={step} />

      {step === 0 && <CSVUploadStep initialFileName={fileName} onAnalyzed={handleAnalyzed} />}
      {step === 1 && analysis && (
        <FieldMapperStep analysis={analysis} mappings={mappings} onChange={setMappings} />
      )}
      {step === 2 && analysis && (
        <PreviewImportStep
          csvText={csvText}
          mappings={mappings}
          options={options}
          onOptionsChange={setOptions}
        />
      )}

      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginTop: 16,
          paddingTop: 16,
          borderTop: '1px solid var(--ow-line)',
        }}
      >
        <button
          type="button"
          onClick={() => setStep((s) => (s > 0 ? ((s - 1) as StepIdx) : s))}
          disabled={step === 0}
          style={{
            ...ghostBtn,
            display: 'inline-flex',
            alignItems: 'center',
            gap: 4,
            opacity: step === 0 ? 0.4 : 1,
            cursor: step === 0 ? 'not-allowed' : 'pointer',
          }}
        >
          <ChevronLeft size={14} />
          Back
        </button>

        {step < 2 ? (
          <button
            type="button"
            onClick={() => setStep((s) => Math.min(2, s + 1) as StepIdx)}
            disabled={!canNext}
            style={{
              ...primaryBtn,
              display: 'inline-flex',
              alignItems: 'center',
              gap: 4,
              opacity: canNext ? 1 : 0.5,
              cursor: canNext ? 'pointer' : 'not-allowed',
            }}
          >
            Next
            <ChevronRight size={14} />
          </button>
        ) : (
          <span style={{ fontSize: 12, color: 'var(--ow-fg-3)' }}>
            Use the Import button in the preview to submit.
          </span>
        )}
      </div>
    </div>
  );
}

function Stepper({ currentStep }: { currentStep: StepIdx }) {
  return (
    <ol
      style={{
        display: 'flex',
        gap: 0,
        padding: 0,
        margin: '0 0 18px',
        listStyle: 'none',
        borderBottom: '1px solid var(--ow-line)',
      }}
      aria-label="Bulk-import progress"
    >
      {STEP_LABELS.map((label, idx) => {
        const isActive = idx === currentStep;
        const isDone = idx < currentStep;
        const color = isActive
          ? 'var(--ow-info)'
          : isDone
          ? 'var(--ow-ok)'
          : 'var(--ow-fg-3)';
        return (
          <li
            key={label}
            aria-current={isActive ? 'step' : undefined}
            style={{
              padding: '10px 14px',
              fontSize: 12,
              fontWeight: isActive ? 600 : 500,
              color,
              borderBottom: isActive ? '2px solid var(--ow-info)' : '2px solid transparent',
              marginBottom: -1,
              display: 'inline-flex',
              alignItems: 'center',
              gap: 8,
            }}
          >
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: 18,
                height: 18,
                borderRadius: 9,
                background: isActive
                  ? 'var(--ow-info)'
                  : isDone
                  ? 'var(--ow-ok)'
                  : 'var(--ow-bg-2)',
                color: isActive || isDone ? 'var(--ow-info-on, #fff)' : 'var(--ow-fg-2)',
                fontSize: 11,
                fontWeight: 600,
              }}
            >
              {idx + 1}
            </span>
            {label}
          </li>
        );
      })}
    </ol>
  );
}
