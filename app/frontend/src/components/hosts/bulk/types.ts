// Bulk import — shared types.
//
// Direct port of the OpenWatch Python frontend's EnhancedBulkImportDialog
// shape so the operator UX matches across the two codebases. The Python
// backend ran analysis server-side via /api/bulk/hosts/analyze-csv; the
// Go rebuild has no equivalent endpoint, so analysis runs client-side
// inside csvAnalysis.ts (see also BACKLOG.md for the deferred backend
// endpoint that would re-enable smart template detection).

export interface FieldAnalysis {
  /** Source column name as it appears in the CSV header. */
  column_name: string;
  /** Inferred type — ip_address, hostname, integer, text, boolean, etc. */
  detected_type: string;
  /** 0..1 confidence in the type detection. */
  confidence: number;
  /** First few non-empty values, for the operator to scan. */
  sample_values: string[];
  /** Unique-value count across all rows. */
  unique_count: number;
  /** How many rows had this column empty. */
  null_count: number;
  /** Suggested host-create target fields (in order of likelihood). */
  suggestions: string[];
}

export interface CSVAnalysis {
  total_rows: number;
  total_columns: number;
  headers: string[];
  field_analyses: FieldAnalysis[];
  /** source_column → target_field (e.g. "Hostname" → "hostname"). */
  auto_mappings: Record<string, string>;
  /** Identified import templates (vCenter, Satellite, AWS EC2, etc.). */
  template_matches: string[];
}

export interface FieldMapping {
  source_column: string;
  /** Empty string when the source column is intentionally skipped. */
  target_field: string;
  transform_function?: string;
}

export interface ImportRowOutcome {
  row: number;
  hostname: string;
  status: 'created' | 'updated' | 'skipped' | 'failed' | 'pending';
  action?: 'create' | 'update';
  error?: string;
  hostId?: string;
}

export interface ImportResult {
  total_processed: number;
  successful_imports: number;
  failed_imports: number;
  skipped_duplicates: number;
  errors: Array<{ row: number; hostname: string; error: string }>;
  imported_hosts: Array<{ hostname: string; ip_address: string; action: 'create' | 'update' }>;
  /** Per-row detail, in source order. */
  outcomes: ImportRowOutcome[];
}

export interface ImportOptions {
  updateExisting: boolean;
  dryRun: boolean;
  /** Which credential strategy applies to every imported host. */
  credentialMode: 'system_default' | 'clone_template';
  /** When credentialMode === 'clone_template', the source credential id
   *  to clone into a host-scoped row for each created host. */
  cloneSourceId?: string;
}

export interface TargetField {
  value: string;
  label: string;
  required: boolean;
  description: string;
}

// Maps onto HostCreateRequest in the Go API. Stays in sync with
// app/api/openapi.yaml § HostCreateRequest.
export const TARGET_FIELDS: TargetField[] = [
  { value: 'hostname', label: 'Hostname', required: true, description: 'System hostname or name' },
  { value: 'ip_address', label: 'IP Address', required: true, description: 'IPv4 or IPv6 address' },
  { value: 'display_name', label: 'Display name', required: false, description: 'Friendly display name' },
  { value: 'port', label: 'SSH port', required: false, description: 'SSH connection port (default: 22)' },
  { value: 'username', label: 'Username', required: false, description: 'SSH username' },
  { value: 'environment', label: 'Environment', required: false, description: 'Environment (prod, staging, dev)' },
  { value: 'tags', label: 'Tags', required: false, description: 'Comma-separated tags' },
  { value: 'description', label: 'Description', required: false, description: 'Free-text description' },
  { value: 'group_id', label: 'Group ID', required: false, description: 'UUID of the target group' },
];
