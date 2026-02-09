/**
 * Audit Query Types
 *
 * TypeScript interfaces for the Audit Query Builder feature.
 *
 * Part of Phase 6: Audit Queries (Aegis Integration Plan)
 */

// =============================================================================
// Query Definition Types
// =============================================================================

export interface DateRange {
  start_date: string; // ISO date string (YYYY-MM-DD)
  end_date: string;
}

export interface QueryDefinition {
  hosts?: string[]; // UUID[]
  host_groups?: number[];
  rules?: string[];
  frameworks?: string[];
  severities?: string[];
  statuses?: string[];
  date_range?: DateRange;
}

// =============================================================================
// Saved Query Types
// =============================================================================

export interface SavedQueryCreate {
  name: string;
  description?: string;
  query_definition: QueryDefinition;
  visibility: 'private' | 'shared';
}

export interface SavedQueryUpdate {
  name?: string;
  description?: string;
  query_definition?: QueryDefinition;
  visibility?: 'private' | 'shared';
}

export interface SavedQuery {
  id: string;
  name: string;
  description: string | null;
  query_definition: QueryDefinition;
  owner_id: number;
  visibility: 'private' | 'shared';
  last_executed_at: string | null;
  execution_count: number;
  created_at: string;
  updated_at: string;
  has_date_range: boolean;
}

export interface SavedQueryListResponse {
  items: SavedQuery[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

// =============================================================================
// Query Execution Types
// =============================================================================

export interface QueryPreviewRequest {
  query_definition: QueryDefinition;
  limit?: number;
}

export interface FindingResult {
  scan_id: string;
  host_id: string;
  hostname: string;
  rule_id: string;
  title: string;
  severity: string;
  status: string;
  detail: string | null;
  framework_section: string | null;
  scanned_at: string;
}

export interface QueryPreviewResponse {
  sample_results: FindingResult[];
  total_count: number;
  has_more: boolean;
  query_definition: QueryDefinition;
}

export interface QueryExecuteRequest {
  page?: number;
  per_page?: number;
}

export interface QueryExecuteResponse {
  items: FindingResult[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
  query_id: string | null;
  executed_at: string;
}

// =============================================================================
// Audit Export Types
// =============================================================================

export type ExportFormat = 'json' | 'csv' | 'pdf';
export type ExportStatus = 'pending' | 'processing' | 'completed' | 'failed';

export interface AuditExportCreate {
  query_id?: string;
  query_definition?: QueryDefinition;
  format: ExportFormat;
}

export interface AuditExport {
  id: string;
  query_id: string | null;
  query_definition: QueryDefinition;
  format: ExportFormat;
  status: ExportStatus;
  file_path: string | null;
  file_size_bytes: number | null;
  file_checksum: string | null;
  error_message: string | null;
  requested_by: number | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  expires_at: string;
  is_ready: boolean;
  is_expired: boolean;
}

export interface AuditExportListResponse {
  items: AuditExport[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

// =============================================================================
// Statistics Types
// =============================================================================

export interface QueryStats {
  total_queries: number;
  my_queries: number;
  shared_queries: number;
  total_executions: number;
}

export interface ExportStats {
  total_exports: number;
  pending: number;
  processing: number;
  completed: number;
  failed: number;
}

// =============================================================================
// Filter Option Types
// =============================================================================

export interface FilterOption {
  value: string;
  label: string;
}

export const SEVERITY_OPTIONS: FilterOption[] = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
];

export const STATUS_OPTIONS: FilterOption[] = [
  { value: 'pass', label: 'Pass' },
  { value: 'fail', label: 'Fail' },
  { value: 'error', label: 'Error' },
  { value: 'skip', label: 'Skip' },
];

export const VISIBILITY_OPTIONS: FilterOption[] = [
  { value: 'private', label: 'Private' },
  { value: 'shared', label: 'Shared' },
];

export const EXPORT_FORMAT_OPTIONS: FilterOption[] = [
  { value: 'csv', label: 'CSV (Spreadsheet)' },
  { value: 'json', label: 'JSON (Data)' },
  { value: 'pdf', label: 'PDF (Report)' },
];
