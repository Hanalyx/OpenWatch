import { api } from './api';
import { type ClassifiedError } from '../components/errors/ErrorClassificationDisplay';

export interface ValidationRequest {
  host_id: string;
  // Legacy SCAP content scanning fields
  content_id?: number;
  profile_id?: string;
  // MongoDB scanning fields
  platform?: string;
  platform_version?: string;
  framework?: string;
}

/**
 * System information collected during validation
 * Contains common fields with extensibility for additional backend data
 */
export interface SystemInfo {
  // Common validation fields
  collection_timestamp?: string;
  openscap_available?: boolean;
  ssh_available?: boolean;
  // Resource information
  memory?: number | string;
  disk_space?: number | string;
  // Additional system details (extensible for backend additions)
  system_details?: Record<string, string | number | boolean>;
  // Allow any additional fields the backend may return
  [key: string]: string | number | boolean | Record<string, string | number | boolean> | undefined;
}

export interface ValidationResult {
  can_proceed: boolean;
  errors: ClassifiedError[];
  warnings: ClassifiedError[];
  pre_flight_duration: number;
  system_info: SystemInfo;
  validation_checks: Record<string, boolean>;
}

export interface RecoveryResponse {
  can_recover: boolean;
  recovery_scan_id?: string;
  message: string;
  error_classification: ClassifiedError;
  recommended_actions?: string;
  estimated_retry_time?: number;
}

export interface AutomatedFixResponse {
  job_id: string;
  fix_id: string;
  host_id: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  estimated_completion: number;
  message: string;
  validate_after: boolean;
}

/**
 * Type guard for axios-like error objects
 * Checks if error has response property with data and status
 */
interface AxiosLikeError {
  response?: {
    data?: {
      detail?: string;
      error_code?: string;
      category?: string;
      message?: string;
    };
    status?: number;
  };
  message?: string;
  code?: string;
}

/**
 * Type guard to check if error is AxiosLikeError
 */
function isAxiosLikeError(error: unknown): error is AxiosLikeError {
  return (
    typeof error === 'object' &&
    error !== null &&
    ('response' in error || 'message' in error || 'code' in error)
  );
}

/**
 * Enhanced error object with classification data
 * Extended Error type that includes classification metadata
 */
interface EnhancedError extends Error {
  classification: ClassifiedError;
  isClassified: true;
}

/**
 * Enhanced error service for structured error handling and recovery
 */
class ErrorService {
  /**
   * Perform pre-flight validation before starting a scan
   */
  async validateScanPrerequisites(request: ValidationRequest): Promise<ValidationResult> {
    try {
      const result = await api.post<ValidationResult>('/api/scans/validate', request);
      return result;
    } catch (error: unknown) {
      // Type-safe error handling: check if error has expected properties
      console.error('Validation request failed:', error);

      // Transform generic errors into structured format
      const classifiedError: ClassifiedError = this.classifyGenericError(error);

      return {
        can_proceed: false,
        errors: [classifiedError],
        warnings: [],
        pre_flight_duration: 0,
        system_info: {},
        validation_checks: {
          network_connectivity: false,
          authentication: false,
          privileges: false,
          resources: false,
          dependencies: false,
        },
      };
    }
  }

  /**
   * Attempt to recover a failed scan
   */
  async recoverFailedScan(scanId: string): Promise<RecoveryResponse> {
    try {
      return await api.post<RecoveryResponse>(`/api/scans/${scanId}/recover`);
    } catch (error: unknown) {
      // Type-safe error handling: unknown type requires runtime checks
      console.error('Recovery request failed:', error);
      throw this.enhanceError(error);
    }
  }

  /**
   * Apply an automated fix to a host
   */
  async applyAutomatedFix(
    hostId: string,
    fixId: string,
    validateAfter: boolean = true
  ): Promise<AutomatedFixResponse> {
    try {
      return await api.post<AutomatedFixResponse>(`/api/scans/hosts/${hostId}/apply-fix`, {
        fix_id: fixId,
        host_id: hostId,
        validate_after: validateAfter,
      });
    } catch (error: unknown) {
      // Type-safe error handling: unknown type requires runtime checks
      console.error('Automated fix request failed:', error);
      throw this.enhanceError(error);
    }
  }

  /**
   * Classify a generic error into structured format
   * Accepts unknown error type and performs runtime type checking
   */
  classifyGenericError(error: unknown): ClassifiedError {
    // Type-safe access using type guard
    const axiosError = isAxiosLikeError(error) ? error : null;
    const errorMessage =
      axiosError?.response?.data?.detail || axiosError?.message || 'An unexpected error occurred';
    const statusCode = axiosError?.response?.status;

    // Network errors
    if (!axiosError?.response || axiosError.code === 'NETWORK_ERROR') {
      return {
        error_code: 'NET_006',
        category: 'network',
        severity: 'error',
        message: 'Unable to connect to OpenWatch server',
        user_guidance: 'Check your network connection and ensure the OpenWatch server is running',
        technical_details: {
          original_error: errorMessage,
          status_code: statusCode,
        },
        automated_fixes: [
          {
            fix_id: 'retry_connection',
            description: 'Retry connection',
            requires_sudo: false,
            estimated_time: 5,
            is_safe: true,
          },
        ],
        can_retry: true,
        retry_after: 30,
        timestamp: new Date().toISOString(),
      };
    }

    // Authentication errors
    if (statusCode === 401) {
      return {
        error_code: 'AUTH_006',
        category: 'authentication',
        severity: 'error',
        message: 'Authentication failed',
        user_guidance: 'Your session may have expired. Please log in again',
        technical_details: {
          status_code: statusCode,
          original_error: errorMessage,
        },
        automated_fixes: [
          {
            fix_id: 'refresh_login',
            description: 'Refresh login',
            requires_sudo: false,
            estimated_time: 10,
            is_safe: true,
          },
        ],
        can_retry: true,
        timestamp: new Date().toISOString(),
      };
    }

    // Authorization errors
    if (statusCode === 403) {
      return {
        error_code: 'AUTH_007',
        category: 'authentication',
        severity: 'error',
        message: 'Access denied',
        user_guidance: 'You do not have permission to perform this action',
        technical_details: {
          status_code: statusCode,
          original_error: errorMessage,
        },
        automated_fixes: [],
        can_retry: false,
        timestamp: new Date().toISOString(),
      };
    }

    // Server errors
    if (statusCode >= 500) {
      return {
        error_code: 'EXEC_002',
        category: 'execution',
        severity: 'error',
        message: 'Server error occurred',
        user_guidance:
          'A server error occurred. Please try again or contact support if the problem persists',
        technical_details: {
          status_code: statusCode,
          original_error: errorMessage,
        },
        automated_fixes: [
          {
            fix_id: 'retry_request',
            description: 'Retry request',
            requires_sudo: false,
            estimated_time: 5,
            is_safe: true,
          },
        ],
        can_retry: true,
        retry_after: 60,
        timestamp: new Date().toISOString(),
      };
    }

    // Client errors
    if (statusCode >= 400 && statusCode < 500) {
      return {
        error_code: 'EXEC_003',
        category: 'configuration',
        severity: 'error',
        message: 'Invalid request',
        user_guidance: errorMessage,
        technical_details: {
          status_code: statusCode,
          original_error: errorMessage,
        },
        automated_fixes: [],
        can_retry: false,
        timestamp: new Date().toISOString(),
      };
    }

    // Default classification
    return {
      error_code: 'EXEC_999',
      category: 'execution',
      severity: 'error',
      message: 'Unexpected error occurred',
      user_guidance: errorMessage,
      technical_details: {
        original_error: errorMessage,
        status_code: statusCode,
      },
      automated_fixes: [
        {
          fix_id: 'retry_operation',
          description: 'Retry operation',
          requires_sudo: false,
          estimated_time: 5,
          is_safe: true,
        },
      ],
      can_retry: true,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Enhance an error with additional context and guidance
   * Returns an error object with attached classification data
   */
  enhanceError(error: unknown): Error {
    const classifiedError = this.classifyGenericError(error);
    const enhancedError = new Error(classifiedError.message) as EnhancedError;

    // Attach classification data to error
    enhancedError.classification = classifiedError;
    enhancedError.isClassified = true;

    return enhancedError;
  }

  /**
   * Type guard for enhanced error objects
   * Checks if error has isClassified flag and classification data
   */
  isClassifiedError(error: unknown): error is EnhancedError {
    return (
      typeof error === 'object' &&
      error !== null &&
      'isClassified' in error &&
      error.isClassified === true &&
      'classification' in error
    );
  }

  /**
   * Extract classification data from an enhanced error
   * Performs type-safe checks on unknown error objects
   */
  getErrorClassification(error: unknown): ClassifiedError | null {
    if (this.isClassifiedError(error)) {
      return error.classification;
    }

    // If it's a backend error response with structured data
    if (isAxiosLikeError(error) && error.response?.data) {
      const data = error.response.data;
      if (data.error_code && data.category && data.message) {
        return data as ClassifiedError;
      }
    }

    return null;
  }

  /**
   * Transform error for user display
   * Accepts unknown error and extracts user-friendly message
   */
  getUserFriendlyError(error: unknown): string {
    const classification = this.getErrorClassification(error);
    if (classification) {
      return classification.user_guidance || classification.message;
    }

    // Fallback to generic handling using type guard
    const axiosError = isAxiosLikeError(error) ? error : null;
    if (axiosError?.response?.data?.detail) {
      return axiosError.response.data.detail;
    }

    if (axiosError?.message) {
      return axiosError.message;
    }

    return 'An unexpected error occurred. Please try again.';
  }

  /**
   * Check if an error can be retried
   * Accepts unknown error type for flexible error handling
   */
  canRetryError(error: unknown): boolean {
    const classification = this.getErrorClassification(error);
    return classification?.can_retry || false;
  }

  /**
   * Get retry delay for an error (in seconds)
   * Accepts unknown error type for flexible error handling
   */
  getRetryDelay(error: unknown): number {
    const classification = this.getErrorClassification(error);
    return classification?.retry_after || 0;
  }

  /**
   * Get available automated fixes for an error
   * Accepts unknown error type for flexible error handling
   */
  getAutomatedFixes(error: unknown) {
    const classification = this.getErrorClassification(error);
    return classification?.automated_fixes || [];
  }
}

export const errorService = new ErrorService();
export default errorService;
