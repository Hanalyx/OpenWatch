/**
 * Compliance Threshold Constants
 *
 * Centralized compliance scoring thresholds per CLAUDE.md standards.
 * These values are used throughout OpenWatch for consistent compliance
 * status determination and color-coding.
 *
 * Standards Alignment:
 * - NIST SP 800-53: Continuous monitoring thresholds
 * - DISA STIG: Assessment benchmarks
 * - FedRAMP: Compliance scoring requirements
 * - ISO 27001: Audit compliance levels
 *
 * Used by:
 * - ComplianceRing component (visual indicators)
 * - Hosts page (compliance status display)
 * - Dashboard (compliance summary cards)
 * - Reports (compliance score calculation)
 *
 * DO NOT modify these values without reviewing CLAUDE.md compliance standards.
 *
 * @module constants/compliance
 */

/**
 * Compliance score thresholds per CLAUDE.md.
 *
 * These thresholds determine compliance status categories:
 * - COMPLIANT (95%+): Green - System meets all critical requirements
 * - NEAR_COMPLIANT (75-94%): Yellow - System requires minor remediation
 * - NON_COMPLIANT (<75%): Red - System requires significant remediation
 *
 * Why these specific values:
 * - 95% COMPLIANT: FedRAMP and NIST recommend 95%+ for production systems
 * - 75% NEAR_COMPLIANT: Industry standard threshold for "acceptable with remediation"
 * - <75% NON_COMPLIANT: Indicates systemic compliance issues requiring immediate action
 *
 * @constant
 * @readonly
 *
 * @example
 * import { COMPLIANCE_THRESHOLDS } from '@/constants/compliance';
 *
 * function getComplianceStatus(score: number): string {
 *   if (score >= COMPLIANCE_THRESHOLDS.COMPLIANT) return 'Compliant';
 *   if (score >= COMPLIANCE_THRESHOLDS.NEAR_COMPLIANT) return 'Near Compliant';
 *   return 'Non-Compliant';
 * }
 */
export const COMPLIANCE_THRESHOLDS = {
  /** Compliant: 95% or higher (green) */
  COMPLIANT: 95,

  /** Near Compliant: 75-94% (yellow/warning) */
  NEAR_COMPLIANT: 75,

  /** Non-Compliant: Below 75% (red/error) */
  NON_COMPLIANT: 0,
} as const;

/**
 * Compliance status labels.
 *
 * Human-readable labels corresponding to compliance threshold levels.
 * Use these for consistent messaging across the application.
 *
 * @constant
 * @readonly
 *
 * @example
 * import { COMPLIANCE_LABELS } from '@/constants/compliance';
 *
 * console.log(COMPLIANCE_LABELS.COMPLIANT); // "Compliant"
 */
export const COMPLIANCE_LABELS = {
  /** Label for systems at 95%+ compliance */
  COMPLIANT: 'Compliant',

  /** Label for systems at 75-94% compliance */
  NEAR_COMPLIANT: 'Near Compliant',

  /** Label for systems below 75% compliance */
  NON_COMPLIANT: 'Non-Compliant',

  /** Label for systems that have never been scanned */
  UNSCANNED: 'Not Scanned',
} as const;

/**
 * Severity level weights for risk scoring.
 *
 * These weights are used to calculate composite risk scores based on
 * finding severity distribution. Higher severity findings have greater
 * impact on overall risk score.
 *
 * Weights based on CVSS severity scoring:
 * - Critical: CVSS 9.0-10.0 (10x weight)
 * - High: CVSS 7.0-8.9 (5x weight)
 * - Medium: CVSS 4.0-6.9 (2x weight)
 * - Low: CVSS 0.1-3.9 (0.5x weight)
 *
 * @constant
 * @readonly
 *
 * @example
 * import { SEVERITY_WEIGHTS } from '@/constants/compliance';
 *
 * const riskScore = (
 *   criticalCount * SEVERITY_WEIGHTS.CRITICAL +
 *   highCount * SEVERITY_WEIGHTS.HIGH +
 *   mediumCount * SEVERITY_WEIGHTS.MEDIUM +
 *   lowCount * SEVERITY_WEIGHTS.LOW
 * );
 */
export const SEVERITY_WEIGHTS = {
  /** Critical severity weight: 10 points per finding */
  CRITICAL: 10,

  /** High severity weight: 5 points per finding */
  HIGH: 5,

  /** Medium severity weight: 2 points per finding */
  MEDIUM: 2,

  /** Low severity weight: 0.5 points per finding */
  LOW: 0.5,
} as const;

/**
 * Severity color palette for UI consistency.
 *
 * RGB color values for severity indicators used across OpenWatch.
 * These colors match the concentric ring visualization in ComplianceRing component.
 *
 * @constant
 * @readonly
 *
 * @example
 * import { SEVERITY_COLORS } from '@/constants/compliance';
 *
 * <Box sx={{ backgroundColor: SEVERITY_COLORS.CRITICAL }}>
 *   {criticalCount} Critical Issues
 * </Box>
 */
export const SEVERITY_COLORS = {
  /** Critical severity: Red - rgb(244, 67, 54) */
  CRITICAL: 'rgb(244, 67, 54)',

  /** High severity: Dark Orange - rgb(255, 152, 0) */
  HIGH: 'rgb(255, 152, 0)',

  /** Medium severity: Light Orange - rgb(255, 183, 77) */
  MEDIUM: 'rgb(255, 183, 77)',

  /** Low severity: Light Blue - rgb(144, 202, 249) */
  LOW: 'rgb(144, 202, 249)',
} as const;

/**
 * Helper function to get compliance status based on score.
 *
 * @param score - Compliance score (0-100) or null
 * @returns Compliance status label
 *
 * @example
 * const status = getComplianceStatus(87.5);
 * console.log(status); // "Near Compliant"
 */
export function getComplianceStatus(score: number | null): string {
  if (score === null) return COMPLIANCE_LABELS.UNSCANNED;
  if (score >= COMPLIANCE_THRESHOLDS.COMPLIANT) return COMPLIANCE_LABELS.COMPLIANT;
  if (score >= COMPLIANCE_THRESHOLDS.NEAR_COMPLIANT) return COMPLIANCE_LABELS.NEAR_COMPLIANT;
  return COMPLIANCE_LABELS.NON_COMPLIANT;
}

/**
 * Helper function to calculate risk score from severity counts.
 *
 * Uses CVSS-based severity weights to calculate composite risk score.
 *
 * @param criticalCount - Number of critical severity findings
 * @param highCount - Number of high severity findings
 * @param mediumCount - Number of medium severity findings
 * @param lowCount - Number of low severity findings
 * @returns Composite risk score (unbounded, typically 0-200)
 *
 * @example
 * const risk = calculateRiskScore(2, 5, 12, 8);
 * console.log(risk); // 59.0 (2*10 + 5*5 + 12*2 + 8*0.5)
 */
export function calculateRiskScore(
  criticalCount: number,
  highCount: number,
  mediumCount: number,
  lowCount: number
): number {
  return (
    criticalCount * SEVERITY_WEIGHTS.CRITICAL +
    highCount * SEVERITY_WEIGHTS.HIGH +
    mediumCount * SEVERITY_WEIGHTS.MEDIUM +
    lowCount * SEVERITY_WEIGHTS.LOW
  );
}
