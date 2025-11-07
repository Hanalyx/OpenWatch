/**
 * Compliance Framework Constants
 *
 * Centralized definitions for supported compliance frameworks and platforms.
 * Following CLAUDE.md best practices - NO hardcoded values in components.
 *
 * Last Updated: 2025-11-07
 */

export interface Platform {
  id: string;
  name: string;
  versions: string[];
}

export interface Framework {
  id: string;
  name: string;
  description: string;
}

/**
 * Supported compliance frameworks
 * These must match backend/app/constants/compliance_frameworks.py
 */
export const SUPPORTED_FRAMEWORKS: Framework[] = [
  {
    id: 'nist_800_53',
    name: 'NIST 800-53',
    description: 'NIST Security and Privacy Controls',
  },
  {
    id: 'cis',
    name: 'CIS Benchmarks',
    description: 'Center for Internet Security Benchmarks',
  },
  {
    id: 'disa_stig',
    name: 'DISA STIG',
    description: 'Defense Information Systems Agency Security Technical Implementation Guide',
  },
  {
    id: 'stig',
    name: 'STIG',
    description: 'Security Technical Implementation Guide',
  },
  {
    id: 'pci_dss',
    name: 'PCI DSS',
    description: 'Payment Card Industry Data Security Standard',
  },
  {
    id: 'hipaa',
    name: 'HIPAA',
    description: 'Health Insurance Portability and Accountability Act Security Rule',
  },
  {
    id: 'iso_27001',
    name: 'ISO/IEC 27001',
    description: 'Information Security Management System Standard',
  },
  {
    id: 'cmmc',
    name: 'CMMC',
    description: 'Cybersecurity Maturity Model Certification',
  },
  {
    id: 'fedramp',
    name: 'FedRAMP',
    description: 'Federal Risk and Authorization Management Program',
  },
];

/**
 * Supported platforms with version information
 * These must match backend/app/constants/compliance_frameworks.py
 */
export const SUPPORTED_PLATFORMS: Platform[] = [
  {
    id: 'rhel',
    name: 'Red Hat Enterprise Linux',
    versions: ['7', '8', '9'],
  },
  {
    id: 'ubuntu',
    name: 'Ubuntu',
    versions: ['18.04', '20.04', '22.04', '24.04'],
  },
  {
    id: 'debian',
    name: 'Debian',
    versions: ['10', '11', '12'],
  },
  {
    id: 'centos',
    name: 'CentOS',
    versions: ['7', '8', '9'],
  },
  {
    id: 'fedora',
    name: 'Fedora',
    versions: ['37', '38', '39'],
  },
  {
    id: 'suse',
    name: 'SUSE Linux Enterprise',
    versions: ['12', '15'],
  },
];

/**
 * Default framework to use when rescan context is missing
 * This should only be used as a last resort fallback
 */
export const DEFAULT_FRAMEWORK = 'disa_stig';

/**
 * Get framework by ID
 */
export function getFrameworkById(id: string): Framework | undefined {
  return SUPPORTED_FRAMEWORKS.find((f) => f.id === id);
}

/**
 * Get platform by ID
 */
export function getPlatformById(id: string): Platform | undefined {
  return SUPPORTED_PLATFORMS.find((p) => p.id === id);
}

/**
 * Check if framework is supported
 */
export function isFrameworkSupported(id: string): boolean {
  return SUPPORTED_FRAMEWORKS.some((f) => f.id === id);
}

/**
 * Check if platform is supported
 */
export function isPlatformSupported(id: string): boolean {
  return SUPPORTED_PLATFORMS.some((p) => p.id === id);
}
