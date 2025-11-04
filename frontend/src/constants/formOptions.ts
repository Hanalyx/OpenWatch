// Form dropdown options for Smart Group Creation Wizard

export interface Option {
  value: string;
  label: string;
  description?: string;
}

// Operating System Family options
export const OS_FAMILY_OPTIONS: Option[] = [
  { value: 'rhel', label: 'Red Hat Enterprise Linux', description: 'RHEL and derivatives' },
  { value: 'ubuntu', label: 'Ubuntu', description: 'Ubuntu and derivatives' },
  { value: 'debian', label: 'Debian', description: 'Debian GNU/Linux' },
  { value: 'centos', label: 'CentOS', description: 'CentOS Linux' },
  { value: 'fedora', label: 'Fedora', description: 'Fedora Linux' },
  { value: 'suse', label: 'SUSE Linux', description: 'SUSE Linux Enterprise' },
  { value: 'opensuse', label: 'openSUSE', description: 'openSUSE distribution' },
  { value: 'windows', label: 'Windows', description: 'Microsoft Windows' },
  { value: 'macos', label: 'macOS', description: 'Apple macOS' },
  { value: 'freebsd', label: 'FreeBSD', description: 'FreeBSD Unix' },
  { value: 'other', label: 'Other', description: 'Other operating systems' },
];

// Architecture options
export const ARCHITECTURE_OPTIONS: Option[] = [
  { value: 'x86_64', label: 'x86_64', description: '64-bit x86 (Intel/AMD)' },
  { value: 'amd64', label: 'amd64', description: '64-bit x86 (AMD64)' },
  { value: 'arm64', label: 'arm64', description: '64-bit ARM (AArch64)' },
  { value: 'aarch64', label: 'aarch64', description: '64-bit ARM (AArch64)' },
  { value: 'i386', label: 'i386', description: '32-bit x86 (Intel)' },
  { value: 'i686', label: 'i686', description: '32-bit x86 (i686)' },
  { value: 'armhf', label: 'armhf', description: '32-bit ARM (hard-float)' },
  { value: 'armv7l', label: 'armv7l', description: '32-bit ARM (ARMv7)' },
  { value: 's390x', label: 's390x', description: '64-bit IBM System z' },
  { value: 'ppc64le', label: 'ppc64le', description: '64-bit PowerPC (little-endian)' },
  { value: 'other', label: 'Other', description: 'Other architectures' },
];

// Compliance Framework options
export const COMPLIANCE_FRAMEWORK_OPTIONS: Option[] = [
  {
    value: 'DISA-STIG',
    label: 'DISA STIG',
    description: 'Defense Information Systems Agency Security Technical Implementation Guide',
  },
  {
    value: 'NIST-800-53',
    label: 'NIST 800-53',
    description: 'NIST Security and Privacy Controls for Federal Information Systems',
  },
  { value: 'NIST-CSF', label: 'NIST CSF', description: 'NIST Cybersecurity Framework' },
  { value: 'CIS', label: 'CIS Benchmarks', description: 'Center for Internet Security Benchmarks' },
  {
    value: 'PCI-DSS',
    label: 'PCI DSS',
    description: 'Payment Card Industry Data Security Standard',
  },
  {
    value: 'HIPAA',
    label: 'HIPAA',
    description: 'Health Insurance Portability and Accountability Act',
  },
  { value: 'SOX', label: 'SOX', description: 'Sarbanes-Oxley Act' },
  {
    value: 'FedRAMP',
    label: 'FedRAMP',
    description: 'Federal Risk and Authorization Management Program',
  },
  {
    value: 'ISO-27001',
    label: 'ISO 27001',
    description: 'ISO/IEC 27001 Information Security Management',
  },
  { value: 'SOC-2', label: 'SOC 2', description: 'Service Organization Control 2' },
  { value: 'GDPR', label: 'GDPR', description: 'General Data Protection Regulation' },
  { value: 'CCPA', label: 'CCPA', description: 'California Consumer Privacy Act' },
  { value: 'Custom', label: 'Custom', description: 'Custom compliance requirements' },
  { value: 'Other', label: 'Other', description: 'Other compliance frameworks' },
];

// Common scan schedules for auto-scanning
export const SCAN_SCHEDULE_OPTIONS: Option[] = [
  { value: 'daily', label: 'Daily', description: 'Run scan once per day' },
  { value: 'weekly', label: 'Weekly', description: 'Run scan once per week' },
  { value: 'monthly', label: 'Monthly', description: 'Run scan once per month' },
  {
    value: '0 2 * * *',
    label: 'Daily at 2:00 AM',
    description: 'Cron expression for daily at 2 AM',
  },
  {
    value: '0 2 * * 0',
    label: 'Weekly on Sunday at 2:00 AM',
    description: 'Cron expression for weekly on Sunday',
  },
  {
    value: '0 2 1 * *',
    label: 'Monthly on 1st at 2:00 AM',
    description: 'Cron expression for monthly on first day',
  },
  { value: 'custom', label: 'Custom', description: 'Enter custom cron expression' },
];

// Helper functions to get labels and options
export const getOSFamilyLabel = (value: string): string => {
  return OS_FAMILY_OPTIONS.find((option) => option.value === value)?.label || value;
};

export const getArchitectureLabel = (value: string): string => {
  return ARCHITECTURE_OPTIONS.find((option) => option.value === value)?.label || value;
};

export const getComplianceFrameworkLabel = (value: string): string => {
  return COMPLIANCE_FRAMEWORK_OPTIONS.find((option) => option.value === value)?.label || value;
};
