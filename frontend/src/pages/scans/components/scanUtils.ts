/**
 * Scan utility functions extracted from ScanDetail.
 * Pure functions with no React/state dependencies.
 */

import type {
  RuleResult,
  RemediationStep,
  ScapRemediationData,
  ScapCommand,
  ScapConfiguration,
  ScanResults,
} from './scanTypes';

/** Map backend severity strings to normalized values. */
export function mapSeverity(severity: string): 'high' | 'medium' | 'low' | 'unknown' {
  const s = severity.toLowerCase();
  if (['high', 'critical'].includes(s)) return 'high';
  if (['medium', 'moderate'].includes(s)) return 'medium';
  if (['low', 'info', 'informational'].includes(s)) return 'low';
  return 'unknown';
}

/** Map backend result strings to normalized values. */
export function mapResult(result: string): 'pass' | 'fail' | 'error' | 'unknown' | 'notapplicable' {
  const r = result.toLowerCase();
  if (r === 'pass') return 'pass';
  if (r === 'fail') return 'fail';
  if (r === 'error') return 'error';
  if (['notapplicable', 'na', 'n/a', 'not applicable'].includes(r)) return 'notapplicable';
  return 'unknown';
}

/** Extract a human-readable title from a SCAP rule ID. */
export function extractRuleTitle(ruleId: string): string {
  if (!ruleId) return 'Unknown Rule';

  const cleanId = ruleId
    .replace('xccdf_org.ssgproject.content_rule_', '')
    .replace('xccdf_', '')
    .replace(/_/g, ' ');

  const ruleMappings: Record<string, string> = {
    package_aide_installed: 'Install AIDE',
    service_auditd_enabled: 'Enable Audit Daemon',
    accounts_password_minlen_login_defs: 'Set Minimum Password Length', // pragma: allowlist secret
    sshd_disable_root_login: 'Disable SSH Root Login',
    kernel_module_usb_storage_disabled: 'Disable USB Storage',
    service_firewalld_enabled: 'Enable Firewall Service',
    file_permissions_etc_passwd: 'Set Correct Permissions on /etc/passwd', // pragma: allowlist secret
    accounts_max_concurrent_login_sessions: 'Limit Concurrent Login Sessions',
    sysctl_kernel_randomize_va_space: 'Enable Address Space Randomization',
    mount_option_tmp_noexec: 'Mount /tmp with noexec Option',
  };

  const lastPart = ruleId.split('_').slice(-3).join('_');
  if (ruleMappings[lastPart]) {
    return ruleMappings[lastPart];
  }

  return (
    cleanId
      .split(' ')
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ')
      .replace(/\s+/g, ' ')
      .trim() || 'Security Configuration Rule'
  );
}

/** Generate a generic description from a rule ID pattern. */
export function extractRuleDescription(ruleId: string): string {
  if (!ruleId) return 'No description available';
  if (ruleId.includes('package') && ruleId.includes('installed'))
    return 'Ensures that the required security package is installed on the system.';
  if (ruleId.includes('service') && ruleId.includes('enabled'))
    return 'Ensures that the required security service is enabled and running.';
  if (ruleId.includes('sshd'))
    return 'Configures SSH daemon settings according to security best practices.';
  if (ruleId.includes('password'))
    return 'Implements password policy requirements for system security.';
  if (ruleId.includes('file_permissions'))
    return 'Sets appropriate file permissions on system configuration files.';
  if (ruleId.includes('kernel') || ruleId.includes('sysctl'))
    return 'Configures kernel parameters for enhanced system security.';
  if (ruleId.includes('mount'))
    return 'Applies security-focused mount options to filesystem mountpoints.';
  if (ruleId.includes('firewall'))
    return 'Configures firewall settings to protect network services.';
  return 'Implements security configuration requirements as defined by the compliance profile.';
}

export function extractPackageName(ruleId: string): string {
  const match = ruleId.match(/package_(\w+)_installed/);
  return match ? match[1].replace(/_/g, '-') : 'package';
}

export function extractServiceName(ruleId: string): string {
  const match = ruleId.match(/service_(\w+)_enabled/);
  return match ? match[1] : 'service';
}

export function extractFilePath(ruleId: string): string {
  const paths: Record<string, string> = {
    etc_passwd: '/etc/passwd',
    etc_shadow: '/etc/shadow',
    etc_group: '/etc/group',
    etc_gshadow: '/etc/gshadow',
  };
  for (const [key, value] of Object.entries(paths)) {
    if (ruleId.includes(key)) return value;
  }
  return '/etc/config';
}

export function extractKernelParam(ruleId: string): string {
  const params: Record<string, string> = {
    randomize_va_space: 'kernel.randomize_va_space',
    dmesg_restrict: 'kernel.dmesg_restrict',
    kptr_restrict: 'kernel.kptr_restrict',
  };
  for (const [key, value] of Object.entries(params)) {
    if (ruleId.includes(key)) return value;
  }
  return 'kernel.parameter';
}

/** Map scan status to MUI chip color. */
export function getStatusColor(
  status: string
): 'success' | 'primary' | 'error' | 'warning' | 'default' {
  switch (status) {
    case 'completed':
      return 'success';
    case 'running':
      return 'primary';
    case 'failed':
      return 'error';
    case 'pending':
      return 'warning';
    default:
      return 'default';
  }
}

/** Map severity to hex color. */
export function getSeverityColor(severity: string): string {
  switch (severity) {
    case 'high':
      return '#f44336';
    case 'medium':
      return '#ff9800';
    case 'low':
      return '#ffeb3b';
    default:
      return '#9e9e9e';
  }
}

/** Filter rules by search query, severity, and result. */
export function filterRules(
  rules: RuleResult[],
  searchQuery: string,
  severityFilter: string,
  resultFilter: string
): RuleResult[] {
  let filtered = [...rules];

  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(
      (rule) =>
        rule.rule_id.toLowerCase().includes(q) ||
        rule.title.toLowerCase().includes(q) ||
        rule.description.toLowerCase().includes(q)
    );
  }

  if (severityFilter !== 'all') {
    filtered = filtered.filter((rule) => rule.severity === severityFilter);
  }

  if (resultFilter !== 'all') {
    filtered = filtered.filter((rule) => rule.result === resultFilter);
  }

  return filtered;
}

/** Generate placeholder rules when actual report data is unavailable. */
export function generateFallbackRuleResults(results: ScanResults): RuleResult[] {
  const fallbackRules: RuleResult[] = [];
  const totalToGenerate = Math.min(100, results.total_rules || 50);

  for (let i = 0; i < totalToGenerate; i++) {
    const isFailedRule = i < (results.failed_rules || 0);
    const severity: RuleResult['severity'] = isFailedRule
      ? i < (results.severity_high || 0)
        ? 'high'
        : i < (results.severity_high || 0) + (results.severity_medium || 0)
          ? 'medium'
          : 'low'
      : (['high', 'medium', 'low'] as const)[i % 3];

    fallbackRules.push({
      rule_id: `xccdf_org.ssgproject.content_rule_security_check_${i + 1}`,
      title: `Security Configuration Rule ${i + 1}`,
      severity,
      result: isFailedRule ? 'fail' : 'pass',
      description:
        'Security configuration rule - detailed information not available from scan results.',
      rationale: '',
      remediation: '',
    });
  }

  return fallbackRules;
}

/** Generate remediation steps for a rule from SCAP data or pattern-based fallback. */
export function generateRemediationSteps(rule: RuleResult): RemediationStep[] {
  const steps: RemediationStep[] = [];

  // Try real SCAP remediation data first
  if (rule.remediation && typeof rule.remediation === 'object') {
    const scapRemediation = rule.remediation as unknown as ScapRemediationData;

    if (scapRemediation.fix_text) {
      steps.push({
        title: 'SCAP Compliance Fix Text',
        description: scapRemediation.fix_text,
        type: 'manual',
        documentation: 'Official SCAP compliance checker remediation',
      });
    } else if (scapRemediation.description) {
      steps.push({
        title: 'OpenSCAP Evaluation Remediation',
        description: scapRemediation.description,
        type: 'manual',
        documentation: 'OpenSCAP evaluation report guidance',
      });
    }

    if (
      scapRemediation.detailed_description &&
      scapRemediation.detailed_description !== scapRemediation.description &&
      scapRemediation.detailed_description !== scapRemediation.fix_text
    ) {
      steps.push({
        title: 'Detailed Description',
        description: scapRemediation.detailed_description,
        type: 'manual',
      });
    }

    if (scapRemediation.commands && Array.isArray(scapRemediation.commands)) {
      scapRemediation.commands.forEach((cmd: ScapCommand, index: number) => {
        steps.push({
          title: cmd.description || `Command ${index + 1}`,
          description: cmd.description || 'Execute the following command:',
          command: cmd.command,
          type: cmd.type === 'shell' ? 'command' : 'config',
        });
      });
    }

    if (scapRemediation.configuration && Array.isArray(scapRemediation.configuration)) {
      scapRemediation.configuration.forEach((config: ScapConfiguration, index: number) => {
        steps.push({
          title: config.description || `Configuration ${index + 1}`,
          description: config.description || 'Apply the following configuration:',
          command: config.setting,
          type: 'config',
        });
      });
    }

    if (scapRemediation.steps && Array.isArray(scapRemediation.steps)) {
      scapRemediation.steps.forEach((step: string, index: number) => {
        steps.push({
          title: `Remediation Step ${index + 1}`,
          description: step,
          type: 'manual',
        });
      });
    }

    if (scapRemediation.complexity && scapRemediation.complexity !== 'unknown') {
      steps.push({
        title: 'Implementation Complexity',
        description: `This remediation has ${scapRemediation.complexity} complexity${scapRemediation.disruption && scapRemediation.disruption !== 'unknown' ? ` and ${scapRemediation.disruption} disruption` : ''}.`,
        type: 'manual',
      });
    }

    if (steps.length > 0) return steps;
  }

  // Fallback: pattern-based remediation
  const ruleId = rule.rule_id.toLowerCase();

  if (ruleId.includes('package') && ruleId.includes('installed')) {
    const packageName = extractPackageName(rule.rule_id);
    steps.push({
      title: `Install ${packageName}`,
      description: `Install the required package using the system package manager.`,
      command: `sudo dnf install -y ${packageName}`,
      type: 'command',
    });
  } else if (ruleId.includes('service') && ruleId.includes('enabled')) {
    const serviceName = extractServiceName(rule.rule_id);
    steps.push(
      {
        title: `Enable ${serviceName}`,
        description: `Enable and start the required service.`,
        command: `sudo systemctl enable --now ${serviceName}`,
        type: 'command',
      },
      {
        title: 'Verify Service Status',
        description: 'Confirm the service is active and enabled.',
        command: `sudo systemctl status ${serviceName}`,
        type: 'command',
      }
    );
  } else if (ruleId.includes('sshd')) {
    steps.push({
      title: 'Configure SSH Daemon',
      description: 'Apply the required SSH configuration setting.',
      command: `sudo vi /etc/ssh/sshd_config\n# Apply the required setting\nsudo systemctl restart sshd`,
      type: 'config',
    });
  } else if (ruleId.includes('password')) {
    steps.push({
      title: 'Update Password Policy',
      description: 'Modify password policy configuration files.',
      command: `sudo vi /etc/security/pwquality.conf\n# Or: sudo vi /etc/login.defs`,
      type: 'config',
    });
  } else if (ruleId.includes('file_permissions')) {
    const filePath = extractFilePath(rule.rule_id);
    steps.push({
      title: 'Fix File Permissions',
      description: `Set correct permissions on ${filePath}.`,
      command: `sudo chmod 644 ${filePath}\nsudo chown root:root ${filePath}`,
      type: 'command',
    });
  } else if (ruleId.includes('kernel') || ruleId.includes('sysctl')) {
    const paramName = extractKernelParam(rule.rule_id);
    steps.push({
      title: 'Set Kernel Parameter',
      description: `Configure the ${paramName} kernel parameter.`,
      command: `sudo sysctl -w ${paramName}=1\necho "${paramName} = 1" | sudo tee -a /etc/sysctl.d/99-security.conf`,
      type: 'command',
    });
  } else {
    steps.push({
      title: 'Manual Remediation Required',
      description:
        rule.description || 'Review the rule requirements and apply the appropriate fix.',
      type: 'manual',
    });
  }

  return steps;
}
