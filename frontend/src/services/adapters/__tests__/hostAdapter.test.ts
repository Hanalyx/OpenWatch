import { describe, it, expect } from 'vitest';
import {
  adaptHost,
  adaptHosts,
  adaptConnectionTest,
  adaptCredential,
  adaptKeyValidation,
  toCreateHostRequest,
  toUpdateHostRequest,
} from '../hostAdapter';
import type {
  ApiHostResponse,
  ApiConnectionTestResponse,
  ApiCredentialResponse,
  ApiKeyValidationResponse,
} from '../hostAdapter';

describe('adaptHost', () => {
  const minimalApiHost: ApiHostResponse = {
    id: '550e8400-e29b-41d4-a716-446655440000',
    hostname: 'web-01',
    ip_address: '10.0.0.1',
    operating_system: 'RHEL 9',
  };

  it('maps required fields', () => {
    const host = adaptHost(minimalApiHost);
    expect(host.id).toBe('550e8400-e29b-41d4-a716-446655440000');
    expect(host.hostname).toBe('web-01');
    expect(host.ipAddress).toBe('10.0.0.1');
    expect(host.operatingSystem).toBe('RHEL 9');
  });

  it('falls back to hostname when display_name is absent', () => {
    const host = adaptHost(minimalApiHost);
    expect(host.displayName).toBe('web-01');
  });

  it('uses display_name when provided', () => {
    const host = adaptHost({ ...minimalApiHost, display_name: 'Web Server 1' });
    expect(host.displayName).toBe('Web Server 1');
  });

  it('maps scan_status=running to scanning', () => {
    const host = adaptHost({ ...minimalApiHost, scan_status: 'running' });
    expect(host.status).toBe('scanning');
  });

  it('maps scan_status=pending to scanning', () => {
    const host = adaptHost({ ...minimalApiHost, scan_status: 'pending' });
    expect(host.status).toBe('scanning');
  });

  it('falls back to status field when scan_status is not running/pending', () => {
    const host = adaptHost({ ...minimalApiHost, status: 'online', scan_status: 'completed' });
    expect(host.status).toBe('online');
  });

  it('defaults to offline when no status fields present', () => {
    const host = adaptHost(minimalApiHost);
    expect(host.status).toBe('offline');
  });

  it('defaults numeric issue counts to 0', () => {
    const host = adaptHost(minimalApiHost);
    expect(host.criticalIssues).toBe(0);
    expect(host.highIssues).toBe(0);
    expect(host.mediumIssues).toBe(0);
    expect(host.lowIssues).toBe(0);
  });

  it('maps group fields', () => {
    const host = adaptHost({
      ...minimalApiHost,
      group_id: 5,
      group_name: 'Production',
      group_description: 'Production servers',
      group_color: '#ff0000',
    });
    expect(host.group).toBe('Production');
    expect(host.group_id).toBe(5);
    expect(host.group_name).toBe('Production');
    expect(host.group_description).toBe('Production servers');
    expect(host.group_color).toBe('#ff0000');
  });

  it('defaults group to Ungrouped', () => {
    const host = adaptHost(minimalApiHost);
    expect(host.group).toBe('Ungrouped');
  });

  it('defaults port to 22 and authMethod to ssh_key', () => {
    const host = adaptHost(minimalApiHost);
    expect(host.port).toBe(22);
    expect(host.authMethod).toBe('ssh_key');
  });

  it('maps all optional fields when present', () => {
    const full: ApiHostResponse = {
      ...minimalApiHost,
      compliance_score: 95,
      tags: ['web', 'prod'],
      owner: 'admin',
      cpu_usage: 45.2,
      memory_usage: 72.1,
      disk_usage: 60,
      uptime: '45d 12h',
      port: 2222,
      username: 'deploy',
      auth_method: 'password',
      ssh_key_fingerprint: 'SHA256:abc',
      ssh_key_type: 'ed25519',
      ssh_key_bits: 256,
      latest_scan_id: 'scan-1',
      latest_scan_name: 'Weekly',
      scan_progress: 50,
      failed_rules: 3,
      passed_rules: 97,
      total_rules: 100,
    };
    const host = adaptHost(full);
    expect(host.complianceScore).toBe(95);
    expect(host.tags).toEqual(['web', 'prod']);
    expect(host.owner).toBe('admin');
    expect(host.cpuUsage).toBe(45.2);
    expect(host.memoryUsage).toBe(72.1);
    expect(host.diskUsage).toBe(60);
    expect(host.uptime).toBe('45d 12h');
    expect(host.port).toBe(2222);
    expect(host.username).toBe('deploy');
    expect(host.authMethod).toBe('password');
    expect(host.ssh_key_fingerprint).toBe('SHA256:abc');
    expect(host.ssh_key_type).toBe('ed25519');
    expect(host.ssh_key_bits).toBe(256);
    expect(host.latestScanId).toBe('scan-1');
    expect(host.latestScanName).toBe('Weekly');
    expect(host.scanProgress).toBe(50);
    expect(host.failedRules).toBe(3);
    expect(host.passedRules).toBe(97);
    expect(host.totalRules).toBe(100);
  });
});

describe('adaptHosts', () => {
  it('maps an array of host responses', () => {
    const hosts = adaptHosts([
      { id: '1', hostname: 'a', ip_address: '1.1.1.1', operating_system: 'RHEL' },
      { id: '2', hostname: 'b', ip_address: '2.2.2.2', operating_system: 'Ubuntu' },
    ]);
    expect(hosts).toHaveLength(2);
    expect(hosts[0].hostname).toBe('a');
    expect(hosts[1].hostname).toBe('b');
  });
});

describe('adaptConnectionTest', () => {
  it('transforms a successful test response', () => {
    const api: ApiConnectionTestResponse = {
      network_reachable: true,
      auth_successful: true,
      detected_os: 'RHEL',
      os_version: '9.2',
      response_time_ms: 45,
      ssh_version: 'OpenSSH_8.7',
    };
    const result = adaptConnectionTest(api);
    expect(result.success).toBe(true);
    expect(result.networkConnectivity).toBe(true);
    expect(result.authentication).toBe(true);
    expect(result.detectedOS).toBe('RHEL');
    expect(result.detectedVersion).toBe('9.2');
    expect(result.responseTime).toBe(45);
    expect(result.sshVersion).toBe('OpenSSH_8.7');
  });

  it('applies defaults for missing fields', () => {
    const result = adaptConnectionTest({});
    expect(result.networkConnectivity).toBe(true);
    expect(result.authentication).toBe(true);
    expect(result.detectedOS).toBe('Unknown');
    expect(result.detectedVersion).toBe('');
    expect(result.responseTime).toBe(0);
  });
});

describe('adaptCredential', () => {
  it('transforms a credential response', () => {
    const api: ApiCredentialResponse = {
      id: '1',
      name: 'deploy-key',
      username: 'deploy',
      is_default: true,
      auth_method: 'ssh_key',
      ssh_key_type: 'ed25519',
      ssh_key_bits: 256,
      ssh_key_comment: 'deploy@host',
      ssh_key_fingerprint: 'SHA256:xyz',
    };
    const cred = adaptCredential(api);
    expect(cred.name).toBe('deploy-key');
    expect(cred.username).toBe('deploy');
    expect(cred.authMethod).toBe('ssh_key');
    expect(cred.sshKeyType).toBe('ed25519');
    expect(cred.sshKeyBits).toBe(256);
    expect(cred.sshKeyComment).toBe('deploy@host');
  });

  it('defaults empty strings for missing fields', () => {
    const cred = adaptCredential({ is_default: false });
    expect(cred.name).toBe('');
    expect(cred.username).toBe('');
    expect(cred.authMethod).toBe('password');
  });
});

describe('adaptKeyValidation', () => {
  it('transforms a validation response', () => {
    const api: ApiKeyValidationResponse = {
      is_valid: true,
      message: 'Key is valid',
      key_type: 'ed25519',
      key_bits: 256,
      security_level: 'secure',
    };
    const result = adaptKeyValidation(api);
    expect(result.isValid).toBe(true);
    expect(result.message).toBe('Key is valid');
    expect(result.keyType).toBe('ed25519');
    expect(result.keyBits).toBe(256);
    expect(result.securityLevel).toBe('secure');
  });
});

describe('toCreateHostRequest', () => {
  it('builds a create request from form data', () => {
    const req = toCreateHostRequest({
      hostname: 'web-01',
      ipAddress: '10.0.0.1',
      displayName: 'Web Server 1',
      operatingSystem: 'RHEL 9',
      authMethod: 'ssh_key',
      sshKey: 'key-content',
      port: 22,
      username: 'admin',
    });
    expect(req.hostname).toBe('web-01');
    expect(req.ip_address).toBe('10.0.0.1');
    expect(req.display_name).toBe('Web Server 1');
    expect(req.operating_system).toBe('RHEL 9');
    expect(req.auth_method).toBe('ssh_key');
    expect(req.ssh_key).toBe('key-content');
    expect(req.password).toBeUndefined();
  });

  it('maps auto-detect OS to Unknown', () => {
    const req = toCreateHostRequest({
      hostname: 'h',
      ipAddress: '1.1.1.1',
      operatingSystem: 'auto-detect',
    });
    expect(req.operating_system).toBe('Unknown');
  });

  it('includes password when authMethod is password', () => {
    const req = toCreateHostRequest({
      hostname: 'h',
      ipAddress: '1.1.1.1',
      operatingSystem: 'RHEL',
      authMethod: 'password',
      password: 'secret', // pragma: allowlist secret
      sshKey: 'should-be-excluded',
    });
    expect(req.password).toBe('secret'); // pragma: allowlist secret
    expect(req.ssh_key).toBeUndefined();
  });

  it('falls back hostname to ipAddress and vice versa', () => {
    const req = toCreateHostRequest({
      hostname: '',
      ipAddress: '10.0.0.1',
      operatingSystem: 'RHEL',
    });
    expect(req.hostname).toBe('10.0.0.1');
  });
});

describe('toUpdateHostRequest', () => {
  it('builds an update request from form data', () => {
    const req = toUpdateHostRequest({
      hostname: 'web-01',
      displayName: 'Web 1',
      ipAddress: '10.0.0.1',
      operatingSystem: 'RHEL 9',
      port: 2222,
      username: 'deploy',
      authMethod: 'password',
      sshKey: '',
      password: 'pass', // pragma: allowlist secret
    });
    expect(req.hostname).toBe('web-01');
    expect(req.display_name).toBe('Web 1');
    expect(req.ip_address).toBe('10.0.0.1');
    expect(req.operating_system).toBe('RHEL 9');
    expect(req.port).toBe(2222);
    expect(req.username).toBe('deploy');
    expect(req.auth_method).toBe('password');
    expect(req.ssh_key).toBe('');
    expect(req.password).toBe('pass');
  });
});
