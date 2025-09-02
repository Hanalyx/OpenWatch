# OpenWatch Security Architecture

## Overview

OpenWatch implements a comprehensive FIPS 140-2 compliant security architecture for secure OpenSCAP scanning operations. This document outlines the security controls, cryptographic implementations, and compliance measures.

## FIPS 140-2 Compliance

### Cryptographic Modules
- **AES-256-GCM**: Data encryption at rest and in transit
- **RSA-2048**: Digital signatures for JWT tokens
- **SHA-256**: Hash functions and key derivation
- **Argon2id**: Password hashing (FIPS approved)
- **PBKDF2**: Key derivation with 100,000 iterations

### Validation Status
- OpenSSL FIPS module validation required for production
- Cryptographic operations use only FIPS-approved algorithms
- Runtime FIPS mode validation on application startup

## Security Architecture

### Transport Security
```
┌─────────────────────────────────────────────────────────────┐
│                        TLS 1.3 Layer                       │
│  ┌─────────────────────────────────────────────────────────┤
│  │            Application Security Layer                   │
│  │  ┌─────────────────────────────────────────────────────┤
│  │  │               Data Security Layer                   │
│  │  │  ┌─────────────────────────────────────────────────┤
│  │  │  │            Infrastructure Security              │
└──┴──┴──┴─────────────────────────────────────────────────────┘
```

### Authentication Flow
1. **User Authentication**: RSA-2048 signed JWT tokens
2. **Service Authentication**: Mutual TLS between services
3. **SSH Authentication**: Encrypted private keys for remote scans
4. **Database Authentication**: SCRAM-SHA-256 with TLS

### Authorization Model
- **Role-Based Access Control (RBAC)**
  - `admin`: Full system access
  - `user`: Limited scan operations
- **Resource-Level Permissions**: Host and scan access controls
- **API Endpoint Protection**: JWT token validation required

## Data Protection

### Encryption at Rest
- **Database**: PostgreSQL with TDE (Transparent Data Encryption)
- **Credentials**: AES-256-GCM encryption for SSH keys and passwords
- **Files**: SCAP content and results encrypted on disk
- **Logs**: Audit logs with integrity protection

### Encryption in Transit
- **HTTPS/TLS 1.3**: All client communications
- **Database TLS**: Encrypted PostgreSQL connections
- **Redis TLS**: Secure Celery message passing
- **SSH**: OpenSCAP remote scanning operations

### Key Management
- **Master Key**: Environment-based encryption key
- **JWT Keys**: RSA-2048 key pair for token signing
- **TLS Certificates**: X.509 certificates for service communication
- **SSH Keys**: Per-host encrypted private keys

## Network Security

### Network Segmentation
```
Internet  ┌──────────────────────────────────────────────────────┐
    ↓     │                Load Balancer                         │
┌─────────┼──────────────────────────────────────────────────────┤
│   DMZ   │              Frontend (HTTPS)                       │
├─────────┼──────────────────────────────────────────────────────┤
│ App Tier│           Backend API (mTLS)                        │
├─────────┼──────────────────────────────────────────────────────┤
│Data Tier│      Database + Redis (Encrypted)                   │
└─────────┴──────────────────────────────────────────────────────┘
```

### Security Headers
- **HSTS**: HTTP Strict Transport Security
- **CSP**: Content Security Policy
- **X-Frame-Options**: Clickjacking protection
- **X-Content-Type-Options**: MIME sniffing protection

## Audit and Compliance

### Security Logging
- **Authentication Events**: Login attempts and failures
- **Authorization Events**: Access control decisions
- **Scan Operations**: All OpenSCAP operations logged
- **System Events**: Configuration changes and errors

### Audit Trail
- **Tamper Evident**: Cryptographic integrity protection
- **Non-Repudiation**: Digital signatures on critical events
- **Retention**: Configurable log retention periods
- **Export**: SIEM integration capabilities

### Compliance Reporting
- **FIPS Validation**: Real-time compliance status
- **Security Metrics**: Authentication and authorization metrics
- **Vulnerability Scanning**: Regular security assessments
- **Penetration Testing**: Periodic security validation

## Secure Development

### Security Testing
- **Static Analysis**: Bandit security linting
- **Dependency Scanning**: Safety vulnerability checks
- **Secret Detection**: Pre-commit hook scanning
- **Dynamic Analysis**: Runtime security testing

### Code Security
- **Input Validation**: All user inputs sanitized
- **SQL Injection**: Parameterized queries only
- **XSS Protection**: Output encoding and CSP
- **CSRF Protection**: Token-based protection

## Operational Security

### Container Security
- **Base Images**: FIPS-compliant Red Hat UBI
- **Vulnerability Scanning**: Regular image updates
- **Runtime Security**: Non-root container execution
- **Resource Limits**: CPU and memory constraints

### Infrastructure Security
- **Secrets Management**: Environment-based configuration
- **Access Control**: Principle of least privilege
- **Network Policies**: Kubernetes network segmentation
- **Monitoring**: Security event monitoring

## Incident Response

### Security Monitoring
- **Failed Authentication**: Account lockout after 5 attempts
- **Unusual Activity**: Anomaly detection and alerting
- **System Health**: Continuous security posture monitoring
- **Threat Detection**: Real-time security event analysis

### Response Procedures
1. **Detection**: Automated security event detection
2. **Analysis**: Security team investigation
3. **Containment**: Threat isolation and mitigation
4. **Eradication**: Root cause remediation
5. **Recovery**: Service restoration
6. **Lessons Learned**: Post-incident review

## Configuration Management

### Security Baselines
- **CIS Benchmarks**: Container and OS hardening
- **NIST Guidelines**: Security control implementation
- **DISA STIGs**: Military security requirements
- **Custom Policies**: Organization-specific controls

### Secure Defaults
- **Encryption Enabled**: All data encrypted by default
- **Strong Authentication**: Multi-factor authentication required
- **Least Privilege**: Minimal permission grants
- **Audit Logging**: Comprehensive security logging

## Disaster Recovery

### Backup Security
- **Encrypted Backups**: AES-256 encryption for all backups
- **Key Escrow**: Secure key recovery procedures
- **Offsite Storage**: Geographically distributed backups
- **Recovery Testing**: Regular disaster recovery drills

### Business Continuity
- **High Availability**: Multi-instance deployments
- **Failover Procedures**: Automated service failover
- **Data Replication**: Real-time data synchronization
- **Recovery Objectives**: RTO < 4 hours, RPO < 1 hour

## Security Contacts

**Openwatch Vulnerability Reports and Security Team**: 
security@hanalyx.com


## References

- [NIST SP 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [FIPS 140-2](https://csrc.nist.gov/publications/detail/fips/140/2/final)
- [OWASP Security Guidelines](https://owasp.org/www-project-application-security-verification-standard/)
- [CIS Controls](https://www.cisecurity.org/controls)
