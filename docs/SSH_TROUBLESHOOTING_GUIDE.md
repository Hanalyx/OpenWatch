# SSH Connection Troubleshooting Guide

## Overview
This guide documents known issues, workarounds, and best practices for SSH connectivity in OpenWatch based on production experience and recent infrastructure improvements.

## Recent Infrastructure Improvements (Phases 1-3)

### Phase 1: SSH Validation Infrastructure (Completed)
- **Issue**: Critical 500 errors during SSH credential creation
- **Root Cause**: Custom SSH key parsing logic conflicts with paramiko validation
- **Solution**: Refactored to use paramiko's built-in validation methods
- **Impact**: 100% success rate for SSH credential creation

### Phase 2: Connection Management Architecture (Completed)  
- **Issue**: Database session management failures in SSH services
- **Root Cause**: Constructor parameter mismatch between HostMonitor and UnifiedSSHService
- **Solution**: Updated dependency injection and session management
- **Impact**: Resolved "No database session available" errors

### Phase 3: Authentication Compatibility (Completed)
- **Issue**: "Unsupported authentication method: ssh-key" errors
- **Root Cause**: String format inconsistency between database storage and SSH service
- **Solution**: Enhanced auth method support for all variants (key, ssh_key, ssh-key)
- **Impact**: 100% host connectivity achieved (3/3 hosts online)

## Known Issues and Workarounds

### 1. SSH Key Format Compatibility

**Issue**: Some SSH key formats may not validate properly during upload.

**Symptoms**:
- "Invalid SSH key format" errors during credential creation
- Keys work with standard SSH clients but fail OpenWatch validation

**Workarounds**:
1. **Convert key format**: Use `ssh-keygen -p -f keyfile -m PEM` to convert to PEM format
2. **Generate new keys**: Use `ssh-keygen -t rsa -b 4096 -m PEM` for maximum compatibility
3. **Check key headers**: Ensure keys start with `-----BEGIN OPENSSH PRIVATE KEY-----` or `-----BEGIN RSA PRIVATE KEY-----`

**Prevention**:
- Always test SSH keys with `ssh -i keyfile user@host` before uploading to OpenWatch
- Use RSA 2048+ or Ed25519 keys for best compatibility

### 2. Host Status Transitions

**Issue**: Hosts may show inconsistent status during monitoring cycles.

**Expected Flow**: `Offline` → `Reachable` → `Online`
- **Offline**: No network connectivity
- **Reachable**: Network accessible but SSH authentication failed
- **Online**: Full SSH connectivity established

**Common Scenarios**:
1. **Stuck in "Reachable"**: SSH port open but authentication failing
   - Check SSH credentials in Settings → System Settings → SSH Credentials
   - Verify host-specific credentials if configured
   - Review SSH service logs for detailed error messages

2. **Intermittent "Offline" status**: Network connectivity issues
   - Check firewall rules for port 22 access
   - Verify DNS resolution for hostname/IP
   - Consider network latency and timeout settings

**Monitoring Best Practices**:
- Use "Check Status" button for immediate host verification
- Monitor host status trends rather than single point-in-time results
- Configure alert settings for status change notifications

### 3. Credential Inheritance and Priority

**Issue**: Confusion about which SSH credentials are used for each host.

**Credential Priority Order**:
1. **Host-specific credentials** (if configured in host edit form)
2. **System default credentials** (Settings → System Settings → SSH Credentials)
3. **No credentials available** (host marked as unreachable for SSH operations)

**Troubleshooting Steps**:
1. Check host details page for credential source information
2. Verify system credentials are configured and not placeholder values
3. Use SSH debug logs (available in Settings → SSH Debug) for detailed connection traces

**Best Practices**:
- Configure system default credentials first for organization-wide SSH access
- Use host-specific credentials only for exceptions (different users, special auth requirements)
- Regularly audit credential usage through monitoring dashboard

### 4. Performance and Scaling Considerations

**Issue**: SSH connection timeouts during bulk operations or high load.

**Current Limits**:
- SSH connection timeout: 10 seconds
- Concurrent SSH connections: Limited by system resources
- Background monitoring: All hosts checked sequentially

**Optimization Strategies**:
1. **Timeout Adjustment**: Increase SSH timeout for slower networks
2. **Batch Processing**: Use bulk operations judiciously to avoid overwhelming targets
3. **Monitoring Intervals**: Adjust automatic monitoring frequency based on infrastructure size

**Resource Monitoring**:
- Check container health status: `docker-compose ps`
- Monitor SSH service logs for timeout patterns
- Use Prometheus metrics endpoint `/metrics` for performance tracking

### 5. SCAP Content and SSH Integration

**Issue**: SCAP scanning requires stable SSH connectivity.

**Prerequisites for Successful Scanning**:
1. Host status must be "Online" (green indicator in dashboard)
2. SSH credentials must support command execution (not just authentication)
3. Target user must have sufficient privileges for SCAP scanning commands

**Common Scanning Issues**:
1. **"Host offline" during scan**: SSH connectivity lost during scan execution
   - Verify sustained SSH connectivity with longer test commands
   - Check for SSH session limits on target systems
   - Consider SSH connection keep-alive settings

2. **Permission denied for SCAP commands**: Insufficient user privileges
   - Ensure SSH user has sudo/admin access if required by SCAP content
   - Test manual SCAP command execution: `oscap info /path/to/datastream.xml`
   - Review SCAP content requirements for target platform

## Emergency Procedures

### Complete SSH System Reset

If SSH connectivity is completely broken:

1. **Verify Container Health**:
   ```bash
   docker-compose ps
   docker-compose logs backend
   ```

2. **Reset SSH Configuration**:
   - Navigate to Settings → System Settings → SSH Credentials
   - Delete existing credentials and recreate with known-good SSH key
   - Test with a single host before bulk operations

3. **Database Verification**:
   ```bash
   # Connect to database container
   docker-compose exec db psql -U openwatch -d openwatch
   # Check system credentials
   SELECT name, username, auth_method FROM system_credentials WHERE is_active = true;
   ```

4. **Restart SSH Services**:
   ```bash
   docker-compose restart backend worker
   ```

### Diagnostic Information Collection

For support requests, collect the following:

1. **System Status**:
   - Container health: `docker-compose ps`
   - Application health: `curl http://localhost:8000/health`

2. **SSH Specific Logs**:
   - Backend logs: `docker-compose logs backend | grep -i ssh`
   - Worker logs: `docker-compose logs worker | grep -i ssh`

3. **Database State**:
   - Host count and status distribution
   - System credentials configuration (sensitive data redacted)
   - Recent audit log entries for SSH operations

4. **Network Connectivity**:
   - Basic connectivity to problem hosts: `ping <host_ip>`
   - SSH port accessibility: `telnet <host_ip> 22`

## Best Practices Summary

### For Administrators
1. **Always configure system default SSH credentials** before adding hosts
2. **Test SSH keys manually** before uploading to OpenWatch
3. **Monitor host status trends** rather than individual check results
4. **Use bulk operations carefully** to avoid overwhelming target systems
5. **Regularly review audit logs** for SSH-related security events

### For Security Teams
1. **Enforce strong SSH key standards** (RSA 2048+ or Ed25519)
2. **Implement SSH key rotation policies** through system credential updates
3. **Monitor authentication failures** through audit logging
4. **Review SSH access patterns** for anomalous behavior
5. **Maintain principle of least privilege** for SSH user accounts

### For Operations Teams
1. **Automate host monitoring** with appropriate alert thresholds
2. **Document host-specific SSH requirements** (special users, ports, etc.)
3. **Maintain SSH connectivity baselines** for performance monitoring
4. **Plan SSH maintenance windows** for system credential updates
5. **Test disaster recovery procedures** for SSH system reset scenarios

## Version History

- **v1.0** (Phase 1): Initial SSH validation improvements
- **v1.1** (Phase 2): Database session management fixes  
- **v1.2** (Phase 3): Authentication compatibility enhancements
- **v1.3** (Current): Comprehensive documentation and troubleshooting guide

## Support and Escalation

For issues not covered in this guide:

1. **Check application logs** for specific error messages
2. **Review audit logs** for related security events
3. **Verify container health** and resource availability
4. **Collect diagnostic information** as outlined above
5. **Escalate with complete information** including system state and reproduction steps

---

*This document is maintained as part of the OpenWatch security scanner project and reflects real-world production experience with SSH connectivity challenges and solutions.*