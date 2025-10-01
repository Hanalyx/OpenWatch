# SSH Validation Refactoring - Phase 1 Deployment Guide

## Overview
This guide covers the deployment of Phase 1 SSH validation improvements that fix critical credential creation issues.

## Changes Included
- **SSH Key Validation**: Refactored to use paramiko's built-in capabilities
- **Bug Fixes**: Fixed credential validation function signature and attribute errors
- **Error Handling**: Improved frontend error messages for better user experience

## Deployment Steps

### 1. Pre-Deployment Checks
```bash
# Verify current version
git log --oneline -5

# Check for any uncommitted changes
git status

# Ensure containers are healthy
docker-compose ps
```

### 2. Deploy Backend Changes
```bash
# Copy updated files to containers
docker cp backend/app/services/unified_ssh_service.py openwatch-backend:/app/backend/app/services/
docker cp backend/app/routes/system_settings_unified.py openwatch-backend:/app/backend/app/routes/
docker cp backend/app/services/credential_validation.py openwatch-backend:/app/backend/app/services/

# Restart backend to load changes
docker-compose restart backend

# Wait for backend to be ready
sleep 10

# Verify backend is running
docker-compose logs --tail=20 backend | grep "application started successfully"
```

### 3. Deploy Frontend Changes
```bash
# For development environments with volume mounts
# The frontend changes should auto-reload

# For production without volume mounts
docker cp frontend/src/pages/settings/Settings.tsx openwatch-frontend:/app/src/pages/settings/
docker-compose restart frontend
```

### 4. Post-Deployment Verification

#### Quick Smoke Test
1. Navigate to Settings → System Settings
2. Click "Add Credentials"
3. Try creating a password-based credential first (simpler)
4. Try creating an SSH key-based credential
5. Verify error messages are specific, not generic

#### API Health Check
```bash
# Test authentication endpoint
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# Check system credentials endpoint (requires auth token)
curl http://localhost:8000/api/system/credentials \
  -H "Authorization: Bearer <token>"
```

## Monitoring Setup

### 1. Key Metrics to Track

#### Success Metrics
- SSH credential creation success rate
- Types of credentials created (password vs SSH key)
- Average response time for credential operations

#### Error Metrics
- Error types and frequencies
- Most common validation failures
- 500 error occurrences (should be zero)

### 2. Log Monitoring Commands

```bash
# Monitor credential creation attempts
docker-compose logs -f backend | grep -E "(credential|SSH|validation)"

# Track errors
docker-compose logs -f backend | grep -E "(ERROR|Exception|500)"

# Monitor specific error patterns
docker-compose logs backend --since 1h | grep "validation failed" | wc -l
```

### 3. Create Monitoring Dashboard Script

```python
#!/usr/bin/env python3
# save as: monitor_ssh_validation.py

import subprocess
import time
from datetime import datetime, timedelta

def get_log_stats(since_minutes=60):
    """Get statistics from backend logs"""
    since = datetime.now() - timedelta(minutes=since_minutes)
    since_str = since.strftime("%Y-%m-%d %H:%M:%S")
    
    cmd = f'docker-compose logs backend --since "{since_str}"'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    logs = result.stdout
    
    stats = {
        "credential_creates": logs.count("POST /api/system/credentials"),
        "successful_stores": logs.count("Stored system credential"),
        "validation_errors": logs.count("validation failed"),
        "500_errors": logs.count("500 Internal Server Error"),
        "ssh_key_creates": logs.count("auth_method='ssh_key'"),
        "password_creates": logs.count("auth_method='password'")
    }
    
    return stats

def print_dashboard():
    """Print monitoring dashboard"""
    print("🔍 SSH Validation Monitoring Dashboard")
    print("=" * 50)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\nLast Hour Statistics:")
    
    stats = get_log_stats(60)
    
    total_attempts = stats["credential_creates"]
    success_rate = (stats["successful_stores"] / total_attempts * 100) if total_attempts > 0 else 0
    
    print(f"📊 Credential Creation Attempts: {total_attempts}")
    print(f"✅ Successful: {stats['successful_stores']} ({success_rate:.1f}%)")
    print(f"❌ Validation Errors: {stats['validation_errors']}")
    print(f"💥 500 Errors: {stats['500_errors']}")
    print(f"\n🔑 By Type:")
    print(f"   SSH Keys: {stats['ssh_key_creates']}")
    print(f"   Passwords: {stats['password_creates']}")

if __name__ == "__main__":
    while True:
        print("\033[2J\033[H")  # Clear screen
        print_dashboard()
        time.sleep(30)  # Update every 30 seconds
```

## Known Issues and Workarounds

### Issue 1: SSH Key Format Not Recognized
**Symptom**: "Invalid SSH key format" error
**Workaround**: Ensure SSH key includes full headers:
```
-----BEGIN OPENSSH PRIVATE KEY-----
[key content]
-----END OPENSSH PRIVATE KEY-----
```

### Issue 2: Credential Validation Too Strict
**Symptom**: "Please check your authentication credentials" for valid credentials
**Workaround**: This may indicate the credential doesn't meet security policies. Check:
- Password complexity requirements
- SSH key strength (minimum 2048-bit RSA or Ed25519)

## Rollback Procedure

If issues are encountered:

```bash
# Revert to previous commits
git log --oneline -10  # Find the commit before changes
git checkout <commit-hash>

# Restart services with old code
docker-compose down
docker-compose up -d

# Or manually restore files from git
git checkout HEAD~3 -- backend/app/services/unified_ssh_service.py
git checkout HEAD~3 -- backend/app/routes/system_settings_unified.py
git checkout HEAD~3 -- backend/app/services/credential_validation.py
docker cp [files] [containers]
docker-compose restart backend
```

## Success Criteria for Phase 2

Before proceeding to Phase 2, ensure:
- [ ] Zero 500 errors for credential operations
- [ ] >90% success rate for valid credentials
- [ ] Clear error messages for all failure scenarios
- [ ] No performance degradation
- [ ] No memory leaks after 24 hours

## Next Steps

After 24-48 hours of stable operation:
1. Review collected metrics
2. Address any discovered issues
3. Document any additional workarounds needed
4. Proceed with Phase 2 (SSH Connection Management Audit)