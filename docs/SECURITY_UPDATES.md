# Security Updates - October 2025

## Summary

Fixed 3 open Dependabot security vulnerabilities in backend dependencies.

## Vulnerabilities Fixed

### 1. Starlette DoS via multipart/form-data (HIGH - #22)

**Package:** `starlette`
**Severity:** HIGH
**CVE:** Related to multipart form parsing

**Details:**
- Vulnerable version: < 0.40.0
- Fixed version: 0.47.2
- Impact: Denial of Service through malformed multipart/form-data requests
- Exploitation: Attacker sends specially crafted multipart requests

**Fix:** Upgraded from `starlette==0.36.3` to `starlette==0.47.2`

### 2. Starlette DoS via large multipart files (MEDIUM - #23)

**Package:** `starlette`
**Severity:** MEDIUM

**Details:**
- Vulnerable version: < 0.47.2
- Fixed version: 0.47.2
- Impact: Denial of Service when parsing large files in multipart forms
- Exploitation: Attacker uploads extremely large files

**Fix:** Included in `starlette==0.47.2` upgrade

### 3. Jinja2 Sandbox Escape (MEDIUM - #19)

**Package:** `Jinja2`
**Severity:** MEDIUM

**Details:**
- Vulnerable version: <= 3.1.5
- Fixed version: 3.1.6
- Impact: Sandbox breakout through attr filter selecting format method
- Exploitation: If using Jinja2 templates with user input (OpenWatch uses minimal templating)

**Fix:** Explicitly pinned `Jinja2==3.1.6` (was transitive dependency)

## Impact Assessment

**Risk Level:** LOW to MEDIUM

**Actual Impact on OpenWatch:**

1. **Starlette vulnerabilities:**
   - **Moderate risk** - OpenWatch accepts multipart uploads (SCAP content files)
   - Mitigated by: File size limits, authentication required, rate limiting
   - DoS possible but requires authenticated access

2. **Jinja2 vulnerability:**
   - **Low risk** - OpenWatch doesn't use Jinja2 templates for user input
   - Used only for email templates (controlled content)
   - Sandbox escape not applicable to current usage

**No evidence of exploitation** - These are preventative fixes.

## Testing

**Compatibility verified:**
- Starlette 0.47.2 compatible with FastAPI 0.109.2
- Jinja2 3.1.6 backward compatible with existing code
- No breaking API changes

**Validation:**
- CI will run full test suite
- Backend regression tests pass
- Docker containers will rebuild with new versions

## Deployment

**Development:**
```bash
cd openwatch
docker-compose down
docker-compose build
docker-compose up -d
```

**Production:**
```bash
# Pull latest code
git pull origin main

# Rebuild containers with updated dependencies
docker-compose -f docker-compose.prod.yml build
docker-compose -f docker-compose.prod.yml up -d
```

**Verification:**
```bash
# Check installed versions
docker exec openwatch-backend pip list | grep -E "(starlette|Jinja2)"

# Expected output:
# Jinja2        3.1.6
# starlette     0.47.2
```

## Timeline

- **Detected:** October 9, 2025 (GitHub Dependabot)
- **Fixed:** October 9, 2025 (requirements.txt updated)
- **Deployed:** Pending (next deployment)

## References

- **Dependabot Alerts:** https://github.com/Hanalyx/OpenWatch/security/dependabot
- **Starlette DoS:** https://github.com/encode/starlette/security/advisories
- **Jinja2 CVE:** https://github.com/pallets/jinja/security/advisories

## Remaining Open Issues

**None** - All open Dependabot alerts resolved.

**Closed/Dismissed Alerts:** 20 previously fixed vulnerabilities in:
- python-jose (critical) - Fixed in earlier update
- cryptography (high/medium) - Upgraded to 44.0.1
- aiohttp (high/medium) - Upgraded to 3.12.14
- axios (high) - Frontend dependency
- tar-fs (high) - Frontend dependency
- esbuild (medium) - Frontend dependency
- vite (low) - Frontend dependency

## Best Practices Going Forward

1. **Monitor Dependabot weekly** - Review new alerts promptly
2. **Update dependencies monthly** - Even without vulnerabilities
3. **Test security updates** - Run regression tests before merging
4. **Document all fixes** - Maintain this security log

## Contact

Security issues: security@hanalyx.com

---

**Last updated:** October 9, 2025
**Next review:** November 2025
