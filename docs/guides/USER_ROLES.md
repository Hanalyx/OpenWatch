# User Roles and Permissions

This document describes the role-based access control (RBAC) system in OpenWatch. It covers the six built-in roles, their permissions, and common workflows for each role.

Source of truth: `backend/app/rbac.py`

---

## Role Overview

OpenWatch defines six roles. The admin and analyst roles form a privilege hierarchy. The compliance officer and auditor roles exist on a parallel track optimized for reporting and audit workflows.

```
SUPER_ADMIN -------- Full platform access
  |
  SECURITY_ADMIN --- Security operations (no user management)
    |
    SECURITY_ANALYST - Day-to-day scanning

COMPLIANCE_OFFICER -- Reporting and audit (parallel track)
AUDITOR ------------ Read-only audit access (parallel track)
GUEST -------------- Minimal read-only
```

---

## Role Descriptions

### Super Admin

**Who uses it:** Platform owners and IT managers responsible for the entire OpenWatch deployment.

**What they can do:**
- Full access to all 33 permissions
- Create, read, update, and delete users
- Assign and change user roles
- Configure system settings, credentials, and maintenance mode
- All host, scan, content, and reporting operations

**What they cannot do:** Nothing is restricted. This role has unrestricted access.

**Typical tasks:**
- Create user accounts and assign roles
- Configure system-level settings (encryption keys, session timeouts)
- Manage SSH credentials for scan targets
- Perform system maintenance (database migrations, cache clearing)
- Review audit logs for security events

---

### Security Admin

**Who uses it:** Senior security engineers who manage hosts, scans, and content but do not manage users or system configuration.

**What they can do:**
- Read user accounts (cannot create, update, delete, or change roles)
- Full host management (create, read, update, delete, manage access)
- Full content management (create, read, update, delete)
- Full scan operations (create, read, update, delete, execute, write, approve, rollback)
- Read all results and generate/export reports
- View system logs
- Read audit logs and view/export compliance data

**What they cannot do:**
- Create, update, or delete user accounts
- Assign or change user roles
- Modify system configuration or credentials
- Perform system maintenance

**Typical tasks:**
- Register and configure scan target hosts
- Upload and manage compliance content
- Execute and monitor compliance scans
- Approve or rollback scan operations
- Review scan results and generate reports
- Investigate compliance failures using audit logs

---

### Security Analyst

**Who uses it:** Day-to-day operators who run scans, review results, and generate reports.

**What they can do:**
- Read and update hosts (manage assigned hosts)
- Read compliance content
- Create, read, execute, and write scans
- Read scan results
- Generate and export reports
- View compliance posture

**What they cannot do:**
- Create or delete hosts
- Manage host access policies
- Create, update, or delete compliance content
- Update, delete, approve, or rollback scans
- Read all results across the platform (only assigned results)
- Access system configuration, credentials, logs, or maintenance
- Read audit logs or export compliance data

**Typical tasks:**
- Check latest scan results for assigned hosts
- Start new compliance scans
- Generate compliance reports for management
- Export reports in required formats
- Monitor compliance posture trends

---

### Compliance Officer

**Who uses it:** Personnel responsible for regulatory reporting, exception management, and audit preparation.

**What they can do:**
- Read hosts (no modification)
- Read compliance content
- Read scans (no execution or modification)
- Read results, including cross-platform results (results:read_all)
- Generate and export reports
- Read audit logs
- View and export compliance data

**What they cannot do:**
- Create, update, or delete hosts
- Manage host access
- Modify compliance content
- Create, execute, or modify scans
- Access system configuration, credentials, logs, or maintenance
- Manage users or roles

**Typical tasks:**
- Review compliance posture across all hosts
- Export compliance data for regulatory submissions
- Generate reports for auditors and management
- Review audit logs for compliance evidence
- Manage compliance exceptions (request, track, review)

---

### Auditor

**Who uses it:** Internal or external auditors who need read-only access to compliance evidence and audit trails.

**What they can do:**
- Read hosts
- Read compliance content
- Read scans
- Read results, including cross-platform results (results:read_all)
- Export reports
- Read audit logs
- View and export compliance data

**What they cannot do:**
- Create, update, or delete any resource
- Execute scans
- Generate reports (can only export existing ones)
- Access system configuration, credentials, logs, or maintenance
- Manage users or roles

**Typical tasks:**
- Query historical compliance posture at a point in time
- Export audit logs for evidence collection
- Review compliance exception history
- Export scan results for external analysis

---

### Guest

**Who uses it:** Stakeholders who need minimal visibility into compliance status without operational access.

**What they can do:**
- Read hosts (assigned hosts only)
- Read results (assigned results only)
- View compliance posture

**What they cannot do:**
- Everything else. Guests have no write, execute, export, or administrative access.

**Typical tasks:**
- View compliance dashboard
- Check host compliance status
- Review assigned scan results

---

## Permissions Matrix

Permissions are grouped by category. Y = granted, - = denied.

| Permission | Super Admin | Security Admin | Security Analyst | Compliance Officer | Auditor | Guest |
|---|---|---|---|---|---|---|
| **User Management** | | | | | | |
| user:create | Y | - | - | - | - | - |
| user:read | Y | Y | - | - | - | - |
| user:update | Y | - | - | - | - | - |
| user:delete | Y | - | - | - | - | - |
| user:manage_roles | Y | - | - | - | - | - |
| **Host Management** | | | | | | |
| host:create | Y | Y | - | - | - | - |
| host:read | Y | Y | Y | Y | Y | Y |
| host:update | Y | Y | Y | - | - | - |
| host:delete | Y | Y | - | - | - | - |
| host:manage_access | Y | Y | - | - | - | - |
| **Content Management** | | | | | | |
| content:create | Y | Y | - | - | - | - |
| content:read | Y | Y | Y | Y | Y | - |
| content:update | Y | Y | - | - | - | - |
| content:delete | Y | Y | - | - | - | - |
| **Scan Operations** | | | | | | |
| scan:create | Y | Y | Y | - | - | - |
| scan:read | Y | Y | Y | Y | Y | - |
| scan:update | Y | Y | - | - | - | - |
| scan:delete | Y | Y | - | - | - | - |
| scan:execute | Y | Y | Y | - | - | - |
| scan:write | Y | Y | Y | - | - | - |
| scan:approve | Y | Y | - | - | - | - |
| scan:rollback | Y | Y | - | - | - | - |
| **Results and Reports** | | | | | | |
| results:read | Y | Y | Y | Y | Y | Y |
| results:read_all | Y | Y | - | Y | Y | - |
| reports:generate | Y | Y | Y | Y | - | - |
| reports:export | Y | Y | Y | Y | Y | - |
| **System Administration** | | | | | | |
| system:config | Y | - | - | - | - | - |
| system:credentials | Y | - | - | - | - | - |
| system:logs | Y | Y | - | - | - | - |
| system:maintenance | Y | - | - | - | - | - |
| **Audit and Compliance** | | | | | | |
| audit:read | Y | Y | - | Y | Y | - |
| compliance:view | Y | Y | Y | Y | Y | Y |
| compliance:export | Y | Y | - | Y | Y | - |

**Permission counts per role:** Super Admin: 33, Security Admin: 26, Security Analyst: 11, Compliance Officer: 11, Auditor: 9, Guest: 3.

---

## Common Workflows

### Security Analyst

1. Log in to OpenWatch
2. Review the compliance dashboard for assigned hosts
3. Identify hosts that need scanning
4. Start new compliance scans against target hosts
5. Monitor scan progress
6. Review scan results and failed findings
7. Generate compliance reports
8. Export reports for distribution

### Compliance Officer

1. Log in to OpenWatch
2. Review compliance posture across all hosts
3. Query historical posture for regulatory windows
4. Export compliance data for submission
5. Review and manage compliance exceptions
6. Generate reports for auditors and executives
7. Review audit logs for evidence of control effectiveness

### Auditor

1. Log in to OpenWatch
2. Query historical compliance posture at a specific point in time
3. Export audit logs covering the audit period
4. Review compliance exception history and approvals
5. Export scan results and findings for external analysis tools

---

## Managing Roles

Role assignment requires the `user:manage_roles` permission, which is exclusive to the Super Admin role.

To change a user's role, use the user management API:

```
PUT /api/users/{user_id}
Content-Type: application/json
Authorization: Bearer <super_admin_token>

{
  "role": "security_analyst"
}
```

Valid role values: `super_admin`, `security_admin`, `security_analyst`, `compliance_officer`, `auditor`, `guest`.

Only one role can be assigned per user. Role changes take effect on the user's next authentication (token refresh or new login).

---

## Related Documentation

- [Security Hardening](SECURITY_HARDENING.md) -- platform security configuration
- [Production Deployment](PRODUCTION_DEPLOYMENT.md) -- deployment procedures
- [Monitoring Setup](MONITORING_SETUP.md) -- operational monitoring
