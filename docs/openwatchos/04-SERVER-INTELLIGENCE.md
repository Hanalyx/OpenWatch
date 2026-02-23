# Server Intelligence Collection

**Status**: Implemented (PR #274, merged 2026-02-16)
**Component**: `backend/app/services/system_info/`
**Part of**: OpenWatch OS Transformation

---

## Overview

Server Intelligence is a data collection system that gathers detailed information about managed hosts during Kensa compliance scans. When a compliance scan runs against a host via SSH, the system automatically collects information about the host's operating system, installed packages, running services, user accounts, network configuration, firewall rules, routing table, security audit events, and resource metrics.

The collected data serves multiple purposes:

- **Visibility**: Provides administrators with a comprehensive inventory of what is running on each host without requiring separate tools.
- **Compliance Context**: Enriches compliance scan results with hardware, software, and configuration context needed for audit reports.
- **Drift Detection**: Enables detection of unauthorized changes between scans by comparing current state to previously collected data.
- **Security Posture**: Surfaces security-relevant details such as users with unrestricted sudo access, services listening on unexpected ports, and weak firewall configurations.

Data is collected via SSH using the same session established for the Kensa compliance scan. No additional agents or tools need to be installed on the target host.

---

## Data Categories

### 1. System Information

Core operating system, kernel, hardware, and security framework details. Stored as a single record per host (upserted on each collection).

**Collected Fields**:

| Field | Description | Source |
|-------|-------------|--------|
| os_name | Distribution name (e.g., "Red Hat Enterprise Linux") | /etc/os-release NAME |
| os_version | Version ID (e.g., "9.4") | /etc/os-release VERSION_ID |
| os_version_full | Full version string (e.g., "9.4 (Plow)") | /etc/os-release VERSION |
| os_pretty_name | Human-readable name | /etc/os-release PRETTY_NAME |
| os_id | Distribution identifier (e.g., "rhel") | /etc/os-release ID |
| os_id_like | Related distributions (e.g., "fedora") | /etc/os-release ID_LIKE |
| kernel_name | Kernel name (e.g., "Linux") | uname -s |
| kernel_release | Kernel release string | uname -r |
| kernel_version | Kernel version string | uname -v |
| architecture | CPU architecture (e.g., "x86_64") | uname -m |
| cpu_model | CPU model name | /proc/cpuinfo model name |
| cpu_cores | Physical CPU cores | /proc/cpuinfo cpu cores |
| cpu_threads | Logical CPU threads (processors) | /proc/cpuinfo processor count |
| memory_total_mb | Total memory in megabytes | /proc/meminfo MemTotal |
| memory_available_mb | Available memory in megabytes | /proc/meminfo MemAvailable |
| swap_total_mb | Total swap in megabytes | /proc/meminfo SwapTotal |
| disk_total_gb | Root filesystem total size in GB | df -BG / |
| disk_used_gb | Root filesystem used space in GB | df -BG / |
| disk_free_gb | Root filesystem free space in GB | df -BG / |
| selinux_status | SELinux enforcement state | getenforce |
| selinux_mode | SELinux policy type (e.g., "targeted") | /etc/selinux/config SELINUXTYPE |
| apparmor_status | AppArmor state (enabled, disabled, not_installed) | aa-status --enabled |
| apparmor_profiles_loaded | Number of loaded AppArmor profiles | aa-status |
| firewall_status | Firewall active/inactive | systemctl / ufw / nft / iptables |
| firewall_service | Active firewall service name | Detection order (see below) |
| hostname | Short hostname | hostname |
| fqdn | Fully qualified domain name | hostname -f |
| primary_ip | IP address on the default route interface | ip route get 1 |
| uptime_seconds | System uptime in seconds | /proc/uptime |
| boot_time | Calculated boot timestamp (UTC) | now - uptime |

### 2. Installed Packages

Complete inventory of installed software packages. Stored per host with a full-refresh pattern on each collection (existing records are deleted and replaced).

**Collected Fields**:

| Field | Description |
|-------|-------------|
| name | Package name |
| version | Package version |
| release | Package release string (RPM/DEB) |
| arch | Package architecture (x86_64, noarch, amd64, etc.) |
| source_repo | Source repository name (zypper only) |
| installed_at | Installation timestamp (RPM only, from INSTALLTIME) |

### 3. System Services

Inventory of systemd services with their states and listening ports.

**Collected Fields**:

| Field | Description |
|-------|-------------|
| name | Service unit name (without .service suffix) |
| display_name | Service description from systemd |
| status | Sub-state: running, stopped, failed, exited, dead |
| enabled | Whether the service is enabled at boot (enabled or static = true) |
| service_type | Service type (simple, forking, oneshot) |
| run_as_user | User the service runs as |
| listening_ports | JSONB array of listening TCP ports (from ss -tlnp) |

The listening_ports field contains entries in the following format:
```json
[{"port": 22, "protocol": "tcp", "address": "0.0.0.0"}]
```

### 4. User Accounts

Local user accounts with group membership, password aging, SSH key inventory, and sudo permissions.

**Collected Fields**:

| Field | Description | Source |
|-------|-------------|--------|
| username | Login name | /etc/passwd |
| uid | User ID | /etc/passwd |
| gid | Primary group ID | /etc/passwd |
| groups | Group memberships (JSONB array) | /etc/group |
| home_dir | Home directory path | /etc/passwd |
| shell | Login shell | /etc/passwd |
| gecos | Full name / comment field | /etc/passwd |
| is_system_account | True if UID < 1000 | Calculated |
| is_locked | True if password hash starts with ! or * | /etc/shadow |
| has_password | True if a password hash is set | /etc/shadow |
| password_last_changed | When the password was last changed | /etc/shadow (days since epoch) |
| password_expires | When the password expires | /etc/shadow (last_changed + max_days) |
| password_max_days | Maximum password age in days | /etc/shadow |
| password_warn_days | Days before expiry to warn user | /etc/shadow |
| last_login | Last login timestamp | lastlog |
| last_login_ip | IP address of last login | lastlog |
| ssh_keys_count | Number of authorized SSH keys | ~/.ssh/authorized_keys |
| ssh_key_types | Types of SSH keys (JSONB array, e.g., ["rsa", "ed25519"]) | ~/.ssh/authorized_keys |
| sudo_rules | Parsed sudo rules (JSONB array) | /etc/sudoers, /etc/sudoers.d/* |
| has_sudo_all | True if user has ALL=(ALL) ALL | Calculated from sudoers |
| has_sudo_nopasswd | True if user has NOPASSWD rule | Calculated from sudoers |

### 5. Network Interfaces

Network interface configuration with IP addresses. Uses `ip -json addr show` with a fallback to text parsing of `ip addr show`.

**Collected Fields**:

| Field | Description |
|-------|-------------|
| interface_name | Interface name (e.g., eth0, ens192) |
| mac_address | MAC address |
| ip_addresses | JSONB array of IP address objects |
| is_up | Whether the interface has the UP flag |
| mtu | Maximum transmission unit |
| speed_mbps | Link speed in Mbps |
| interface_type | Detected type: ethernet, loopback, bridge, vlan, bond, veth |

The ip_addresses field contains entries in the following format:
```json
[{"address": "192.168.1.10", "prefix": 24, "type": "ipv4", "scope": "global"}]
```

Interface type detection logic:
- "lo" -> loopback
- link_type "ether" -> ethernet
- link_type "bridge" -> bridge
- Name contains "." -> vlan
- Name starts with "bond" -> bond
- Name starts with "veth" -> veth
- Name starts with "docker" or "br-" -> bridge

### 6. Firewall Rules

Firewall configuration from whichever firewall system is active. The collector tries multiple firewall tools in a specific order and returns rules from the first one found.

**Collected Fields**:

| Field | Description |
|-------|-------------|
| firewall_type | Source firewall system (ufw, firewalld, iptables) |
| chain | Rule chain (INPUT, OUTPUT, FORWARD) |
| rule_number | Rule position within the chain |
| protocol | Protocol (tcp, udp, icmp, all) |
| source | Source address/network |
| destination | Destination address/network |
| port | Destination port or port range |
| action | Rule action (ACCEPT, DROP, REJECT, ALLOW, DENY, LIMIT) |
| interface_in | Input interface |
| interface_out | Output interface |
| state | Connection state (NEW, ESTABLISHED, RELATED) |
| comment | Rule comment |
| raw_rule | Original rule text as collected |

### 7. Network Routes

Routing table from the host. Uses `ip -json route show` with a fallback to text parsing.

**Collected Fields**:

| Field | Description |
|-------|-------------|
| destination | Destination network/host in CIDR notation, or "default" |
| gateway | Next-hop gateway IP address (null for direct routes) |
| interface | Output interface name |
| metric | Route metric |
| scope | Route scope (link, host, global) |
| route_type | Route type (unicast, local, broadcast) |
| protocol | How the route was learned (kernel, static, dhcp) |
| is_default | True if this is a default route |

### 8. Security Audit Events

Authentication and privilege escalation events from system logs. Unlike other categories, audit events use an append pattern (not full refresh) with deduplication.

**Collected Fields**:

| Field | Description |
|-------|-------------|
| event_type | Category: auth, sudo, login_failure |
| event_timestamp | When the event occurred |
| username | User who performed the action |
| source_ip | IP address the action originated from |
| action | Specific action (ssh_login, command, failed_login, su_session, login_session) |
| target | Target of the action (e.g., command run via sudo) |
| result | Outcome: success or failure |
| raw_message | Original log message (truncated to 500 chars) |
| source_process | Process that generated the event (sshd, sudo, su, login) |
| metadata | Additional structured data (JSONB) |

**Event Sources** (checked in order):
1. `journalctl` with JSON output for sshd, sudo, su, and login processes (last N hours)
2. `/var/log/secure` (parsed as fallback if journalctl is unavailable)
3. `lastb` for failed login attempts from /var/log/btmp

**Default collection parameters**: max_events=1000, hours_back=24.

### 9. Resource Metrics

Point-in-time system resource utilization. Stored as time-series data (each collection inserts a new row, not an upsert).

**Collected Fields**:

| Field | Description | Source |
|-------|-------------|--------|
| collected_at | Timestamp of collection (UTC) | System clock |
| cpu_usage_percent | Overall CPU usage percentage | /proc/stat (calculated from idle ratio) |
| load_avg_1m | 1-minute load average | /proc/loadavg |
| load_avg_5m | 5-minute load average | /proc/loadavg |
| load_avg_15m | 15-minute load average | /proc/loadavg |
| memory_total_bytes | Total physical memory in bytes | /proc/meminfo MemTotal |
| memory_used_bytes | Used memory in bytes (total - available) | Calculated |
| memory_available_bytes | Available memory in bytes | /proc/meminfo MemAvailable |
| swap_total_bytes | Total swap in bytes | /proc/meminfo SwapTotal |
| swap_used_bytes | Used swap in bytes (total - free) | Calculated |
| disk_total_bytes | Root filesystem total in bytes | df -B1 / |
| disk_used_bytes | Root filesystem used in bytes | df -B1 / |
| disk_available_bytes | Root filesystem available in bytes | df -B1 / |
| uptime_seconds | System uptime in seconds | /proc/uptime |
| process_count | Number of running processes | Count of /proc/[0-9]* directories |

---

## Collection Methods

### SSH Session

All data is collected through the existing SSH session established by the Kensa compliance scanner. The `SystemInfoCollector` class accepts any SSH session object that has a `run()` method returning a result with `stdout`, `stderr`, and `exit_code` (or `returncode`) attributes.

```python
class SystemInfoCollector:
    def __init__(self, ssh_session: Any):
        self.ssh = ssh_session

    def _run_command(self, command: str) -> Optional[str]:
        result = self.ssh.run(command)
        exit_code = getattr(result, "exit_code", getattr(result, "returncode", None))
        if exit_code == 0:
            stdout = result.stdout.strip() if result.stdout else ""
            return stdout if stdout else None
        return None
```

Commands that fail (non-zero exit code or exception) return None and are logged at DEBUG level. This means collection is best-effort -- if a particular command is unavailable on the target host, that field is simply omitted.

### Package Manager Detection

The collector tries package managers in the following order:

1. **zypper** (SUSE-preferred): `zypper packages --installed-only` -- provides package name, version, architecture, and source repository.
2. **rpm** (RHEL-family and SUSE fallback): `rpm -qa --queryformat '%{NAME}|%{VERSION}|%{RELEASE}|%{ARCH}|%{INSTALLTIME}\n'` -- provides name, version, release, architecture, and installation timestamp.
3. **dpkg** (Debian/Ubuntu): `dpkg -l | grep ^ii` -- provides name, version (parsed into version and release at the last hyphen), and architecture.

The first package manager that returns results is used. If none return output, the collector logs a warning.

### Service Discovery

Services are collected from systemd exclusively:

1. `systemctl list-units --type=service --all --no-legend --no-pager` -- lists all service units with their LOAD, ACTIVE, and SUB states. Only units with the `.service` suffix are processed. The SUB state (running, stopped, failed, exited, dead) becomes the `status` field.
2. `systemctl list-unit-files --type=service --no-legend --no-pager` -- determines whether each service is enabled at boot. Services with state "enabled" or "static" are marked as enabled.
3. `ss -tlnp` -- maps listening TCP ports to service processes by parsing the process info field.

### Security Framework Detection

**SELinux** (RHEL family):
- `getenforce` -- returns "Enforcing", "Permissive", or "Disabled"
- `/etc/selinux/config SELINUXTYPE` -- returns policy type (targeted, mls, minimum)

**AppArmor** (Debian/Ubuntu/SUSE):
- `aa-status --enabled` -- checks if AppArmor is enabled
- `aa-status` with profile count parsing -- gets number of loaded profiles
- Falls back to `systemctl is-active apparmor` if aa-status is unavailable

### Firewall Detection

Firewalls are detected in the following order. The first active firewall found is reported in system info; firewall rules are collected separately.

1. **firewalld**: `systemctl is-active firewalld` -- RHEL 7+, CentOS 7+, Fedora, modern SUSE
2. **ufw**: `ufw status | head -1` -- Ubuntu default
3. **SuSEfirewall2**: `systemctl is-active SuSEfirewall2` -- older SUSE systems
4. **nftables**: `nft list tables | wc -l` -- modern iptables replacement (active if table count > 0)
5. **iptables**: `iptables -L -n | grep -c '^[A-Z]'` -- legacy fallback (active if rule count > 3, meaning more than default empty chains)

For firewall rule collection, the detection order differs slightly:
1. **ufw**: `ufw status verbose` -- parsed from human-readable output
2. **firewalld**: `firewall-cmd --list-all-zones` -- extracts services and ports per zone
3. **iptables**: `iptables-save` -- parsed from the machine-readable save format

### User Account Collection

User data is assembled from multiple sources:
1. `/etc/passwd` -- core account information (username, UID, GID, home, shell, GECOS)
2. `/etc/group` -- group membership mapping
3. `/etc/shadow` -- password aging, lock status (requires root/sudo)
4. `lastlog` -- last login time and source IP
5. `/etc/sudoers` and `/etc/sudoers.d/*` -- sudo rules (parsed for user and group rules)
6. `~/.ssh/authorized_keys` -- SSH key count and types per user

System accounts are identified as those with UID < 1000.

### Network Interface Collection

Two methods are attempted:
1. **JSON output** (preferred): `ip -json addr show` -- parsed directly as JSON, providing structured interface data with flags, addresses, MTU, and link type.
2. **Text output** (fallback): `ip addr show` -- parsed with regex for interface name, flags, MTU, MAC addresses, and IPv4/IPv6 addresses.

### Route Collection

Two methods are attempted:
1. **JSON output** (preferred): `ip -json route show`
2. **Text output** (fallback): `ip route show` -- parsed by extracting keyword-value pairs (via, dev, metric, scope, proto)

---

## Database Schema

All tables use UUID primary keys generated by PostgreSQL `gen_random_uuid()`. All tables have a foreign key to `hosts(id)` with `ON DELETE CASCADE`.

### host_system_info

One row per host (unique on host_id). Upserted on each collection.

| Column | Type | Nullable | Notes |
|--------|------|----------|-------|
| id | UUID | No | Primary key, auto-generated |
| host_id | UUID | No | FK to hosts(id), unique |
| os_name | VARCHAR(255) | Yes | |
| os_version | VARCHAR(50) | Yes | |
| os_version_full | VARCHAR(255) | Yes | |
| os_pretty_name | VARCHAR(255) | Yes | |
| os_id | VARCHAR(50) | Yes | |
| os_id_like | VARCHAR(100) | Yes | |
| kernel_version | VARCHAR(100) | Yes | |
| kernel_release | VARCHAR(100) | Yes | |
| kernel_name | VARCHAR(50) | Yes | |
| architecture | VARCHAR(50) | Yes | |
| cpu_model | VARCHAR(255) | Yes | |
| cpu_cores | INTEGER | Yes | |
| cpu_threads | INTEGER | Yes | |
| memory_total_mb | INTEGER | Yes | |
| memory_available_mb | INTEGER | Yes | |
| swap_total_mb | INTEGER | Yes | |
| disk_total_gb | FLOAT | Yes | |
| disk_used_gb | FLOAT | Yes | |
| disk_free_gb | FLOAT | Yes | |
| selinux_status | VARCHAR(50) | Yes | enforcing, permissive, disabled |
| selinux_mode | VARCHAR(50) | Yes | targeted, mls, minimum |
| firewall_status | VARCHAR(50) | Yes | active, inactive |
| firewall_service | VARCHAR(50) | Yes | firewalld, ufw, iptables, nftables, SuSEfirewall2 |
| hostname | VARCHAR(255) | Yes | |
| fqdn | VARCHAR(255) | Yes | |
| primary_ip | VARCHAR(45) | Yes | IPv4 or IPv6 |
| uptime_seconds | BIGINT | Yes | |
| boot_time | TIMESTAMPTZ | Yes | |
| collected_at | TIMESTAMPTZ | No | Default CURRENT_TIMESTAMP |
| updated_at | TIMESTAMPTZ | No | Default CURRENT_TIMESTAMP |

**Indexes**: ix_host_system_info_host_id (unique), ix_host_system_info_collected_at

### host_packages

One row per installed package per host. Full refresh on each collection (delete + insert). Unique constraint on (host_id, name, arch).

| Column | Type | Nullable | Notes |
|--------|------|----------|-------|
| id | UUID | No | Primary key, auto-generated |
| host_id | UUID | No | FK to hosts(id) |
| name | VARCHAR(255) | No | Package name |
| version | VARCHAR(100) | Yes | |
| release | VARCHAR(100) | Yes | |
| arch | VARCHAR(50) | Yes | x86_64, noarch, amd64, etc. |
| source_repo | VARCHAR(255) | Yes | Source repository (zypper only) |
| installed_at | TIMESTAMPTZ | Yes | Install timestamp (RPM only) |
| collected_at | TIMESTAMPTZ | No | Default CURRENT_TIMESTAMP |

**Indexes**: ix_host_packages_host_id, ix_host_packages_name, ix_host_packages_collected_at
**Unique Constraint**: uq_host_packages_host_name_arch (host_id, name, arch)

### host_services

One row per service per host. Full refresh on each collection. Unique constraint on (host_id, name).

| Column | Type | Nullable | Notes |
|--------|------|----------|-------|
| id | UUID | No | Primary key, auto-generated |
| host_id | UUID | No | FK to hosts(id) |
| name | VARCHAR(255) | No | Service name (without .service) |
| display_name | VARCHAR(255) | Yes | Service description |
| status | VARCHAR(50) | Yes | running, stopped, failed, exited, dead |
| enabled | BOOLEAN | Yes | |
| service_type | VARCHAR(50) | Yes | simple, forking, oneshot |
| run_as_user | VARCHAR(100) | Yes | |
| listening_ports | JSONB | Yes | Array of port objects |
| collected_at | TIMESTAMPTZ | No | Default CURRENT_TIMESTAMP |

**Indexes**: ix_host_services_host_id, ix_host_services_name, ix_host_services_status, ix_host_services_collected_at, ix_host_services_listening_ports (GIN)
**Unique Constraint**: uq_host_services_host_name (host_id, name)

### host_users

One row per user account per host. Full refresh on each collection. Unique constraint on (host_id, username).

| Column | Type | Nullable | Notes |
|--------|------|----------|-------|
| id | UUID | No | Primary key, auto-generated |
| host_id | UUID | No | FK to hosts(id) |
| username | VARCHAR(100) | No | |
| uid | INTEGER | Yes | |
| gid | INTEGER | Yes | |
| groups | JSONB | Yes | Array of group names |
| home_dir | VARCHAR(255) | Yes | |
| shell | VARCHAR(255) | Yes | |
| gecos | VARCHAR(255) | Yes | Full name / comment |
| is_system_account | BOOLEAN | Yes | True if UID < 1000 |
| is_locked | BOOLEAN | Yes | |
| has_password | BOOLEAN | Yes | |
| password_last_changed | TIMESTAMPTZ | Yes | |
| password_expires | TIMESTAMPTZ | Yes | |
| password_max_days | INTEGER | Yes | |
| password_warn_days | INTEGER | Yes | |
| last_login | TIMESTAMPTZ | Yes | |
| last_login_ip | VARCHAR(45) | Yes | |
| ssh_keys_count | INTEGER | Yes | |
| ssh_key_types | JSONB | Yes | Array of key type strings |
| sudo_rules | JSONB | Yes | Array of sudo rule strings |
| has_sudo_all | BOOLEAN | Yes | |
| has_sudo_nopasswd | BOOLEAN | Yes | |
| collected_at | TIMESTAMPTZ | No | Default CURRENT_TIMESTAMP |

**Indexes**: ix_host_users_host_id, ix_host_users_username, ix_host_users_is_system_account, ix_host_users_has_sudo_all, ix_host_users_collected_at, ix_host_users_groups (GIN)
**Unique Constraint**: uq_host_users_host_username (host_id, username)

### host_network

One row per network interface per host. Full refresh on each collection. Unique constraint on (host_id, interface_name).

| Column | Type | Nullable | Notes |
|--------|------|----------|-------|
| id | UUID | No | Primary key, auto-generated |
| host_id | UUID | No | FK to hosts(id) |
| interface_name | VARCHAR(50) | No | |
| mac_address | VARCHAR(17) | Yes | |
| ip_addresses | JSONB | Yes | Array of address objects |
| is_up | BOOLEAN | Yes | |
| mtu | INTEGER | Yes | |
| speed_mbps | INTEGER | Yes | |
| interface_type | VARCHAR(50) | Yes | ethernet, loopback, bridge, vlan, bond, veth |
| collected_at | TIMESTAMPTZ | Yes | Default CURRENT_TIMESTAMP |

**Indexes**: idx_host_network_host, idx_host_network_ip_addresses (GIN)
**Unique Constraint**: uq_host_network_interface (host_id, interface_name)

### host_firewall_rules

One row per firewall rule per host. Full refresh on each collection (no unique constraint, replaced entirely).

| Column | Type | Nullable | Notes |
|--------|------|----------|-------|
| id | UUID | No | Primary key, auto-generated |
| host_id | UUID | No | FK to hosts(id) |
| firewall_type | VARCHAR(50) | Yes | iptables, nftables, firewalld, ufw |
| chain | VARCHAR(50) | Yes | INPUT, OUTPUT, FORWARD |
| rule_number | INTEGER | Yes | Position in chain |
| protocol | VARCHAR(20) | Yes | tcp, udp, icmp, all |
| source | VARCHAR(100) | Yes | |
| destination | VARCHAR(100) | Yes | |
| port | VARCHAR(50) | Yes | Single port or range (8000:8080) |
| action | VARCHAR(20) | Yes | ACCEPT, DROP, REJECT, ALLOW, DENY, LIMIT |
| interface_in | VARCHAR(50) | Yes | |
| interface_out | VARCHAR(50) | Yes | |
| state | VARCHAR(100) | Yes | NEW, ESTABLISHED, RELATED |
| comment | TEXT | Yes | |
| raw_rule | TEXT | Yes | Original rule text |
| collected_at | TIMESTAMPTZ | Yes | Default CURRENT_TIMESTAMP |

**Indexes**: idx_host_firewall_host, idx_host_firewall_chain, idx_host_firewall_action

### host_routes

One row per route per host. Full refresh on each collection.

| Column | Type | Nullable | Notes |
|--------|------|----------|-------|
| id | UUID | No | Primary key, auto-generated |
| host_id | UUID | No | FK to hosts(id) |
| destination | VARCHAR(100) | No | Network CIDR or "default" |
| gateway | VARCHAR(45) | Yes | Next-hop IP |
| interface | VARCHAR(50) | Yes | Output interface |
| metric | INTEGER | Yes | |
| scope | VARCHAR(20) | Yes | link, host, global |
| route_type | VARCHAR(20) | Yes | unicast, local, broadcast |
| protocol | VARCHAR(20) | Yes | kernel, static, dhcp |
| is_default | BOOLEAN | Yes | Default false |
| collected_at | TIMESTAMPTZ | Yes | Default CURRENT_TIMESTAMP |

**Indexes**: idx_host_routes_host, idx_host_routes_default (host_id, is_default)

### host_audit_events

Append-only table for security audit events. New events are inserted with deduplication (WHERE NOT EXISTS check on host_id + event_timestamp + event_type + raw_message).

| Column | Type | Nullable | Notes |
|--------|------|----------|-------|
| id | UUID | No | Primary key, auto-generated |
| host_id | UUID | No | FK to hosts(id) |
| event_type | VARCHAR(50) | No | auth, sudo, login_failure |
| event_timestamp | TIMESTAMPTZ | No | When the event occurred |
| username | VARCHAR(100) | Yes | |
| source_ip | VARCHAR(45) | Yes | |
| action | VARCHAR(100) | Yes | ssh_login, command, failed_login |
| target | VARCHAR(255) | Yes | Command or target of action |
| result | VARCHAR(20) | Yes | success, failure |
| raw_message | TEXT | Yes | Truncated to 500 chars |
| source_process | VARCHAR(100) | Yes | sshd, sudo, su, login |
| metadata | JSONB | Yes | Additional structured data |
| collected_at | TIMESTAMPTZ | Yes | Default CURRENT_TIMESTAMP |

**Indexes**: idx_host_audit_events_host, idx_host_audit_events_type, idx_host_audit_events_timestamp (DESC), idx_host_audit_events_result, idx_host_audit_events_host_type_time (compound)

### host_metrics

Time-series table for resource metrics. Each collection inserts a new row (not upserted).

| Column | Type | Nullable | Notes |
|--------|------|----------|-------|
| id | UUID | No | Primary key, auto-generated |
| host_id | UUID | No | FK to hosts(id) |
| collected_at | TIMESTAMPTZ | No | Default CURRENT_TIMESTAMP |
| cpu_usage_percent | FLOAT | Yes | |
| load_avg_1m | FLOAT | Yes | |
| load_avg_5m | FLOAT | Yes | |
| load_avg_15m | FLOAT | Yes | |
| memory_total_bytes | BIGINT | Yes | |
| memory_used_bytes | BIGINT | Yes | |
| memory_available_bytes | BIGINT | Yes | |
| swap_total_bytes | BIGINT | Yes | |
| swap_used_bytes | BIGINT | Yes | |
| disk_total_bytes | BIGINT | Yes | |
| disk_used_bytes | BIGINT | Yes | |
| disk_available_bytes | BIGINT | Yes | |
| uptime_seconds | BIGINT | Yes | |
| process_count | INTEGER | Yes | |

**Indexes**: idx_host_metrics_host, idx_host_metrics_time (DESC), idx_host_metrics_host_time (compound)

### Migration History

| Migration | Revision | Tables Created |
|-----------|----------|----------------|
| 20260210_0100_027 | 027_host_system_info | host_system_info |
| 20260210_0200_028 | 028_host_packages_services | host_packages, host_services |
| 20260210_0300_029 | 029_host_users | host_users |
| 20260210_0400_030 | 030_host_network | host_network, host_firewall_rules, host_routes |
| 20260210_0500_031 | 031_host_audit_events | host_audit_events |
| 20260210_0600_032 | 032_host_metrics | host_metrics |

---

## API Endpoints

All endpoints are under `/api/hosts/{host_id}/` and require the `HOST_READ` permission. The router is registered in `backend/app/routes/hosts/intelligence.py`.

### System Information

| Method | Path | Description |
|--------|------|-------------|
| GET | `/{host_id}/system-info` | Get system information for a host |

Returns a `SystemInfoResponse` with all fields from the `host_system_info` table. Returns 404 if no system information has been collected for the host.

### Packages

| Method | Path | Description |
|--------|------|-------------|
| GET | `/{host_id}/packages` | List installed packages (paginated) |

**Query Parameters**:
- `search` (string) -- Filter by package name (ILIKE match)
- `limit` (int, 1-1000, default 100) -- Maximum items
- `offset` (int, default 0) -- Pagination offset

Returns `PackagesListResponse` with items, total, limit, and offset fields. Results are ordered by name ascending.

### Services

| Method | Path | Description |
|--------|------|-------------|
| GET | `/{host_id}/services` | List system services (paginated) |

**Query Parameters**:
- `search` (string) -- Filter by service name or display name (ILIKE match)
- `status` (string) -- Filter by status (running, stopped, failed)
- `limit` (int, 1-1000, default 100) -- Maximum items
- `offset` (int, default 0) -- Pagination offset

Returns `ServicesListResponse`. Results are ordered by name ascending.

### Users

| Method | Path | Description |
|--------|------|-------------|
| GET | `/{host_id}/users` | List user accounts (paginated) |

**Query Parameters**:
- `search` (string) -- Filter by username or full name (ILIKE match)
- `include_system` (bool, default false) -- Include system accounts (UID < 1000)
- `has_sudo` (bool) -- Filter by sudo access
- `limit` (int, 1-1000, default 100) -- Maximum items
- `offset` (int, default 0) -- Pagination offset

Returns `UsersListResponse`. Results are ordered by UID ascending (nulls last), then username ascending.

### Network Interfaces

| Method | Path | Description |
|--------|------|-------------|
| GET | `/{host_id}/network` | List network interfaces (paginated) |

**Query Parameters**:
- `interface_type` (string) -- Filter by type (ethernet, loopback, bridge, etc.)
- `is_up` (bool) -- Filter by up/down status
- `limit` (int, 1-1000, default 100) -- Maximum items
- `offset` (int, default 0) -- Pagination offset

Returns `NetworkListResponse`. Results are ordered by interface name ascending.

### Firewall Rules

| Method | Path | Description |
|--------|------|-------------|
| GET | `/{host_id}/firewall` | List firewall rules (paginated) |

**Query Parameters**:
- `chain` (string) -- Filter by chain (INPUT, OUTPUT, FORWARD)
- `action` (string) -- Filter by action (ACCEPT, DROP, REJECT)
- `firewall_type` (string) -- Filter by firewall type (iptables, firewalld, ufw)
- `limit` (int, 1-1000, default 100) -- Maximum items
- `offset` (int, default 0) -- Pagination offset

Returns `FirewallListResponse`. Results are ordered by chain ascending, then rule number ascending.

### Routes

| Method | Path | Description |
|--------|------|-------------|
| GET | `/{host_id}/routes` | List network routes (paginated) |

**Query Parameters**:
- `is_default` (bool) -- Filter for default routes only
- `limit` (int, 1-1000, default 100) -- Maximum items
- `offset` (int, default 0) -- Pagination offset

Returns `RoutesListResponse`. Results are ordered by is_default descending, then destination ascending.

### Audit Events

| Method | Path | Description |
|--------|------|-------------|
| GET | `/{host_id}/audit-events` | List security audit events (paginated) |

**Query Parameters**:
- `event_type` (string) -- Filter by type (auth, sudo, login_failure)
- `result` (string) -- Filter by result (success, failure)
- `username` (string) -- Filter by username (ILIKE match)
- `limit` (int, 1-1000, default 100) -- Maximum items
- `offset` (int, default 0) -- Pagination offset

Returns `AuditEventsListResponse`. Results are ordered by event_timestamp descending.

### Metrics

| Method | Path | Description |
|--------|------|-------------|
| GET | `/{host_id}/metrics` | List resource metrics (paginated, time-filtered) |
| GET | `/{host_id}/metrics/latest` | Get most recent metrics snapshot |

**Query Parameters** (list endpoint):
- `hours_back` (int, 1-720, default 24) -- How many hours of metrics to return
- `limit` (int, 1-1000, default 100) -- Maximum items
- `offset` (int, default 0) -- Pagination offset

Returns `MetricsListResponse`. Results are ordered by collected_at descending.

The `/metrics/latest` endpoint returns a single `MetricsResponse` or 404 if no metrics have been collected.

### Intelligence Summary

| Method | Path | Description |
|--------|------|-------------|
| GET | `/{host_id}/intelligence/summary` | Get server intelligence summary |

Returns a `ServerIntelligenceSummary` with aggregate counts:

| Field | Description |
|-------|-------------|
| host_id | Host UUID |
| system_info_collected | Whether system info has been collected |
| packages_count | Total installed packages |
| services_count | Total services |
| running_services_count | Services with status "running" |
| listening_ports_count | Services with non-empty listening_ports |
| users_count | Non-system user accounts |
| sudo_users_count | Users with has_sudo_all = true |
| network_interfaces_count | Network interfaces |
| firewall_rules_count | Firewall rules |
| routes_count | Network routes |
| audit_events_count | Audit events |
| last_collected_at | Most recent collection timestamp |

---

## Integration with Kensa Compliance Scans

Server intelligence collection is triggered automatically during Kensa compliance scans via the compliance scheduler task.

### Collection Flow

1. The compliance scheduler task (`compliance_scheduler_tasks.py`) runs a scan against a host.
2. The scanner's `scan()` method is called with all collection flags set to `True`:

```python
scan_result = await scanner.scan(
    host_id=host_id,
    db=db,
    collect_system_info=True,
    collect_packages=True,
    collect_services=True,
    collect_users=True,
    collect_network=True,
    collect_firewall=True,
    collect_routes=True,
    collect_audit_events=True,
    collect_metrics=True,
)
```

3. The scan result dictionary contains keys for each data category: `system_info`, `packages`, `services`, `users`, `network`, `firewall`, `routes`, `audit_events`, `metrics`.

4. After compliance findings are saved, the task creates a `SystemInfoService` instance and calls the appropriate save methods:

```python
from app.services.system_info import SystemInfoService

service = SystemInfoService(db)

if system_info:
    service.save_system_info(host_id, system_info)

if packages:
    service.save_packages(host_id, packages)

if services:
    service.save_services(host_id, services)

# ... and so on for each category
```

5. OS information from system_info is also synced back to the `hosts` table's `operating_system` and `os_version` columns for display consistency.

6. Server intelligence collection errors are caught and logged as warnings. A failure to save intelligence data does not cause the scan itself to fail.

### Data Freshness

The `collected_at` timestamp on each table records when the data was last collected. For most categories (packages, services, users, network, firewall, routes), each collection performs a full refresh -- all existing rows for the host are deleted and replaced with current data. This means the data always reflects the state at the most recent scan.

Exceptions to the full-refresh pattern:
- **host_system_info**: Upserted (one row per host, updated in place).
- **host_audit_events**: Appended with deduplication (events accumulate over time).
- **host_metrics**: Appended (time-series, new row per collection).

---

## OS Support

### Supported Linux Distributions

| Family | Distributions | Package Manager | Security Framework | Default Firewall |
|--------|--------------|-----------------|-------------------|-----------------|
| RHEL | RHEL, CentOS, Fedora, Rocky Linux, AlmaLinux, Oracle Linux | rpm | SELinux | firewalld |
| Debian | Debian, Ubuntu | dpkg | AppArmor | ufw (Ubuntu), iptables (Debian) |
| SUSE | SLES, openSUSE | zypper (preferred), rpm (fallback) | AppArmor | firewalld (modern), SuSEfirewall2 (legacy) |

### Distribution Detection

Distribution detection is performed by parsing `/etc/os-release`, which is present on all modern Linux distributions. The `ID` field (e.g., "rhel", "ubuntu", "sles") identifies the specific distribution, while `ID_LIKE` (e.g., "fedora", "debian") identifies the distribution family.

The collector does not use `ID` or `ID_LIKE` to select collection methods. Instead, it tries each tool in order and uses whichever one succeeds. This means that derivative distributions or custom builds that provide standard Linux tools will work without explicit support.

### Minimum Requirements

- SSH access with a user that has sudo privileges (required for /etc/shadow, firewall rules, some audit data)
- systemd (required for service collection)
- Standard Linux utilities: uname, hostname, ip, df, cat, grep, awk, wc
- For audit events: journalctl or /var/log/secure, lastb

---

## Key Files

| File | Description |
|------|-------------|
| `backend/app/services/system_info/__init__.py` | Package public API (exports all dataclasses and classes) |
| `backend/app/services/system_info/collector.py` | SystemInfoCollector (SSH collection) and SystemInfoService (database persistence) |
| `backend/app/routes/hosts/intelligence.py` | API endpoints and Pydantic response models |
| `backend/app/routes/hosts/__init__.py` | Router registration (intelligence_router included in hosts router) |
| `backend/app/tasks/compliance_scheduler_tasks.py` | Integration point (calls collector during scans) |
| `backend/alembic/versions/20260210_0100_027_add_host_system_info_table.py` | Migration: host_system_info |
| `backend/alembic/versions/20260210_0200_028_add_host_packages_services_tables.py` | Migration: host_packages, host_services |
| `backend/alembic/versions/20260210_0300_029_add_host_users_table.py` | Migration: host_users |
| `backend/alembic/versions/20260210_0400_030_add_host_network_tables.py` | Migration: host_network, host_firewall_rules, host_routes |
| `backend/alembic/versions/20260210_0500_031_add_host_audit_events_table.py` | Migration: host_audit_events |
| `backend/alembic/versions/20260210_0600_032_add_host_metrics_table.py` | Migration: host_metrics |
