"""Target host resolution from --host, Ansible inventory, or plain text lists."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class HostInfo:
    """Resolved target host with connection parameters."""

    hostname: str
    port: int = 22
    user: str | None = None
    key_path: str | None = None
    groups: list[str] = field(default_factory=list)


def resolve_targets(
    *,
    host: str | None = None,
    inventory: str | None = None,
    limit: str | None = None,
    default_user: str | None = None,
    default_key: str | None = None,
    default_port: int = 22,
) -> list[HostInfo]:
    """Resolve target hosts from all sources and apply defaults.

    CLI flags (default_user, default_key, default_port) act as fallbacks.
    Inventory-level per-host vars override them (Ansible precedence).
    """
    hosts: list[HostInfo] = []

    if host:
        hosts.extend(_parse_host_flag(host))
    if inventory:
        hosts.extend(_parse_inventory(inventory))

    if not hosts:
        raise ValueError("No target hosts specified — use --host or --inventory")

    # Apply CLI defaults where inventory didn't set per-host values
    for h in hosts:
        if h.user is None:
            h.user = default_user
        if h.key_path is None:
            h.key_path = default_key
        if h.port == 22 and default_port != 22:
            h.port = default_port

    # Apply --limit filter
    if limit:
        hosts = _apply_limit(hosts, limit)
        if not hosts:
            raise ValueError(f"--limit '{limit}' matched no hosts")

    return hosts


def _parse_host_flag(host_str: str) -> list[HostInfo]:
    """Parse comma-separated host string."""
    hosts = []
    for part in host_str.split(","):
        part = part.strip()
        if not part:
            continue
        hostname, port = _split_host_port(part)
        hosts.append(HostInfo(hostname=hostname, port=port))
    return hosts


def _split_host_port(s: str) -> tuple[str, int]:
    """Extract hostname and port from 'host:port' or plain 'host'."""
    if ":" in s and not s.startswith("["):
        host, port_s = s.rsplit(":", 1)
        try:
            return host, int(port_s)
        except ValueError:
            return s, 22
    return s, 22


def _parse_inventory(path_str: str) -> list[HostInfo]:
    """Auto-detect inventory format and parse."""
    p = Path(path_str)
    if not p.exists():
        raise FileNotFoundError(f"Inventory file not found: {path_str}")

    text = p.read_text()

    if p.suffix in (".yml", ".yaml"):
        return _parse_yaml_inventory(text)

    # Detect INI by presence of [group] headers
    if re.search(r"^\[.+\]", text, re.MULTILINE):
        return _parse_ini_inventory(text)

    # Fall back to plain text host list
    return _parse_plain_hostlist(text)


def _parse_ini_inventory(text: str) -> list[HostInfo]:
    """Parse Ansible INI-format inventory."""
    hosts: dict[str, HostInfo] = {}
    current_group = "ungrouped"
    in_vars = False

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        # Group header
        m = re.match(r"^\[(.+)\]$", line)
        if m:
            header = m.group(1)
            if header.endswith(":vars"):
                in_vars = True
                current_group = header[: -len(":vars")]
            elif header.endswith(":children"):
                in_vars = False
                current_group = header[: -len(":children")]
            else:
                in_vars = False
                current_group = header
            continue

        if in_vars:
            # Group-level vars — skip for V0 (per-host vars suffice)
            continue

        # Host line: hostname key=value key=value ...
        parts = line.split()
        raw_host = parts[0]
        host_vars = _parse_inline_vars(parts[1:])

        hostname = host_vars.pop("ansible_host", raw_host)
        port = int(host_vars.pop("ansible_port", 22))
        user = host_vars.pop("ansible_user", None)
        key = host_vars.pop("ansible_ssh_private_key_file", None)

        if hostname in hosts:
            # Host already seen — add group
            if current_group not in hosts[hostname].groups:
                hosts[hostname].groups.append(current_group)
        else:
            hosts[hostname] = HostInfo(
                hostname=hostname,
                port=port,
                user=user,
                key_path=key,
                groups=[current_group],
            )

    return list(hosts.values())


def _parse_inline_vars(parts: list[str]) -> dict[str, str]:
    """Parse key=value pairs from an INI host line."""
    result = {}
    for p in parts:
        if "=" in p:
            k, v = p.split("=", 1)
            result[k] = v
    return result


def _parse_yaml_inventory(text: str) -> list[HostInfo]:
    """Parse Ansible YAML-format inventory."""
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("YAML inventory must be a mapping")

    hosts: dict[str, HostInfo] = {}
    _walk_yaml_group(data, "all", hosts)
    return list(hosts.values())


def _walk_yaml_group(data: dict, group_name: str, hosts: dict[str, HostInfo]) -> None:
    """Recursively walk YAML inventory groups."""
    if not isinstance(data, dict):
        return

    # Top-level may be wrapped in 'all' or be direct
    node = data.get(group_name, data) if group_name == "all" else data

    # Process hosts at this level
    group_hosts = node.get("hosts", {})
    if isinstance(group_hosts, dict):
        for hostname, vars_data in group_hosts.items():
            hvars = vars_data if isinstance(vars_data, dict) else {}
            actual_host = hvars.get("ansible_host", hostname)
            port = int(hvars.get("ansible_port", 22))
            user = hvars.get("ansible_user")
            key = hvars.get("ansible_ssh_private_key_file")

            if actual_host in hosts:
                if group_name not in hosts[actual_host].groups:
                    hosts[actual_host].groups.append(group_name)
            else:
                hosts[actual_host] = HostInfo(
                    hostname=actual_host,
                    port=port,
                    user=user,
                    key_path=key,
                    groups=[group_name],
                )

    # Recurse into children
    children = node.get("children", {})
    if isinstance(children, dict):
        for child_name, child_data in children.items():
            if isinstance(child_data, dict):
                _walk_yaml_group(child_data, child_name, hosts)


def _parse_plain_hostlist(text: str) -> list[HostInfo]:
    """Parse a plain text file with one host per line."""
    hosts = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        hostname, port = _split_host_port(line)
        hosts.append(HostInfo(hostname=hostname, port=port))
    return hosts


def _apply_limit(hosts: list[HostInfo], limit: str) -> list[HostInfo]:
    """Filter hosts by group name or hostname glob pattern."""
    result = []
    for h in hosts:
        # Match by group membership
        if limit in h.groups:
            result.append(h)
            continue
        # Match by hostname glob
        if fnmatch.fnmatch(h.hostname, limit):
            result.append(h)
    return result
