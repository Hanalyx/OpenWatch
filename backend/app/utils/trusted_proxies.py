"""
Trusted Proxy Validation for X-Forwarded-For Header

Only trust X-Forwarded-For when the direct client IP is a known proxy.
This prevents IP spoofing by untrusted clients sending forged headers.

Configuration:
    Set OPENWATCH_TRUSTED_PROXIES env var with comma-separated IPs/CIDRs.
    Defaults include loopback and common Docker/private network ranges.
"""

import ipaddress
import os
from functools import lru_cache
from typing import List, Union

from fastapi import Request


@lru_cache(maxsize=1)
def get_trusted_proxy_networks() -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    """
    Load trusted proxy networks from environment or use defaults.

    Defaults cover loopback and Docker/private network ranges.
    """
    env_value = os.getenv("OPENWATCH_TRUSTED_PROXIES", "")
    if env_value.strip():
        raw_entries = [entry.strip() for entry in env_value.split(",") if entry.strip()]
    else:
        raw_entries = [
            "127.0.0.1",
            "::1",
            "172.16.0.0/12",
            "10.0.0.0/8",
        ]

    networks = []
    for entry in raw_entries:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            # Skip malformed entries
            pass
    return networks


def is_trusted_proxy(client_ip: str) -> bool:
    """
    Check if a client IP belongs to a trusted proxy network.

    Args:
        client_ip: The direct connection IP (request.client.host).

    Returns:
        True if the IP is within a trusted proxy network.
    """
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False

    for network in get_trusted_proxy_networks():
        if addr in network:
            return True
    return False


def get_client_ip(request: Request) -> str:
    """
    Extract the real client IP, only trusting X-Forwarded-For from known proxies.

    If the direct client is a trusted proxy, use the first IP from
    X-Forwarded-For. Otherwise, use the direct client IP.

    Args:
        request: The incoming FastAPI/Starlette request.

    Returns:
        The client IP address string.
    """
    direct_ip = request.client.host if request.client else "unknown"

    if direct_ip != "unknown" and is_trusted_proxy(direct_ip):
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip

    return direct_ip
