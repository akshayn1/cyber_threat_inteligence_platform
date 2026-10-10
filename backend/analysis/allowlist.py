"""Allowlist and False-Positive Protection Engine.

Safeguards against blocking legitimate infrastructure, shared CDNs, DNS resolvers,
and internal corporate ranges which would otherwise cause service outages.
"""
import ipaddress
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

DEFAULT_ALLOWLIST = [
    {
        "id": "al-cf-dns-1",
        "indicator": "1.1.1.1",
        "indicator_type": "ip",
        "reason": "Cloudflare Anycast Public Resolver (1.1.1.1)",
        "added_at": "2026-01-01T00:00:00Z",
    },
    {
        "id": "al-cf-dns-2",
        "indicator": "1.0.0.1",
        "indicator_type": "ip",
        "reason": "Cloudflare Anycast Public Resolver (1.0.0.1)",
        "added_at": "2026-01-01T00:00:00Z",
    },
    {
        "id": "al-goog-dns-1",
        "indicator": "8.8.8.8",
        "indicator_type": "ip",
        "reason": "Google Public DNS Anycast (8.8.8.8)",
        "added_at": "2026-01-01T00:00:00Z",
    },
    {
        "id": "al-goog-dns-2",
        "indicator": "8.8.4.4",
        "indicator_type": "ip",
        "reason": "Google Public DNS Anycast (8.8.4.4)",
        "added_at": "2026-01-01T00:00:00Z",
    },
    {
        "id": "al-rfc1918-10",
        "indicator": "10.0.0.0/8",
        "indicator_type": "cidr",
        "reason": "RFC 1918 Private Corporate Subnet (10.0.0.0/8)",
        "added_at": "2026-01-01T00:00:00Z",
    },
    {
        "id": "al-rfc1918-192",
        "indicator": "192.168.0.0/16",
        "indicator_type": "cidr",
        "reason": "RFC 1918 Private Corporate Subnet (192.168.0.0/16)",
        "added_at": "2026-01-01T00:00:00Z",
    },
    {
        "id": "al-cdn-cf",
        "indicator": "cloudflare.com",
        "indicator_type": "domain",
        "reason": "Cloudflare Global Content Delivery Network",
        "added_at": "2026-01-01T00:00:00Z",
    },
    {
        "id": "al-cdn-akamai",
        "indicator": "akamaiedge.net",
        "indicator_type": "domain",
        "reason": "Akamai Edge Shared CDN Infrastructure",
        "added_at": "2026-01-01T00:00:00Z",
    },
    {
        "id": "al-cdn-fastly",
        "indicator": "fastly.net",
        "indicator_type": "domain",
        "reason": "Fastly CDN Shared Edge Nodes",
        "added_at": "2026-01-01T00:00:00Z",
    },
]


def is_in_cidr(ip_str: str, cidr_str: str) -> bool:
    """Checks whether an IPv4 string belongs to a CIDR range."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        net = ipaddress.ip_network(cidr_str.strip(), strict=False)
        return ip in net
    except Exception:
        return False


def check_allowlist(indicator: str, allowlist_items: List[dict]) -> Tuple[bool, Optional[dict]]:
    """Checks if an indicator is protected under the allowlist.
    Returns (is_protected, matching_rule).
    """
    cleaned = indicator.strip().lower()

    # Strip port if present
    if ":" in cleaned and not cleaned.startswith("http"):
        parts = cleaned.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            cleaned = parts[0]

    for item in allowlist_items:
        rule_val = str(item.get("indicator", "")).strip().lower()
        if not rule_val:
            continue

        # Exact match
        if cleaned == rule_val:
            return True, item

        # CIDR subnet match for IPs
        if "/" in rule_val:
            if is_in_cidr(cleaned, rule_val):
                return True, item

        # Domain / Subdomain match
        if item.get("indicator_type") == "domain" or ("." in rule_val and "/" not in rule_val):
            if cleaned.endswith("." + rule_val) or cleaned == rule_val:
                return True, item

    return False, None


def compute_source_trust(source: str, source_penalties: Dict[str, int]) -> int:
    """Computes effective trust score for an intelligence source (0-100).
    Base trust is 100. Each false positive report applies a penalty.
    """
    base = 100
    penalty = source_penalties.get(source, 0)
    return max(10, min(100, base - penalty))
