"""Live Log Matching Engine.

Parses Suricata eve.json, Zeek (TSV/JSON), Wazuh alerts, and generic Firewall syslog.
Matches network traffic and endpoint events continuously against known threat indicators
while enforcing allowlist protection to prevent false positive alerts.
"""
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from analysis.allowlist import check_allowlist

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
HASH_REGEX = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


def _clean_ip(ip_str: str) -> Optional[str]:
    parts = ip_str.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return ip_str
    return None


def parse_suricata_line(data: dict) -> dict:
    """Extract telemetry from a Suricata EVE JSON event."""
    src_ip = data.get("src_ip")
    dest_ip = data.get("dest_ip")
    proto = data.get("proto", "TCP")
    timestamp = data.get("timestamp") or datetime.now(timezone.utc).isoformat()
    alert_info = data.get("alert", {})
    http_info = data.get("http", {})
    dns_info = data.get("dns", {})
    tls_info = data.get("tls", {})

    indicators = []
    if src_ip: indicators.append(src_ip)
    if dest_ip: indicators.append(dest_ip)
    if http_info.get("hostname"): indicators.append(http_info["hostname"])
    if dns_info.get("rrname"): indicators.append(dns_info["rrname"])
    if tls_info.get("sni"): indicators.append(tls_info["sni"])

    signature = alert_info.get("signature") or http_info.get("url") or f"Suricata {data.get('event_type', 'flow')} traffic"

    return {
        "format": "suricata",
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "proto": proto,
        "signature": signature,
        "indicators": list(dict.fromkeys(indicators)),
        "raw": data,
    }


def parse_wazuh_line(data: dict) -> dict:
    """Extract telemetry from a Wazuh alert JSON event."""
    data_block = data.get("data", {})
    rule_block = data.get("rule", {})
    src_ip = data_block.get("srcip") or data.get("srcip")
    dest_ip = data_block.get("dstip") or data.get("dstip")
    timestamp = data.get("timestamp") or datetime.now(timezone.utc).isoformat()
    sig = rule_block.get("description") or "Wazuh security detection alert"

    indicators = []
    if src_ip: indicators.append(src_ip)
    if dest_ip: indicators.append(dest_ip)
    if data_block.get("domain"): indicators.append(data_block["domain"])

    return {
        "format": "wazuh",
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "proto": data_block.get("proto", "IP"),
        "signature": sig,
        "indicators": list(dict.fromkeys(indicators)),
        "raw": data,
    }


def parse_generic_line(line: str) -> dict:
    """Fallback parser for syslog, Zeek TSV, or raw log text."""
    ips = [_clean_ip(ip) for ip in IP_REGEX.findall(line) if _clean_ip(ip)]
    domains = [d for d in DOMAIN_REGEX.findall(line) if not d.endswith(".local") and not d.endswith(".arpa")]
    hashes = HASH_REGEX.findall(line)

    src_ip = ips[0] if len(ips) > 0 else None
    dest_ip = ips[1] if len(ips) > 1 else None

    all_ind = list(dict.fromkeys([*ips, *domains, *hashes]))
    return {
        "format": "syslog",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "proto": "IP",
        "signature": line[:180],
        "indicators": all_ind,
        "raw": {"line": line},
    }


def match_log_entry(
    entry: dict,
    threats_by_indicator: Dict[str, dict],
    allowlist: List[dict]
) -> List[dict]:
    """Matches a parsed log entry against known platform indicators."""
    matches = []
    for ind in entry["indicators"]:
        ind_clean = ind.strip().lower()

        # Check allowlist
        is_protected, allow_rule = check_allowlist(ind, allowlist)
        if is_protected:
            # Indicator is explicitly allowlisted -> suppress alert to prevent outage
            continue

        threat = threats_by_indicator.get(ind_clean)
        if threat:
            # Hit! Raise alert
            analysis = threat.get("analysis", {})
            match_id = "log-alert-" + uuid.uuid4().hex[:10]
            matches.append({
                "id": match_id,
                "timestamp": entry["timestamp"],
                "format": entry["format"],
                "matched_indicator": threat["indicator"],
                "indicator_type": threat.get("indicator_type", "ip"),
                "threat_id": threat["id"],
                "malware": threat.get("malware"),
                "campaign": threat.get("campaign"),
                "severity": threat.get("severity", "high"),
                "risk_score": analysis.get("risk_score", 75),
                "src_ip": entry["src_ip"] or "Unknown",
                "dest_ip": entry["dest_ip"] or threat["indicator"],
                "proto": entry["proto"],
                "signature": entry["signature"],
                "cves": threat.get("cves", []),
                "action": "FIREWALL_ALERT",
            })
    return matches


def process_logs_batch(
    content: str,
    threats: List[dict],
    allowlist: List[dict]
) -> Dict[str, any]:
    """Process multiple log lines from an uploaded file or stream text."""
    threat_map = {t["indicator"].strip().lower(): t for t in threats}
    lines = [line.strip() for line in content.strip().splitlines() if line.strip()]

    total_lines = len(lines)
    all_matches = []
    parsed_count = 0

    for line in lines:
        parsed_count += 1
        entry = None
        # Try JSON first (Suricata EVE or Wazuh)
        if line.startswith("{") and line.endswith("}"):
            try:
                js = json.loads(line)
                if "alert" in js or "event_type" in js:
                    entry = parse_suricata_line(js)
                elif "rule" in js or "agent" in js:
                    entry = parse_wazuh_line(js)
                else:
                    entry = parse_suricata_line(js)
            except Exception:
                entry = parse_generic_line(line)
        else:
            entry = parse_generic_line(line)

        hits = match_log_entry(entry, threat_map, allowlist)
        all_matches.extend(hits)

    return {
        "lines_processed": parsed_count,
        "threat_hits": len(all_matches),
        "matches": all_matches,
    }


def generate_sample_log_stream(threats: List[dict]) -> str:
    """Generates realistic sample Suricata, Zeek, and Wazuh log lines combining
    known malicious C2 indicators from the database with benign background traffic.
    """
    sample_malicious_ips = [t["indicator"] for t in threats if t.get("indicator_type") == "ip"][:3]
    m_ip1 = sample_malicious_ips[0] if len(sample_malicious_ips) > 0 else "203.0.113.46"
    m_ip2 = sample_malicious_ips[1] if len(sample_malicious_ips) > 1 else "198.51.100.23"

    sample_lines = [
        # Benign internal
        json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "flow",
            "src_ip": "10.0.4.15",
            "dest_ip": "1.1.1.1",
            "proto": "UDP",
            "dns": {"rrname": "internal-portal.corp.local"},
        }),
        # Suricata hit on known C2 IP
        json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "alert",
            "src_ip": "10.0.12.88",
            "dest_ip": m_ip1,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2024001,
                "rev": 1,
                "signature": "ET TROJAN Observed Suspicious Beaconing to Hostile C2 IP",
                "category": "A Network Trojan was detected",
                "severity": 1,
            },
            "http": {"hostname": m_ip1, "url": "/api/v2/beacon"},
        }),
        # Benign CDN
        json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "http",
            "src_ip": "10.0.15.22",
            "dest_ip": "104.16.132.229",
            "proto": "TCP",
            "http": {"hostname": "cdn.cloudflare.net", "url": "/assets/style.css"},
        }),
        # Wazuh alert hit on hostile IP
        json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rule": {
                "level": 12,
                "description": "Hostile outbound connection to flagged threat intelligence indicator",
                "id": "100201",
            },
            "agent": {"id": "002", "name": "finance-db-01"},
            "data": {
                "srcip": "10.0.30.5",
                "dstip": m_ip2,
                "proto": "TCP",
                "action": "outbound_syn",
            },
        }),
        # Firewall syslog hit
        f"Oct 10 07:15:22 fw-core-01 kernel: [UFW BLOCK] IN=eth0 OUT=eth1 SRC=10.0.2.44 DST={m_ip1} PROTO=TCP SPT=49210 DPT=443",
    ]
    return "\n".join(sample_lines)
