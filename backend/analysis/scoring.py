"""Risk scoring: 0-100 weighted score + rule-based adjustments."""

WEIGHTS = {
    "reputation": 0.30,
    "vulnerability": 0.25,
    "confidence": 0.20,
    "frequency": 0.15,
    "asset": 0.10,
}


def severity_from_score(score: int) -> str:
    return ("critical" if score >= 85 else "high" if score >= 70
            else "medium" if score >= 40 else "low")


def reputation_score(threat: dict, campaign_size: int, source_trust: int = 100) -> int:
    base = 45
    if threat.get("malware"):
        base += 30
    if threat.get("source") in ("threat_feed", "osint", "honeypot"):
        base += 10
    if campaign_size > 1:
        base += 10
    # Scale reputation by source trust
    effective = int(base * (source_trust / 100.0))
    return max(10, min(100, effective))


def compute(threat: dict, ctx: dict) -> dict:
    """ctx: related_cves, exposed_assets, campaign_size, chain_strength, aging, source_trust"""
    # 1. Allowlist Protection Check
    if threat.get("is_allowlisted"):
        return {
            "risk_score": 0,
            "severity": "low",
            "components": {"reputation": 0, "vulnerability": 0, "confidence": 0, "frequency": 0, "asset": 0},
            "rules_triggered": ["PROTECTED ALLOWLIST: Legitimate CDN / Infrastructure (Alerts & Export Suppressed)"],
        }

    # 2. False Positive Protection Check
    if threat.get("is_false_positive"):
        fp_reason = threat.get("fp_reason") or "Analyst verified false alarm"
        return {
            "risk_score": 5,
            "severity": "low",
            "components": {"reputation": 5, "vulnerability": 0, "confidence": 5, "frequency": 0, "asset": 0},
            "rules_triggered": [f"FLAGGED FALSE POSITIVE: {fp_reason} (Source Trust Penalized, Alerts Suppressed)"],
        }

    related_cves = ctx.get("related_cves", [])
    exposed = ctx.get("exposed_assets", [])
    aging = ctx.get("aging", {})
    source_trust = ctx.get("source_trust", 100)

    cvss_vals = [c.get("cvss", 0) for c in related_cves]
    has_kev = any(c.get("in_kev") for c in related_cves)
    has_ransomware = any(c.get("ransomware_campaign") for c in related_cves)
    max_epss = max((c.get("epss", 0.0) for c in related_cves), default=0.0)

    # Vulnerability calculation combining CVSS, CISA KEV, and EPSS probability
    base_vuln = int(max(cvss_vals) * 10) if cvss_vals else 0
    if has_ransomware:
        base_vuln = 100
    elif has_kev:
        # KEV proves active in-the-wild exploitation
        base_vuln = min(100, max(base_vuln, 88) + 12)
    elif max_epss >= 0.25:
        # High EPSS exploit prediction likelihood boost
        base_vuln = min(100, max(base_vuln, 75) + int(max_epss * 20))

    # Incorporate indicator confidence aging decay
    effective_confidence = aging.get("aged_confidence", int(threat.get("confidence", 0)))

    components = {
        "reputation": reputation_score(threat, ctx.get("campaign_size", 1), source_trust),
        "vulnerability": base_vuln,
        "confidence": effective_confidence,
        "frequency": min(100, int(threat.get("hits", 0) * 100 / 60)),  # 60 sightings = 100
        "asset": max((a["importance"] for a in exposed), default=30),
    }
    score = sum(components[k] * w for k, w in WEIGHTS.items())

    rules = []
    if effective_confidence > 80 and (threat.get("malware") or threat.get("severity") in ("high", "critical")):
        rules.append("Malicious indicator with active confidence > 80 -> HIGH floor")
        score = max(score, 70)
    if ctx.get("campaign_size", 1) > 1:
        rules.append(f"Part of campaign with {ctx['campaign_size']} indicators (+5)")
        score += 5
    if ctx.get("chain_strength", 0) >= 3:
        rules.append(f"ATT&CK techniques form a {ctx['chain_strength']}-stage attack chain (+5)")
        score += 5
    if has_kev:
        rules.append("Actively exploited in the wild (CISA KEV Catalog) -> +12 risk boost")
        score += 12
    if max_epss >= 0.20:
        epss_pct = round(max_epss * 100, 1)
        rules.append(f"High EPSS exploit probability ({epss_pct}%) -> +8 risk boost")
        score += 8
    if has_ransomware:
        rules.append("Known ransomware campaign weaponization (CISA KEV) -> CRITICAL floor")
        score = max(score, 88)
    if exposed and (threat.get("malware") or effective_confidence > 70 or has_kev):
        rules.append("Malicious indicator + vulnerable internal asset -> CRITICAL floor")
        score = max(score, 85)

    # Indicator aging penalty if stale or expired
    if aging.get("status") in ("stale", "expired"):
        rules.append(f"Indicator aging: {aging.get('status').upper()} ({aging.get('age_days')}d old, confidence decayed to {effective_confidence}%) -> -15 risk reduction")
        score = max(20, score - 15)

    score = int(round(min(100, score)))
    return {"risk_score": score, "severity": severity_from_score(score),
            "components": components, "rules_triggered": rules}


def recommendation(severity: str, ctx: dict, threat: dict) -> list:
    if threat.get("is_allowlisted"):
        return ["DO NOT BLOCK: Protected on corporate allowlist. Blocking will cause network outage."]

    if threat.get("is_false_positive"):
        return ["No action required: Analyst flagged as false positive. Source trust penalized."]

    recs = []
    aging = ctx.get("aging", {})
    if aging.get("status") in ("stale", "expired"):
        recs.append(f"Caution: Indicator is {aging.get('status')} ({aging.get('age_days')}d old). Verify before hard blocking to avoid false positive outage.")

    if threat["indicator_type"] == "ip":
        recs.append(f"Block {threat['indicator']} at firewall/proxy and add to blocklist")
    elif threat["indicator_type"] in ("domain", "url"):
        recs.append(f"Sinkhole / block {threat['indicator']} in DNS and web proxy")
    if ctx.get("exposed_assets"):
        names = ", ".join(a["name"] for a in ctx["exposed_assets"])
        recs.append(f"Patch or isolate exposed assets: {names}")
    for c in ctx.get("related_cves", []):
        if c.get("in_kev"):
            action = c.get("required_action") or "Apply vendor mitigation immediately"
            due = f" [CISA Due Date: {c['due_date']}]" if c.get("due_date") else ""
            ransom = " [⚠ Known Ransomware Threat]" if c.get("ransomware_campaign") else ""
            recs.append(f"CISA KEV MANDATE for {c['cve_id']}: {action}{due}{ransom}")
        elif c.get("epss", 0) >= 0.25:
            recs.append(f"EPSS Priority: {c['cve_id']} has {round(c['epss']*100, 1)}% exploit probability in next 30 days ({round(c.get('epss_percentile',0)*100, 1)}th percentile)")
        else:
            recs.append(f"Prioritize remediation of {c['cve_id']} (CVSS {c.get('cvss', 'N/A')})")
    if any(t.startswith("T1059") for t in threat.get("techniques", [])):
        recs.append("Review PowerShell / script-interpreter logging on connected endpoints")
    if "T1566" in threat.get("techniques", []):
        recs.append("Search mail gateway for related phishing and run user awareness comms")
    if "T1003" in threat.get("techniques", []):
        recs.append("Rotate credentials and hunt for LSASS access / credential dumping")
    if severity in ("critical", "high"):
        recs.append("Hunt for connections to this indicator in the last 30 days of network logs")
    return recs
