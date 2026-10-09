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


def reputation_score(threat: dict, campaign_size: int) -> int:
    base = 45
    if threat.get("malware"):
        base += 30
    if threat.get("source") in ("threat_feed", "osint", "honeypot"):
        base += 10
    if campaign_size > 1:
        base += 10
    return min(100, base)


def compute(threat: dict, ctx: dict) -> dict:
    """ctx: related_cves, exposed_assets, campaign_size, chain_strength"""
    cvss_vals = [c.get("cvss", 0) for c in ctx["related_cves"]]
    exposed = ctx["exposed_assets"]

    components = {
        "reputation": reputation_score(threat, ctx["campaign_size"]),
        "vulnerability": int(max(cvss_vals) * 10) if cvss_vals else 0,
        "confidence": int(threat.get("confidence", 0)),
        "frequency": min(100, int(threat.get("hits", 0) * 100 / 60)),  # 60 sightings = 100
        "asset": max((a["importance"] for a in exposed), default=30),
    }
    score = sum(components[k] * w for k, w in WEIGHTS.items())

    rules = []
    if threat.get("confidence", 0) > 80 and (threat.get("malware") or threat.get("severity") in ("high", "critical")):
        rules.append("Malicious indicator with confidence > 80 -> HIGH floor")
        score = max(score, 70)
    if ctx["campaign_size"] > 1:
        rules.append(f"Part of campaign with {ctx['campaign_size']} indicators (+5)")
        score += 5
    if ctx["chain_strength"] >= 3:
        rules.append(f"ATT&CK techniques form a {ctx['chain_strength']}-stage attack chain (+5)")
        score += 5
    if exposed and (threat.get("malware") or threat.get("confidence", 0) > 70):
        rules.append("Malicious indicator + vulnerable internal asset -> CRITICAL floor")
        score = max(score, 85)

    score = int(round(min(100, score)))
    return {"risk_score": score, "severity": severity_from_score(score),
            "components": components, "rules_triggered": rules}


def recommendation(severity: str, ctx: dict, threat: dict) -> list:
    recs = []
    if threat["indicator_type"] == "ip":
        recs.append(f"Block {threat['indicator']} at firewall/proxy and add to blocklist")
    elif threat["indicator_type"] in ("domain", "url"):
        recs.append(f"Sinkhole / block {threat['indicator']} in DNS and web proxy")
    if ctx["exposed_assets"]:
        names = ", ".join(a["name"] for a in ctx["exposed_assets"])
        recs.append(f"Patch or isolate exposed assets: {names}")
    for c in ctx["related_cves"]:
        recs.append(f"Prioritize remediation of {c['cve_id']} (CVSS {c['cvss']})")
    if any(t.startswith("T1059") for t in threat.get("techniques", [])):
        recs.append("Review PowerShell / script-interpreter logging on connected endpoints")
    if "T1566" in threat.get("techniques", []):
        recs.append("Search mail gateway for related phishing and run user awareness comms")
    if "T1003" in threat.get("techniques", []):
        recs.append("Rotate credentials and hunt for LSASS access / credential dumping")
    if severity in ("critical", "high"):
        recs.append("Hunt for connections to this indicator in the last 30 days of network logs")
    return recs
