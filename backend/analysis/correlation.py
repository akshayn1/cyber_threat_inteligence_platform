"""Correlation engine: indicator -> malware -> techniques -> CVEs -> assets -> campaign -> aging -> allowlist."""
from collectors.mitre import build_attack_chain, chain_strength, technique_info
from analysis import scoring, aging as aging_engine
from analysis.allowlist import check_allowlist, compute_source_trust


def _asset_exposed(asset: dict, cve: dict) -> bool:
    prod = cve.get("affected_product", "").lower()
    return any(prod and (prod in p.lower() or p.lower() in prod) for p in asset.get("products", []))


def correlate(
    threat: dict,
    threats: list,
    cves: list,
    assets: list,
    allowlist: list = None,
    source_penalties: dict = None
) -> dict:
    allowlist = allowlist or []
    source_penalties = source_penalties or {}

    # Check Allowlist
    is_protected, allow_rule = check_allowlist(threat["indicator"], allowlist)
    if is_protected or threat.get("is_allowlisted"):
        threat["is_allowlisted"] = True

    # Compute aging
    aging_data = aging_engine.compute_aging(threat)

    # Compute source trust
    source_trust = compute_source_trust(threat.get("source", "threat_feed"), source_penalties)

    # Campaign / malware siblings
    siblings = [t for t in threats if t["id"] != threat["id"] and (
        (threat.get("campaign") and t.get("campaign") == threat["campaign"]) or
        (threat.get("malware") and t.get("malware") == threat["malware"]))]
    campaign_size = 1 + len([s for s in siblings if s.get("campaign") == threat.get("campaign")]) \
        if threat.get("campaign") else 1

    # Techniques: own + those seen on same-malware indicators
    techniques = list(dict.fromkeys(threat.get("techniques", [])))

    # CVEs: explicit links on the indicator, plus CVEs tied to siblings
    cve_ids = set(threat.get("cves", []))
    cve_map = {c["cve_id"]: c for c in cves}
    related_cves = [cve_map[c] for c in cve_ids if c in cve_map]

    exposed = [a for a in assets if any(_asset_exposed(a, c) for c in related_cves)]

    chain = build_attack_chain(techniques)
    ctx = {
        "related_cves": related_cves,
        "exposed_assets": exposed,
        "campaign_size": campaign_size,
        "chain_strength": chain_strength(chain),
        "aging": aging_data,
        "source_trust": source_trust,
    }
    score = scoring.compute(threat, ctx)

    return {
        **score,
        "indicator": threat["indicator"],
        "is_allowlisted": bool(threat.get("is_allowlisted")),
        "is_false_positive": bool(threat.get("is_false_positive")),
        "fp_reason": threat.get("fp_reason"),
        "allowlist_rule": allow_rule,
        "aging": aging_data,
        "source_trust": source_trust,
        "related_indicators": len(siblings),
        "related_indicator_list": [{"id": s["id"], "indicator": s["indicator"],
                                    "malware": s.get("malware"), "campaign": s.get("campaign")}
                                   for s in siblings],
        "attack_techniques": [technique_info(t) for t in techniques],
        "attack_chain": chain,
        "related_cves": related_cves,
        "exposed_assets": exposed,
        "evidence": _evidence(threat, siblings, related_cves, exposed, chain, aging_data, is_protected, allow_rule),
        "recommendations": scoring.recommendation(score["severity"], ctx, threat),
    }


def _evidence(threat, siblings, cves, exposed, chain, aging, is_protected, allow_rule) -> list:
    ev = []
    if is_protected or threat.get("is_allowlisted"):
        r_name = allow_rule.get("reason") if allow_rule else "Verified corporate allowlist"
        ev.append(f"🛡 [ALLOWLIST PROTECTED] Matches allowlist rule: {r_name} (Alerts suppressed)")

    if threat.get("is_false_positive"):
        ev.append(f"🚩 [FALSE POSITIVE] Flagged by analyst: {threat.get('fp_reason', 'Verified false alarm')}")

    ev.append(f"Reported by {threat['source']} with {threat['confidence']}% confidence; {threat['hits']} sightings")

    # Aging evidence
    if aging.get("status") in ("stale", "expired"):
        ev.append(f"⏳ [INDICATOR AGING] First seen {aging['age_days']} days ago — Confidence decayed from {aging['initial_confidence']}% to {aging['aged_confidence']}% ({aging['status'].upper()})")
    else:
        ev.append(f"⚡ [LIFECYCLE ACTIVE] Telemetry observed {aging['age_days']}d ago (half-life: {aging['half_life_days']}d, expires in {aging['expires_in_days']}d)")

    if threat.get("malware"):
        ev.append(f"Associated malware family: {threat['malware']}")
    if threat.get("campaign"):
        ev.append(f"Linked to campaign '{threat['campaign']}' ({len(siblings)} related indicators)")
    if chain:
        ev.append("Observed tactics: " + " -> ".join(s["label"] for s in chain))

    for c in cves:
        kev_note = " [⚡ CISA KEV: Actively Exploited in the Wild]" if c.get("in_kev") else ""
        rw_note = " [⚠ Ransomware Associated]" if c.get("ransomware_campaign") else ""
        epss_val = c.get("epss")
        epss_note = f" [📊 EPSS: {round(epss_val*100, 1)}% exploit probability ({round(c.get('epss_percentile', 0)*100, 1)}th %ile)]" if epss_val else ""
        ev.append(f"Exploits/relates to {c['cve_id']} (CVSS {c.get('cvss', 'N/A')}) in {c.get('affected_product', 'unknown')}{kev_note}{rw_note}{epss_note}")

    for a in exposed:
        ev.append(f"Internal asset '{a['name']}' runs a vulnerable product (importance {a['importance']})")
    return ev


def enrich(threat: dict, threats, cves, assets, allowlist=None, source_penalties=None) -> dict:
    """Return threat merged with its analysis."""
    return {**threat, "analysis": correlate(threat, threats, cves, assets, allowlist, source_penalties)}

