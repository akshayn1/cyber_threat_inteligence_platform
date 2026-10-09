"""Correlation engine: indicator -> malware -> techniques -> CVEs -> assets -> campaign."""
from collectors.mitre import build_attack_chain, chain_strength, technique_info
from analysis import scoring


def _asset_exposed(asset: dict, cve: dict) -> bool:
    prod = cve.get("affected_product", "").lower()
    return any(prod and (prod in p.lower() or p.lower() in prod) for p in asset.get("products", []))


def correlate(threat: dict, threats: list, cves: list, assets: list) -> dict:
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
    ctx = {"related_cves": related_cves, "exposed_assets": exposed,
           "campaign_size": campaign_size, "chain_strength": chain_strength(chain)}
    score = scoring.compute(threat, ctx)

    return {
        **score,
        "indicator": threat["indicator"],
        "related_indicators": len(siblings),
        "related_indicator_list": [{"id": s["id"], "indicator": s["indicator"],
                                    "malware": s.get("malware"), "campaign": s.get("campaign")}
                                   for s in siblings],
        "attack_techniques": [technique_info(t) for t in techniques],
        "attack_chain": chain,
        "related_cves": related_cves,
        "exposed_assets": exposed,
        "evidence": _evidence(threat, siblings, related_cves, exposed, chain),
        "recommendations": scoring.recommendation(score["severity"], ctx, threat),
    }


def _evidence(threat, siblings, cves, exposed, chain) -> list:
    ev = [f"Reported by {threat['source']} with {threat['confidence']}% confidence; {threat['hits']} sightings"]
    if threat.get("malware"):
        ev.append(f"Associated malware family: {threat['malware']}")
    if threat.get("campaign"):
        ev.append(f"Linked to campaign '{threat['campaign']}' ({len(siblings)} related indicators)")
    if chain:
        ev.append("Observed tactics: " + " -> ".join(s["label"] for s in chain))
    for c in cves:
        ev.append(f"Exploits/relates to {c['cve_id']} (CVSS {c['cvss']}) in {c['affected_product']}")
    for a in exposed:
        ev.append(f"Internal asset '{a['name']}' runs a vulnerable product (importance {a['importance']})")
    return ev


def enrich(threat: dict, threats, cves, assets) -> dict:
    """Return threat merged with its analysis."""
    return {**threat, "analysis": correlate(threat, threats, cves, assets)}
