"""Cyber Threat Intelligence Platform — FastAPI backend.

Pipeline:  collect -> normalize -> store -> correlate -> score -> aging -> allowlist -> logs -> AI explain -> dashboard
Run:       uvicorn main:app --reload --port 8000
"""
import json
import uuid
from collections import Counter

from fastapi import FastAPI, File, HTTPException, UploadFile, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse

from analysis import ai, correlation, logs, aging as aging_engine
from analysis.allowlist import DEFAULT_ALLOWLIST, check_allowlist, compute_source_trust
from collectors import cve as cve_collector
from collectors import mitre, threats as threat_collector
from database import store
from models.threat import (
    AnalyzeRequest,
    ImportBundle,
    AllowlistItem,
    FalsePositiveRequest,
    LogMatchRequest,
)

app = FastAPI(title="Cyber Threat Intelligence Platform", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ---------- helpers ----------
def _all():
    return store.list("threats"), store.list("cves"), store.list("assets"), store.list("allowlist")


def _source_penalties() -> dict:
    return {r["id"]: r.get("penalty", 0) for r in store.list("source_reputation")}


def _ingest(bundle: dict) -> dict:
    n = {"threats": 0, "cves": 0, "assets": 0, "allowlist": 0}
    for raw in bundle.get("threats", []):
        store.upsert("threats", threat_collector.normalize(raw)); n["threats"] += 1
    for c in bundle.get("cves", []):
        c.setdefault("cve_id", c.get("id"))
        c["id"] = c["cve_id"]
        c = cve_collector.enrich_cve_with_kev(c)
        store.upsert("cves", c); n["cves"] += 1
    for a in bundle.get("assets", []):
        a.setdefault("id", "asset-" + uuid.uuid4().hex[:8])
        store.upsert("assets", a); n["assets"] += 1
    for item in bundle.get("allowlist", []):
        item.setdefault("id", "al-" + uuid.uuid4().hex[:8])
        store.upsert("allowlist", item); n["allowlist"] += 1
    return n


def _enriched():
    threats, cves, assets, allowlist = _all()
    penalties = _source_penalties()
    out = [correlation.enrich(t, threats, cves, assets, allowlist, penalties) for t in threats]
    out.sort(key=lambda t: -t["analysis"]["risk_score"])
    return out


def _summary(t: dict) -> dict:
    a = t["analysis"]
    base_keys = ("id", "indicator", "indicator_type", "source", "confidence",
                 "malware", "campaign", "geo", "hits", "first_seen", "tags")
    res = {k: t.get(k) for k in base_keys}
    res["is_allowlisted"] = bool(t.get("is_allowlisted") or a.get("is_allowlisted"))
    res["is_false_positive"] = bool(t.get("is_false_positive") or a.get("is_false_positive"))
    res["fp_reason"] = t.get("fp_reason") or a.get("fp_reason")
    res.update({
        "risk_score": a["risk_score"],
        "severity": a["severity"],
        "techniques": [x["id"] for x in a["attack_techniques"]],
        "cves": [c["cve_id"] for c in a["related_cves"]],
        "related_indicators": a["related_indicators"],
        "aging": a["aging"],
        "source_trust": a["source_trust"],
    })
    return res


# ---------- core API ----------
@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "database": store.kind,
        "threats": len(store.list("threats")),
        "allowlist_entries": len(store.list("allowlist")),
        "log_alerts": len(store.list("log_alerts")),
    }


@app.get("/api/threats")
def list_threats(
    severity: str | None = None,
    lifecycle: str | None = None,
    include_allowlisted: bool = True,
    include_fp: bool = True,
):
    items = [_summary(t) for t in _enriched()]
    if severity:
        items = [i for i in items if i["severity"] == severity]
    if lifecycle:
        items = [i for i in items if i.get("aging", {}).get("status") == lifecycle]
    if not include_allowlisted:
        items = [i for i in items if not i.get("is_allowlisted")]
    if not include_fp:
        items = [i for i in items if not i.get("is_false_positive")]
    return items


@app.get("/api/threats/{threat_id}")
def get_threat(threat_id: str):
    threats, cves, assets, allowlist = _all()
    t = next((x for x in threats if x["id"] == threat_id), None)
    if not t:
        raise HTTPException(404, "Threat not found")
    penalties = _source_penalties()
    return correlation.enrich(t, threats, cves, assets, allowlist, penalties)


@app.get("/api/cves")
def list_cves():
    cves = sorted(store.list("cves"), key=lambda c: -c.get("cvss", 0))
    threats = store.list("threats")
    for c in cves:
        c["linked_indicators"] = sum(1 for t in threats if c["cve_id"] in t.get("cves", []))
    return cves


@app.get("/api/alerts")
def alerts():
    out = []
    for t in _enriched():
        a = t["analysis"]
        # Skip allowlisted or false positive indicators
        if t.get("is_allowlisted") or t.get("is_false_positive"):
            continue
        # Skip expired indicators
        if a.get("aging", {}).get("status") == "expired":
            continue

        if a["severity"] in ("critical", "high", "medium"):
            if a["exposed_assets"]:
                title = f"Malicious indicator targeting vulnerable asset {a['exposed_assets'][0]['name']}"
            elif t.get("malware"):
                title = f"{t['malware']} infrastructure detected"
            else:
                title = "Suspicious indicator detected"
            out.append({
                "id": t["id"],
                "severity": a["severity"],
                "title": title,
                "indicator": t["indicator"],
                "risk_score": a["risk_score"],
                "time": t["first_seen"],
                "aging_status": a.get("aging", {}).get("status", "active"),
                "aged_confidence": a.get("aging", {}).get("aged_confidence", t.get("confidence")),
            })
    out.sort(key=lambda x: (SEV_ORDER[x["severity"]], -x["risk_score"]))
    return out


@app.get("/api/stats")
def stats():
    items = _enriched()
    sev = Counter(i["analysis"]["severity"] for i in items if not i.get("is_allowlisted") and not i.get("is_false_positive"))
    campaigns = {i.get("campaign") for i in items if i.get("campaign")}
    tech = Counter(t["id"] for i in items for t in i["analysis"]["attack_techniques"])
    all_cves = store.list("cves")
    kev_count = sum(1 for c in all_cves if c.get("in_kev"))
    high_epss_count = sum(1 for c in all_cves if c.get("epss", 0) >= 0.20)
    ransomware_count = sum(1 for c in all_cves if c.get("ransomware_campaign"))

    allowlist_count = len(store.list("allowlist"))
    fp_count = sum(1 for i in items if i.get("is_false_positive"))
    stale_count = sum(1 for i in items if i["analysis"].get("aging", {}).get("is_stale"))
    log_alert_count = len(store.list("log_alerts"))

    return {
        "total_threats": len(items),
        "critical": sev.get("critical", 0),
        "total_cves": len(all_cves),
        "cisa_kev_count": kev_count,
        "high_epss_count": high_epss_count,
        "ransomware_cves": ransomware_count,
        "campaigns": len(campaigns),
        "allowlist_count": allowlist_count,
        "false_positive_count": fp_count,
        "stale_indicators": stale_count,
        "log_alert_count": log_alert_count,
        "by_severity": [{"severity": s, "count": sev.get(s, 0)} for s in ("critical", "high", "medium", "low")],
        "top_techniques": [{"id": k, "name": mitre.technique_info(k)["name"], "count": v}
                           for k, v in tech.most_common(6)],
        "database": store.kind,
    }


@app.get("/api/map")
def threat_map():
    return [{"id": i["id"], "indicator": i["indicator"], "geo": i["geo"], "severity": i["analysis"]["severity"],
             "risk_score": i["analysis"]["risk_score"], "malware": i.get("malware"),
             "cves": [c["cve_id"] for c in i["analysis"]["related_cves"]],
             "targets": [a["name"] for a in i["analysis"]["exposed_assets"]],
             "is_allowlisted": i.get("is_allowlisted", False),
             "is_false_positive": i.get("is_false_positive", False)}
            for i in _enriched() if i.get("geo")]


@app.get("/api/mitre")
def mitre_techniques():
    return {"tactics": mitre.TACTIC_ORDER,
            "techniques": [mitre.technique_info(t) for t in mitre.TECHNIQUES]}


@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
    threats, cves, assets, allowlist = _all()
    t = None
    if req.id:
        t = next((x for x in threats if x["id"] == req.id), None)
    elif req.indicator:
        t = next((x for x in threats if x["indicator"] == req.indicator), None)
    if not t:
        raise HTTPException(404, "Indicator not found — import it first via /api/import")
    penalties = _source_penalties()
    enriched = correlation.enrich(t, threats, cves, assets, allowlist, penalties)
    return {**enriched, "ai": ai.analyze(t, enriched["analysis"], req.use_ai)}


# ---------- Feature 2: Allowlist & False-Positive Management ----------
@app.get("/api/allowlist")
def list_allowlist():
    return store.list("allowlist")


@app.post("/api/allowlist")
def add_allowlist_item(item: AllowlistItem):
    doc = item.model_dump()
    doc["id"] = doc.get("id") or "al-" + uuid.uuid4().hex[:8]
    doc.setdefault("added_at", threat_collector.datetime.now(threat_collector.timezone.utc).isoformat())
    store.upsert("allowlist", doc)
    return {"message": "Added to allowlist", "item": doc}


@app.delete("/api/allowlist/{item_id}")
def delete_allowlist_item(item_id: str):
    ok = store.delete("allowlist", item_id)
    if not ok:
        raise HTTPException(404, "Allowlist entry not found")
    return {"message": "Allowlist entry removed", "id": item_id}


@app.post("/api/threats/{threat_id}/false-positive")
def mark_false_positive(threat_id: str, req: FalsePositiveRequest):
    t = store.get("threats", threat_id)
    if not t:
        raise HTTPException(404, "Threat not found")
    t["is_false_positive"] = True
    t["fp_reason"] = req.reason
    store.upsert("threats", t)

    # Apply source penalty
    if req.penalize_source:
        src = t.get("source", "threat_feed")
        cur_rec = store.get("source_reputation", src) or {"id": src, "penalty": 0, "false_positives": 0}
        cur_rec["penalty"] = cur_rec.get("penalty", 0) + 15
        cur_rec["false_positives"] = cur_rec.get("false_positives", 0) + 1
        store.upsert("source_reputation", cur_rec)

    return {"message": "Indicator marked as false positive", "threat_id": threat_id, "fp_reason": req.reason}


@app.post("/api/threats/{threat_id}/unmark-false-positive")
def unmark_false_positive(threat_id: str):
    t = store.get("threats", threat_id)
    if not t:
        raise HTTPException(404, "Threat not found")
    t["is_false_positive"] = False
    t["fp_reason"] = None
    store.upsert("threats", t)
    return {"message": "Indicator false positive flag cleared", "threat_id": threat_id}


@app.post("/api/threats/{threat_id}/allowlist")
def allowlist_threat(threat_id: str, reason: str = Query("Analyst verified legitimate infrastructure")):
    t = store.get("threats", threat_id)
    if not t:
        raise HTTPException(404, "Threat not found")
    al_item = {
        "id": "al-" + uuid.uuid4().hex[:8],
        "indicator": t["indicator"],
        "indicator_type": t.get("indicator_type", "ip"),
        "reason": reason,
        "added_at": threat_collector.datetime.now(threat_collector.timezone.utc).isoformat(),
    }
    store.upsert("allowlist", al_item)
    t["is_allowlisted"] = True
    store.upsert("threats", t)
    return {"message": "Threat added to protected allowlist", "allowlist_entry": al_item}


@app.get("/api/sources")
def list_sources():
    threats = store.list("threats")
    penalties = _source_penalties()
    src_names = set(t.get("source", "threat_feed") for t in threats) | set(penalties.keys())
    out = []
    for s in src_names:
        count = sum(1 for t in threats if t.get("source") == s)
        fps = sum(1 for t in threats if t.get("source") == s and t.get("is_false_positive"))
        trust = compute_source_trust(s, penalties)
        out.append({"source": s, "indicator_count": count, "false_positives": fps, "trust_score": trust})
    out.sort(key=lambda x: -x["trust_score"])
    return out


# ---------- Feature 3: Live Log Matching & Ingestion ----------
@app.post("/api/logs/match")
async def match_logs(file: UploadFile = None, payload: LogMatchRequest = None):
    """Upload Suricata eve.json, Zeek, Wazuh, or syslog to continuously correlate against known threats."""
    text = ""
    if file:
        try:
            text = (await file.read()).decode("utf-8", errors="replace")
        except Exception as e:
            raise HTTPException(400, f"Cannot read uploaded file: {e}")
    elif payload and payload.log_text:
        text = payload.log_text
    else:
        raise HTTPException(400, "Provide either a log file or log_text payload")

    threats, _, _, allowlist = _all()
    # Enrich threats so risk score is present in match alerts
    enriched_threats = _enriched()
    res = logs.process_logs_batch(text, enriched_threats, allowlist)

    # Persist log detection events
    for m in res["matches"]:
        store.upsert("log_alerts", m)

    return res


@app.post("/api/logs/simulate")
def simulate_log_stream():
    """Generates real-world live traffic stream from Suricata, Zeek & Wazuh, matching stored IoCs."""
    threats = _enriched()
    _, _, _, allowlist = _all()
    sample_content = logs.generate_sample_log_stream(threats)
    res = logs.process_logs_batch(sample_content, threats, allowlist)

    for m in res["matches"]:
        store.upsert("log_alerts", m)

    return res


@app.get("/api/logs/matches")
def get_log_matches(limit: int = 50):
    all_hits = sorted(store.list("log_alerts"), key=lambda x: x.get("timestamp", ""), reverse=True)
    return all_hits[:limit]


@app.delete("/api/logs/matches")
def clear_log_matches():
    store.clear("log_alerts")
    return {"message": "Log alerts cleared"}


# ---------- Feature 4: Indicator Aging & Clean Export ----------
@app.get("/api/export/blocklist")
def export_blocklist(
    format: str = Query("txt", description="txt (one indicator per line) or json"),
    exclude_stale: bool = Query(True, description="Exclude indicators whose confidence decayed due to aging"),
    exclude_allowlist: bool = Query(True, description="Exclude indicators on the protected allowlist"),
    min_confidence: int = Query(50, description="Minimum confidence threshold"),
):
    """Clean operational firewall/EDR blocklist export, suppressing false-positives and stale IPs."""
    items = _enriched()
    clean = []
    for t in items:
        a = t["analysis"]
        if exclude_allowlist and (t.get("is_allowlisted") or a.get("is_allowlisted")):
            continue
        if t.get("is_false_positive"):
            continue
        if exclude_stale and a.get("aging", {}).get("is_stale"):
            continue
        effective_conf = a.get("aging", {}).get("aged_confidence", t.get("confidence", 0))
        if effective_conf < min_confidence:
            continue
        clean.append(t)

    if format == "json":
        return [{
            "indicator": c["indicator"],
            "type": c["indicator_type"],
            "malware": c.get("malware"),
            "risk_score": c["analysis"]["risk_score"],
            "aged_confidence": c["analysis"]["aging"]["aged_confidence"],
            "status": c["analysis"]["aging"]["status"],
        } for c in clean]

    # Plain text export suitable for firewall feed
    lines = [
        f"# Cyber Threat Intelligence Platform — Clean Blocklist Export",
        f"# Generated: {threat_collector.datetime.now(threat_collector.timezone.utc).isoformat()}",
        f"# Exclude Stale: {exclude_stale} | Exclude Allowlist: {exclude_allowlist} | Total: {len(clean)}",
        "",
    ]
    for c in clean:
        lines.append(c["indicator"])
    return PlainTextResponse("\n".join(lines), media_type="text/plain")


# ---------- ingestion ----------
@app.post("/api/import")
async def import_file(file: UploadFile = File(...)):
    """Upload a threat-intel JSON file: a list of indicators, or {threats, cves, assets, allowlist}."""
    try:
        data = json.loads((await file.read()).decode("utf-8"))
    except Exception:
        raise HTTPException(400, "File is not valid JSON")
    bundle = {"threats": data} if isinstance(data, list) else data
    before = {t["id"] for t in store.list("threats")}
    try:
        n = _ingest(bundle)
    except ValueError as e:
        raise HTTPException(400, str(e))
    new = [t for t in _enriched() if t["id"] not in before]
    return {"imported": n, "new_threats": [_summary(t) for t in new]}


@app.post("/api/import/json")
def import_json(bundle: ImportBundle):
    return {"imported": _ingest(bundle.model_dump())}


@app.post("/api/seed")
def seed(reset: bool = True):
    if reset:
        store.clear()
        # Seed default allowlist
        for al in DEFAULT_ALLOWLIST:
            store.upsert("allowlist", al)
    return {"seeded": _ingest(threat_collector.load_sample())}


@app.post("/api/collect/{source}")
def collect(source: str):
    try:
        if source == "cve":
            items = cve_collector.fetch_recent()
            return {"collected": _ingest({"cves": items})}
        if source in ("cisa", "kev"):
            items = cve_collector.load_cisa_kev(limit=100)
            return {"collected": _ingest({"cves": items})}
        if source == "feodo":
            items = threat_collector.fetch_feodo()
            return {"collected": _ingest({"threats": items})}
        if source == "mitre":
            return {"techniques_loaded": mitre.fetch_full()}
    except Exception as e:
        raise HTTPException(502, f"Collector '{source}' failed: {e.__class__.__name__}: {e}")
    raise HTTPException(404, "Unknown source (use cve | cisa | feodo | mitre)")


@app.on_event("startup")
def auto_seed():
    # Ensure default allowlist is present
    if not store.list("allowlist"):
        for al in DEFAULT_ALLOWLIST:
            store.upsert("allowlist", al)

    if not store.list("threats"):
        _ingest(threat_collector.load_sample())
    else:
        # Re-enrich stored CVEs with KEV and EPSS flags if present
        for c in store.list("cves"):
            store.upsert("cves", cve_collector.enrich_cve_with_kev(c))
