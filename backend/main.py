"""Cyber Threat Intelligence Platform — FastAPI backend.

Pipeline:  collect -> normalize -> store -> correlate -> score -> AI explain -> dashboard
Run:       uvicorn main:app --reload --port 8000
"""
import json
import uuid
from collections import Counter

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from analysis import ai, correlation
from collectors import cve as cve_collector
from collectors import mitre, threats as threat_collector
from database import store
from models.threat import AnalyzeRequest, ImportBundle

app = FastAPI(title="Cyber Threat Intelligence Platform", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ---------- helpers ----------
def _all():
    return store.list("threats"), store.list("cves"), store.list("assets")


def _ingest(bundle: dict) -> dict:
    n = {"threats": 0, "cves": 0, "assets": 0}
    for raw in bundle.get("threats", []):
        store.upsert("threats", threat_collector.normalize(raw)); n["threats"] += 1
    for c in bundle.get("cves", []):
        c.setdefault("cve_id", c.get("id"))
        c["id"] = c["cve_id"]
        store.upsert("cves", c); n["cves"] += 1
    for a in bundle.get("assets", []):
        a.setdefault("id", "asset-" + uuid.uuid4().hex[:8])
        store.upsert("assets", a); n["assets"] += 1
    return n


def _enriched():
    threats, cves, assets = _all()
    out = [correlation.enrich(t, threats, cves, assets) for t in threats]
    out.sort(key=lambda t: -t["analysis"]["risk_score"])
    return out


def _summary(t: dict) -> dict:
    a = t["analysis"]
    return {k: t[k] for k in ("id", "indicator", "indicator_type", "source", "confidence",
                              "malware", "campaign", "geo", "hits", "first_seen", "tags")} | {
        "risk_score": a["risk_score"], "severity": a["severity"],
        "techniques": [x["id"] for x in a["attack_techniques"]],
        "cves": [c["cve_id"] for c in a["related_cves"]],
        "related_indicators": a["related_indicators"],
    }


# ---------- core API ----------
@app.get("/api/health")
def health():
    return {"status": "ok", "database": store.kind, "threats": len(store.list("threats"))}


@app.get("/api/threats")
def list_threats(severity: str | None = None):
    items = [_summary(t) for t in _enriched()]
    if severity:
        items = [i for i in items if i["severity"] == severity]
    return items


@app.get("/api/threats/{threat_id}")
def get_threat(threat_id: str):
    threats, cves, assets = _all()
    t = next((x for x in threats if x["id"] == threat_id), None)
    if not t:
        raise HTTPException(404, "Threat not found")
    return correlation.enrich(t, threats, cves, assets)


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
        if a["severity"] in ("critical", "high", "medium"):
            if a["exposed_assets"]:
                title = f"Malicious indicator targeting vulnerable asset {a['exposed_assets'][0]['name']}"
            elif t.get("malware"):
                title = f"{t['malware']} infrastructure detected"
            else:
                title = "Suspicious indicator detected"
            out.append({"id": t["id"], "severity": a["severity"], "title": title,
                        "indicator": t["indicator"], "risk_score": a["risk_score"],
                        "time": t["first_seen"]})
    out.sort(key=lambda x: (SEV_ORDER[x["severity"]], -x["risk_score"]))
    return out


@app.get("/api/stats")
def stats():
    items = _enriched()
    sev = Counter(i["analysis"]["severity"] for i in items)
    campaigns = {i.get("campaign") for i in items if i.get("campaign")}
    tech = Counter(t["id"] for i in items for t in i["analysis"]["attack_techniques"])
    return {
        "total_threats": len(items),
        "critical": sev.get("critical", 0),
        "total_cves": len(store.list("cves")),
        "campaigns": len(campaigns),
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
             "targets": [a["name"] for a in i["analysis"]["exposed_assets"]]}
            for i in _enriched() if i.get("geo")]


@app.get("/api/mitre")
def mitre_techniques():
    return {"tactics": mitre.TACTIC_ORDER,
            "techniques": [mitre.technique_info(t) for t in mitre.TECHNIQUES]}


@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
    threats, cves, assets = _all()
    t = None
    if req.id:
        t = next((x for x in threats if x["id"] == req.id), None)
    elif req.indicator:
        t = next((x for x in threats if x["indicator"] == req.indicator), None)
    if not t:
        raise HTTPException(404, "Indicator not found — import it first via /api/import")
    enriched = correlation.enrich(t, threats, cves, assets)
    return {**enriched, "ai": ai.analyze(t, enriched["analysis"], req.use_ai)}


# ---------- ingestion ----------
@app.post("/api/import")
async def import_file(file: UploadFile = File(...)):
    """Upload a threat-intel JSON file: a list of indicators, or {threats, cves, assets}."""
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
    return {"seeded": _ingest(threat_collector.load_sample())}


@app.post("/api/collect/{source}")
def collect(source: str):
    try:
        if source == "cve":
            items = cve_collector.fetch_recent()
            return {"collected": _ingest({"cves": items})}
        if source == "feodo":
            items = threat_collector.fetch_feodo()
            return {"collected": _ingest({"threats": items})}
        if source == "mitre":
            return {"techniques_loaded": mitre.fetch_full()}
    except Exception as e:  # network / upstream errors
        raise HTTPException(502, f"Collector '{source}' failed: {e.__class__.__name__}: {e}")
    raise HTTPException(404, "Unknown source (use cve | feodo | mitre)")


@app.on_event("startup")
def auto_seed():
    if not store.list("threats"):
        _ingest(threat_collector.load_sample())
