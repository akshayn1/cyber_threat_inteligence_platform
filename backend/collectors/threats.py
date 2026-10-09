"""Threat feed collector + normalizer.

* load_sample()  -> bundled demo data (uses RFC 5737 documentation IP ranges,
                    so no real host is ever labelled malicious)
* fetch_feodo()  -> live botnet C2 blocklist from abuse.ch Feodo Tracker
* normalize()    -> turns raw feed / uploaded JSON into the platform schema
"""
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx

DATA = Path(__file__).resolve().parent.parent / "data" / "sample_data.json"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _type_of(value: str) -> str:
    if IP_RE.match(value):
        return "ip"
    if value.lower().startswith(("http://", "https://")):
        return "url"
    if re.fullmatch(r"[a-fA-F0-9]{32,64}", value):
        return "hash"
    return "domain"


def _severity(conf: int) -> str:
    return "critical" if conf >= 90 else "high" if conf >= 75 else "medium" if conf >= 50 else "low"


def normalize(raw: dict) -> dict:
    """Accepts our schema, or loose feed-style keys (ioc/indicator/ip/value)."""
    value = str(raw.get("indicator") or raw.get("ioc") or raw.get("ip_address")
                or raw.get("ip") or raw.get("value") or "").strip()
    if not value:
        raise ValueError("record has no indicator")
    conf = int(raw.get("confidence", 60))
    geo = raw.get("geo") or ({"country": raw["country"], "lat": raw.get("lat", 0),
                              "lon": raw.get("lon", 0)} if raw.get("country") else None)
    return {
        "id": raw.get("id") or "thr-" + uuid.uuid5(uuid.NAMESPACE_URL, value).hex[:10],
        "indicator": value,
        "indicator_type": raw.get("indicator_type") or _type_of(value),
        "source": raw.get("source", "threat_feed"),
        "confidence": max(0, min(100, conf)),
        "severity": raw.get("severity") or _severity(conf),
        "malware": raw.get("malware"),
        "campaign": raw.get("campaign"),
        "techniques": list(raw.get("techniques", [])),
        "cves": list(raw.get("cves", [])),
        "hits": int(raw.get("hits", 1)),
        "geo": geo,
        "first_seen": raw.get("first_seen") or datetime.now(timezone.utc).isoformat(),
        "tags": list(raw.get("tags", [])),
    }


def load_sample() -> dict:
    return json.loads(DATA.read_text())


def fetch_feodo(limit: int = 40) -> list:
    r = httpx.get(FEODO_URL, timeout=30)
    r.raise_for_status()
    out = []
    for e in r.json()[:limit]:
        out.append(normalize({
            "indicator": e["ip_address"], "source": "abuse.ch Feodo Tracker",
            "malware": e.get("malware"), "confidence": 88, "hits": 10,
            "country": e.get("country"), "first_seen": e.get("first_seen"),
            "techniques": ["T1071", "T1105"], "tags": ["botnet-c2"],
        }))
    return out
