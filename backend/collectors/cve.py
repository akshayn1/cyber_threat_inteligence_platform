"""CVE collector — integrates NIST NVD 2.0 API and CISA Known Exploited Vulnerabilities (KEV)."""
import json
from pathlib import Path
from typing import Dict, List, Optional
import httpx

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_FILE = Path(__file__).resolve().parent.parent / "data" / "cisa.json"

_KEV_CACHE: Optional[Dict[str, dict]] = None


def _severity(cvss: float) -> str:
    return ("critical" if cvss >= 9 else "high" if cvss >= 7
            else "medium" if cvss >= 4 else "low")


def normalize_cisa_kev(v: dict) -> dict:
    """Normalize a CISA KEV catalog entry into the platform CVE schema."""
    cve_id = str(v.get("cveID", "")).strip()
    vendor = str(v.get("vendorProject", "")).strip()
    product = str(v.get("product", "")).strip()
    affected = f"{vendor} {product}".strip() or "unknown"
    ransomware = str(v.get("knownRansomwareCampaignUse", "")).strip().lower() == "known"

    return {
        "id": cve_id,
        "cve_id": cve_id,
        "cvss": 9.8 if ransomware else 8.5,
        "severity": "critical" if ransomware else "high",
        "affected_product": affected,
        "description": v.get("shortDescription", ""),
        "published": v.get("dateAdded"),
        "in_kev": True,
        "kev_date_added": v.get("dateAdded"),
        "ransomware_campaign": ransomware,
        "required_action": v.get("requiredAction", ""),
        "due_date": v.get("dueDate", ""),
        "cwes": v.get("cwes", []),
        "notes": v.get("notes", ""),
    }


def get_kev_catalog() -> Dict[str, dict]:
    """Load and index CISA KEV catalog by CVE ID (lazy cached)."""
    global _KEV_CACHE
    if _KEV_CACHE is not None:
        return _KEV_CACHE

    _KEV_CACHE = {}
    if CISA_FILE.exists():
        try:
            data = json.loads(CISA_FILE.read_text(encoding="utf-8"))
            for item in data.get("vulnerabilities", []):
                norm = normalize_cisa_kev(item)
                _KEV_CACHE[norm["cve_id"]] = norm
        except Exception as e:
            print(f"[cve] Error loading cisa.json: {e}")
    return _KEV_CACHE


def enrich_cve_with_kev(cve: dict) -> dict:
    """Enrich an existing NVD or stored CVE with CISA KEV exploitation metadata."""
    cve_id = cve.get("cve_id") or cve.get("id")
    if not cve_id:
        return cve

    catalog = get_kev_catalog()
    kev_match = catalog.get(cve_id)
    if kev_match:
        cve["in_kev"] = True
        cve["kev_date_added"] = kev_match.get("kev_date_added")
        cve["ransomware_campaign"] = kev_match.get("ransomware_campaign", False)
        cve["required_action"] = kev_match.get("required_action")
        cve["due_date"] = kev_match.get("due_date")
        if not cve.get("affected_product") or cve["affected_product"] == "unknown":
            cve["affected_product"] = kev_match.get("affected_product", "unknown")
        if not cve.get("description"):
            cve["description"] = kev_match.get("description", "")
        # Elevate severity if KEV confirms weaponization
        if cve.get("ransomware_campaign"):
            cve["severity"] = "critical"
            cve["cvss"] = max(cve.get("cvss", 0), 9.5)
        else:
            cve["cvss"] = max(cve.get("cvss", 0), 8.0)
    else:
        cve.setdefault("in_kev", False)
        cve.setdefault("ransomware_campaign", False)

    return cve


def normalize_nvd(item: dict) -> dict:
    cve = item["cve"]
    metrics = cve.get("metrics", {})
    cvss = 0.0
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            cvss = float(metrics[key][0]["cvssData"]["baseScore"])
            break
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
    product = "unknown"
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m.get("criteria", "").split(":")
                if len(parts) > 4:
                    product = parts[4].replace("_", " ")
                    break

    res = {
        "id": cve["id"], "cve_id": cve["id"], "cvss": cvss, "severity": _severity(cvss),
        "affected_product": product, "description": desc[:400],
        "published": cve.get("published"),
    }
    return enrich_cve_with_kev(res)


normalize = normalize_nvd


def fetch_recent(limit: int = 25, severity: str = "CRITICAL") -> list:
    r = httpx.get(NVD_URL, params={"cvssV3Severity": severity, "resultsPerPage": limit}, timeout=45)
    r.raise_for_status()
    return [normalize_nvd(v) for v in r.json().get("vulnerabilities", [])]


def load_cisa_kev(limit: Optional[int] = None) -> List[dict]:
    """Load CISA KEV from local cisa.json file."""
    catalog = get_kev_catalog()
    items = list(catalog.values())
    return items[:limit] if limit else items


def fetch_cisa_live(limit: int = 50) -> List[dict]:
    """Fetch live CISA KEV catalog or fall back to local cisa.json."""
    try:
        r = httpx.get(CISA_KEV_URL, timeout=40)
        r.raise_for_status()
        vulnerabilities = r.json().get("vulnerabilities", [])
        return [normalize_cisa_kev(v) for v in vulnerabilities[:limit]]
    except Exception as e:
        print(f"[cve] Live CISA KEV fetch failed ({e}); falling back to local file")
        return load_cisa_kev(limit=limit)

