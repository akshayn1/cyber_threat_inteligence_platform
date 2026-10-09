"""CVE collector — pulls recent critical CVEs from the NVD 2.0 API and normalizes them."""
import httpx

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _severity(cvss: float) -> str:
    return ("critical" if cvss >= 9 else "high" if cvss >= 7
            else "medium" if cvss >= 4 else "low")


def normalize(item: dict) -> dict:
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
    return {
        "id": cve["id"], "cve_id": cve["id"], "cvss": cvss, "severity": _severity(cvss),
        "affected_product": product, "description": desc[:400],
        "published": cve.get("published"),
    }


def fetch_recent(limit: int = 25, severity: str = "CRITICAL") -> list:
    r = httpx.get(NVD_URL, params={"cvssV3Severity": severity, "resultsPerPage": limit},
                  timeout=45)
    r.raise_for_status()
    return [normalize(v) for v in r.json().get("vulnerabilities", [])]
