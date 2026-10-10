from typing import List, Optional
from pydantic import BaseModel, Field


class Geo(BaseModel):
    country: str = "Unknown"
    lat: float = 0.0
    lon: float = 0.0


class Threat(BaseModel):
    """Normalized threat indicator (IP / domain / hash / url)."""
    indicator: str
    indicator_type: str = "ip"
    source: str = "threat_feed"
    confidence: int = Field(50, ge=0, le=100)
    severity: str = "medium"
    malware: Optional[str] = None
    campaign: Optional[str] = None
    techniques: List[str] = []
    cves: List[str] = []
    hits: int = 1  # observed frequency (e.g. sightings / events)
    geo: Optional[Geo] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    tags: List[str] = []
    # False positive & allowlist protection
    is_allowlisted: bool = False
    is_false_positive: bool = False
    fp_reason: Optional[str] = None


class CVE(BaseModel):
    cve_id: str
    cvss: float = 0.0
    severity: str = "medium"
    affected_product: str = "unknown"
    description: str = ""
    published: Optional[str] = None
    # CISA KEV fields
    in_kev: bool = False
    kev_date_added: Optional[str] = None
    ransomware_campaign: bool = False
    required_action: Optional[str] = None
    due_date: Optional[str] = None
    cwes: List[str] = []
    # EPSS (Exploit Prediction Scoring System)
    epss: float = 0.0
    epss_percentile: float = 0.0


class Asset(BaseModel):
    name: str
    ip: Optional[str] = None
    products: List[str] = []
    importance: int = Field(50, ge=0, le=100)


class AllowlistItem(BaseModel):
    id: Optional[str] = None
    indicator: str
    indicator_type: str = "ip"  # ip, cidr, domain
    reason: str = "Legitimate infrastructure / CDN"
    added_at: Optional[str] = None


class FalsePositiveRequest(BaseModel):
    reason: str = "Legitimate CDN or verified false alarm"
    penalize_source: bool = True


class LogMatchRequest(BaseModel):
    log_text: Optional[str] = None
    log_format: str = "auto"  # auto, suricata, zeek, wazuh, firewall


class AnalyzeRequest(BaseModel):
    id: Optional[str] = None
    indicator: Optional[str] = None
    use_ai: bool = True


class ImportBundle(BaseModel):
    threats: List[dict] = []
    cves: List[dict] = []
    assets: List[dict] = []
    allowlist: List[dict] = []
