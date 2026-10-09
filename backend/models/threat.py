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
    tags: List[str] = []


class CVE(BaseModel):
    cve_id: str
    cvss: float = 0.0
    severity: str = "medium"
    affected_product: str = "unknown"
    description: str = ""
    published: Optional[str] = None


class Asset(BaseModel):
    name: str
    ip: Optional[str] = None
    products: List[str] = []
    importance: int = Field(50, ge=0, le=100)


class AnalyzeRequest(BaseModel):
    id: Optional[str] = None
    indicator: Optional[str] = None
    use_ai: bool = True


class ImportBundle(BaseModel):
    threats: List[dict] = []
    cves: List[dict] = []
    assets: List[dict] = []
