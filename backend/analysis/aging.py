"""Indicator Aging & Decay Engine.

Models time-decay of threat intelligence indicators:
- IP addresses are dynamic (DHCP / CDN / VPS reassignments): 7-day half-life.
- URLs (phishing landing pages / malicious redirects): 14-day half-life.
- Domains (C2 / bulletproof DNS): 30-day half-life.
- File Hashes (malware binaries): 180-day half-life.

Formulas:
  decay_factor = 0.5 ** (age_days / half_life)
  aged_confidence = initial_confidence * decay_factor
"""
from datetime import datetime, timezone
from typing import Optional

HALF_LIVES_DAYS = {
    "ip": 7,
    "url": 14,
    "domain": 30,
    "hash": 180,
}


def _parse_iso(dt_str: Optional[str]) -> datetime:
    if not dt_str:
        return datetime.now(timezone.utc)
    try:
        # Normalize trailing Z
        s = dt_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.now(timezone.utc)


def compute_aging(threat: dict, as_of: Optional[datetime] = None) -> dict:
    """Computes age, decay factor, aged confidence, and lifecycle status for a threat."""
    now = as_of or datetime.now(timezone.utc)
    seen_str = threat.get("last_seen") or threat.get("first_seen")
    seen_dt = _parse_iso(seen_str)

    delta_sec = (now - seen_dt).total_seconds()
    age_days = max(0.0, delta_sec / 86400.0)

    itype = str(threat.get("indicator_type", "ip")).lower()
    half_life = HALF_LIVES_DAYS.get(itype, 14)

    decay_factor = 0.5 ** (age_days / half_life)
    initial_conf = int(threat.get("confidence", 50))

    # If marked false positive, confidence drops to 5 immediately
    if threat.get("is_false_positive"):
        aged_conf = 5
    else:
        aged_conf = max(5, min(100, int(round(initial_conf * decay_factor))))

    if age_days <= half_life:
        status = "active"
    elif age_days <= 2 * half_life:
        status = "aging"
    elif age_days <= 3 * half_life:
        status = "stale"
    else:
        status = "expired"

    expires_in = max(0, int(round((3 * half_life) - age_days)))

    return {
        "age_days": round(age_days, 1),
        "half_life_days": half_life,
        "decay_factor": round(decay_factor, 3),
        "initial_confidence": initial_conf,
        "aged_confidence": aged_conf,
        "status": status,
        "is_stale": status in ("stale", "expired"),
        "expires_in_days": expires_in,
    }
