"""MITRE ATT&CK helper.

Ships an embedded subset of Enterprise ATT&CK techniques so the demo works
offline. `fetch_full()` can pull the complete STIX bundle from MITRE's CTI repo.
"""
import httpx

# Kill-chain ordering of ATT&CK tactics
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

TACTIC_LABEL = {t: t.replace("-", " ").title() for t in TACTIC_ORDER}

TECHNIQUES = {
    "T1566": {"name": "Phishing", "tactic": "initial-access"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial-access"},
    "T1078": {"name": "Valid Accounts", "tactic": "initial-access"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "execution"},
    "T1204": {"name": "User Execution", "tactic": "execution"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "persistence"},
    "T1055": {"name": "Process Injection", "tactic": "defense-evasion"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "credential-access"},
    "T1082": {"name": "System Information Discovery", "tactic": "discovery"},
    "T1021": {"name": "Remote Services", "tactic": "lateral-movement"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "command-and-control"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "command-and-control"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "exfiltration"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "exfiltration"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "impact"},
}


def technique_info(tid: str) -> dict:
    t = TECHNIQUES.get(tid, {"name": "Unknown technique", "tactic": "unknown"})
    return {"id": tid, "name": t["name"], "tactic": t["tactic"],
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"}


def build_attack_chain(technique_ids):
    """Order techniques along the ATT&CK kill chain. Returns list of stages."""
    stages = {}
    for tid in technique_ids:
        info = technique_info(tid)
        stages.setdefault(info["tactic"], []).append(info)
    chain = []
    for tactic in TACTIC_ORDER:
        if tactic in stages:
            chain.append({"tactic": tactic, "label": TACTIC_LABEL[tactic],
                          "techniques": stages[tactic]})
    return chain


def chain_strength(chain) -> int:
    """Number of *consecutive-ish* kill-chain stages covered (gaps of <=1 allowed)."""
    idx = sorted(TACTIC_ORDER.index(s["tactic"]) for s in chain)
    if not idx:
        return 0
    best = run = 1
    for a, b in zip(idx, idx[1:]):
        run = run + 1 if b - a <= 2 else 1
        best = max(best, run)
    return best


def fetch_full():
    """Optional: download the full Enterprise ATT&CK STIX bundle and merge it in."""
    url = ("https://raw.githubusercontent.com/mitre/cti/master/"
           "enterprise-attack/enterprise-attack.json")
    r = httpx.get(url, timeout=60, follow_redirects=True)
    r.raise_for_status()
    added = 0
    for obj in r.json().get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid = next((e["external_id"] for e in obj.get("external_references", [])
                    if e.get("source_name") == "mitre-attack"), None)
        phases = obj.get("kill_chain_phases") or []
        if tid and phases:
            TECHNIQUES[tid] = {"name": obj["name"], "tactic": phases[0]["phase_name"]}
            added += 1
    return added
