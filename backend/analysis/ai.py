"""AI analyst: explains already-correlated intelligence using a local Ollama model.

The LLM never decides the risk — it only narrates the evidence the rules engine produced.
Falls back to a deterministic template if Ollama is not running.
"""
import os

import httpx

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")


def build_prompt(threat: dict, a: dict) -> str:
    techs = ", ".join(f"{t['id']} ({t['name']})" for t in a["attack_techniques"]) or "none"
    cves = ", ".join(f"{c['cve_id']} CVSS {c['cvss']} {c['affected_product']}" for c in a["related_cves"]) or "none"
    assets = ", ".join(x["name"] for x in a["exposed_assets"]) or "none"
    return f"""You are a cybersecurity threat analyst.

Analyze ONLY the following correlated threat intelligence:

Indicator: {threat['indicator']} ({threat['indicator_type']})
Confidence: {threat['confidence']}
Computed risk score: {a['risk_score']}/100 ({a['severity'].upper()})
Related malware: {threat.get('malware') or 'none'}
Campaign: {threat.get('campaign') or 'none'}
MITRE techniques: {techs}
Related CVEs: {cves}
Exposed internal assets: {assets}
Rules triggered: {'; '.join(a['rules_triggered']) or 'none'}

Provide these sections, using exactly these headings:
THREAT SUMMARY
ATTACK SCENARIO
MITRE TECHNIQUES INVOLVED
RISK EXPLANATION
RECOMMENDED ACTIONS

Do not invent indicators, vulnerabilities, malware or techniques that are not listed above.
Infrastructure location is not attacker attribution. Be concise."""


def template_analysis(threat: dict, a: dict) -> str:
    chain = " -> ".join(s["label"] for s in a["attack_chain"]) or "not enough data"
    techs = "\n".join(f"- {t['id']} {t['name']} ({t['tactic']})" for t in a["attack_techniques"]) or "- none"
    recs = "\n".join(f"{i}. {r}" for i, r in enumerate(a["recommendations"], 1))
    cve_txt = (", ".join(c["cve_id"] for c in a["related_cves"])) or "no linked CVEs"
    return f"""THREAT SUMMARY
{threat['indicator']} is flagged as malicious infrastructure ({threat['confidence']}% confidence){f" associated with {threat['malware']}" if threat.get('malware') else ''}{f" and the campaign '{threat['campaign']}'" if threat.get('campaign') else ''}.

ATTACK SCENARIO
Observed behaviour maps to the kill chain: {chain}. Related vulnerabilities: {cve_txt}.

MITRE TECHNIQUES INVOLVED
{techs}

RISK EXPLANATION
Risk score {a['risk_score']}/100 ({a['severity'].upper()}). {' '.join(a['rules_triggered'])}

RECOMMENDED ACTIONS
{recs}"""


def analyze(threat: dict, analysis: dict, use_ai: bool = True) -> dict:
    if use_ai:
        try:
            r = httpx.post(f"{OLLAMA_URL}/api/generate", timeout=120, json={
                "model": OLLAMA_MODEL, "prompt": build_prompt(threat, analysis),
                "stream": False, "options": {"temperature": 0.2}})
            r.raise_for_status()
            return {"text": r.json()["response"].strip(), "source": f"ollama:{OLLAMA_MODEL}"}
        except Exception:  # noqa: BLE001
            pass
    return {"text": template_analysis(threat, analysis), "source": "template (Ollama offline)"}
