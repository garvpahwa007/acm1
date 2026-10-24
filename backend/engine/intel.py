"""Third-party reputation lookups. All optional, all degrading to 'not configured'.

Deliberately BYO-key: the app is fully useful without paying anyone, and gets
strictly better when the operator supplies keys. That undercuts SaaS pricing.
"""
from __future__ import annotations

import hashlib
import os

import requests

TIMEOUT = (4, 8)
GSB_KEY = os.environ.get("GSB_API_KEY", "").strip()
VT_KEY = os.environ.get("VT_API_KEY", "").strip()
URLSCAN_KEY = os.environ.get("URLSCAN_API_KEY", "").strip()


def configured() -> dict:
    return {"safe_browsing": bool(GSB_KEY), "virustotal": bool(VT_KEY),
            "urlscan": bool(URLSCAN_KEY)}


def safe_browsing(url: str) -> dict:
    """Google Safe Browsing v4 threatMatches:find."""
    if not GSB_KEY:
        return {"ok": False, "configured": False, "hit": False,
                "note": "Safe Browsing key not configured (set GSB_API_KEY)"}
    body = {
        "client": {"clientId": "phishguard", "clientVersion": "0.9.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = requests.post("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                          params={"key": GSB_KEY}, json=body, timeout=TIMEOUT)
        r.raise_for_status()
        matches = r.json().get("matches", [])
        return {"ok": True, "configured": True, "hit": bool(matches),
                "threats": sorted({m.get("threatType") for m in matches}),
                "note": "Safe Browsing: " + ("MATCH" if matches else "no match")}
    except Exception as exc:
        return {"ok": False, "configured": True, "hit": False,
                "note": f"Safe Browsing unavailable ({type(exc).__name__})"}


def virustotal_url(url: str) -> dict:
    """VT v3: submit-free lookup by URL id. 404 = never seen (a weak signal)."""
    if not VT_KEY:
        return {"ok": False, "configured": False, "hit": False,
                "note": "VirusTotal key not configured (set VT_API_KEY)"}
    import base64
    uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{uid}",
                         headers={"x-apikey": VT_KEY}, timeout=TIMEOUT)
        if r.status_code == 404:
            return {"ok": True, "configured": True, "hit": False, "never_seen": True,
                    "note": "VirusTotal: URL never submitted (no history either way)"}
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        bad = stats.get("malicious", 0) + stats.get("suspicious", 0)
        return {"ok": True, "configured": True, "hit": bad > 0, "stats": stats,
                "note": f"VirusTotal: {bad} engines flagged "
                        f"({stats.get('malicious',0)} malicious, {stats.get('suspicious',0)} suspicious)"}
    except Exception as exc:
        return {"ok": False, "configured": True, "hit": False,
                "note": f"VirusTotal unavailable ({type(exc).__name__})"}


def virustotal_hash(sha256: str) -> dict:
    if not VT_KEY:
        return {"ok": False, "configured": False, "hit": False,
                "note": "VirusTotal key not configured"}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}",
                         headers={"x-apikey": VT_KEY}, timeout=TIMEOUT)
        if r.status_code == 404:
            return {"ok": True, "configured": True, "hit": False, "never_seen": True,
                    "note": "VirusTotal: attachment hash never seen before"}
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        bad = stats.get("malicious", 0) + stats.get("suspicious", 0)
        return {"ok": True, "configured": True, "hit": bad > 0, "stats": stats,
                "note": f"VirusTotal: {bad} engines flagged this file"}
    except Exception as exc:
        return {"ok": False, "configured": True, "hit": False,
                "note": f"VirusTotal unavailable ({type(exc).__name__})"}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
