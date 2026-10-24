"""Turn a pile of signals into a defensible verdict.

Two rules that make this different from a risk-score slider:
  1. Every verdict carries an evidence chain (what fired, why, how confident).
  2. 'Unknown' is a first-class outcome. Ambiguity is reported, not smoothed over.
"""
from __future__ import annotations

from datetime import datetime, timezone

ENGINE_VERSION = "0.9.0"
THRESHOLDS = {"malicious": 65, "suspicious": 30, "low": 12}

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Diminishing returns: one critical signal should not be diluted by ten weak ones,
# and ten weak ones should not add up to a critical verdict on their own.
DECAY = (1.0, 0.75, 0.6, 0.5, 0.45, 0.4, 0.35, 0.3, 0.25, 0.2)


def score_signals(signals: list[dict]) -> int:
    if not signals:
        return 0
    ordered = sorted(signals, key=lambda s: (SEV_ORDER.get(s["severity"], 0), s["weight"]),
                     reverse=True)
    total = 0.0
    for i, s in enumerate(ordered):
        total += s["weight"] * (DECAY[i] if i < len(DECAY) else 0.15)
    # a critical signal alone must be able to reach 'malicious'
    if ordered and ordered[0]["severity"] == "critical":
        total = max(total, ordered[0]["weight"])
    return int(min(100, round(total)))


def judge(signals: list[dict], *, intel_ok: bool, intel_notes: list[str] | None = None,
          channel: str = "url", force_unknown: bool = False) -> dict:
    """Aggregate signals -> verdict object."""
    intel_notes = intel_notes or []
    score = score_signals(signals)
    crit = [s for s in signals if s["severity"] == "critical"]
    high = [s for s in signals if s["severity"] == "high"]
    indep_cats = {s["category"] for s in signals}
    corroborated = len(indep_cats) >= 2 and (len(crit) + len(high)) >= 2

    if score >= THRESHOLDS["malicious"]:
        tier = "malicious"
    elif score >= THRESHOLDS["suspicious"]:
        tier = "suspicious"
    elif score >= THRESHOLDS["low"]:
        tier = "low"
    else:
        tier = "safe"

    # --- confidence --------------------------------------------------------
    if crit and corroborated and intel_ok:
        confidence = "high"
    elif crit or (len(high) >= 2 and intel_ok):
        confidence = "medium" if intel_ok else "low"
    elif intel_ok and len(signals) <= 1:
        confidence = "medium"
    else:
        confidence = "low"
    if not intel_ok:
        confidence = "low" if confidence != "low" else "low"

    # --- the honest 'unknown' ---------------------------------------------
    # If we could not corroborate with infrastructure data and the score is
    # middling, refusing to answer is the correct answer.
    # "Unknown" is for THIN evidence, not for uncorroborated-but-decisive evidence.
    # A critical/high signal (a typosquat, a DMARC fail) still names the tier at low
    # confidence while the network corroboration streams in. Refusing to tier it
    # would make the instant verdict look like it had no opinion at all.
    decisive = bool(crit or high)
    unknown = (not intel_ok) and not decisive and tier in ("safe", "low") and score >= 8

    if tier == "malicious":
        label, headline = "malicious", "Do not click or reply"
    elif tier == "suspicious":
        label = "unknown" if (unknown and confidence == "low") else "suspicious"
        headline = ("Unverified — treat as hostile until confirmed"
                    if label == "unknown" else "Treat as hostile until proven otherwise")
    elif tier == "low":
        label = "unknown" if unknown else "likely_safe"
        headline = "Could not fully verify — verify out of band" if unknown else "Nothing conclusive found"
    else:
        label = "unknown" if unknown else "likely_safe"
        headline = "Not enough data to clear it" if unknown else "Nothing suspicious found"

    if force_unknown and tier in ("safe", "low", "suspicious"):
        label = "unknown"
        headline = "Destination not verified — do not trust the presentation"

    explain = _explain(signals, score, tier)
    return {
        "engine_version": ENGINE_VERSION,
        "channel": channel,
        "score": score,
        "tier": tier,
        "label": label,
        "headline": headline,
        "confidence": confidence,
        "confidence_text": _confidence_text(score, confidence),
        "intel_ok": intel_ok,
        # A verdict produced before corroboration is provisional: the UI says
        # "verifying", not "cleared" or "unknown".
        "provisional": not intel_ok,
        "intel_notes": intel_notes,
        "explain": explain,
        "signals": sorted(signals, key=lambda s: (SEV_ORDER.get(s["severity"], 0),
                                                  s["weight"]), reverse=True),
        "counts": {sev: sum(1 for s in signals if s["severity"] == sev)
                   for sev in ("critical", "high", "medium", "low", "info")},
        "tips": _tips(signals),
        "next_steps": _next_steps(label, channel),
        "out_of_band": _out_of_band(signals, channel),
        "blast_radius": _blast_radius(signals),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "thresholds": THRESHOLDS,
        "receipt_id": None,  # filled by caller after persisting
    }


def _confidence_text(score: int, confidence: str) -> str:
    """Express confidence in the VERDICT, as a range.

    Deliberately not derived from the risk score: "risk 20/100" and "80% sure" are
    different quantities, and arithmetic mixing them produced nonsense ranges like
    "55–15% likely correct". These bands describe evidential strength only.
    """
    bands = {
        "high": ("85–95%", "corroborated by independent signal categories"),
        "medium": ("65–85%", "limited corroboration"),
        "low": ("45–65%", "insufficient corroboration — do not treat as a clearance"),
    }
    pct, why = bands.get(confidence, bands["low"])
    return f"{pct} confident ({why})"


def _explain(signals, score, tier) -> str:
    if not signals:
        return ("No lexical, infrastructure or content indicators fired. "
                "That is a weak positive, not a guarantee — absence of evidence "
                "is not evidence of safety.")
    top = sorted(signals, key=lambda s: s["weight"], reverse=True)[:3]
    parts = ", ".join(s["title"].lower() for s in top)
    return (f"Score {score}/100. Decisive factors: {parts}. "
            f"{len(signals)} signal(s) across {len({s['category'] for s in signals})} "
            "independent categories; agreement across categories is what raises confidence.")


def _tips(signals) -> list[str]:
    seen, out = set(), []
    for s in sorted(signals, key=lambda s: s["weight"], reverse=True):
        if s.get("tip") and s["tip"] not in seen:
            seen.add(s["tip"])
            out.append(s["tip"])
    return out[:4]


def _next_steps(label: str, channel: str) -> list[str]:
    if label == "malicious":
        base = ["Do not click, reply, or enter any credentials.",
                "Report it in one tap so everyone else who got it is protected.",
                "If you already clicked: go to the Post-click step and work the checklist."]
    elif label == "suspicious":
        base = ["Do not act on it from this message.",
                "Reach the sender through a channel you already had — not the one in the message.",
                "Report it so the org-wide sweep can cluster it."]
    elif label == "unknown":
        base = ["Do not act yet — we could not confirm either way.",
                "Verify out of band with the challenge below.",
                "If it involves money or credentials, treat it as hostile until confirmed."]
    else:
        base = ["Nothing suspicious found, but stay with your normal habits.",
                "Still confirm unexpected payment or credential requests out of band.",
                "If it felt wrong, report it — your instinct is data we can use."]
    if channel == "email":
        base.append("Check the real sender address, not the display name.")
    return base


def _out_of_band(signals, channel) -> dict:
    """A generated verification script — the antidote to 'urgent'."""
    ids = {s["id"] for s in signals}
    if "bec_bank_change" in ids or "phone_payment" in ids:
        q = ("Call the vendor on the number from your own records (contract or last "
             "known invoice) and ask them to read back the account number. Do not "
             "use a number printed in this message.")
    elif ids & {"bec_credential", "credential", "password_form_external", "india_kyc"}:
        q = ("Open the service by typing its address yourself (or via your saved "
             "bookmark), sign in there, and check for alerts. Never sign in from a "
             "link in a message.")
    elif "bec_giftcard" in ids:
        q = "Ask the requester, on a known number, to confirm the request in person. No legitimate payment is gift cards."
    else:
        q = ("Forward this to the person via a separate channel and ask one specific "
             "question only they could answer about it (an old reference number, a "
             "prior conversation).")
    return {"question": q, "principle": "Urgency is the attack. One out-of-band call defeats almost all of it."}


def _blast_radius(signals) -> dict:
    """What happens if you click — the part users actually understand."""
    ids = {s["id"] for s in signals}
    if ids & {"password_form_external"}:
        return {"risk": "credential_theft",
                "summary": "This page takes a password and sends it to a different "
                           "domain than the one you'd be looking at.",
                "consequence": "Your credentials are captured in real time, then you are "
                               "usually redirected to the genuine site so nothing looks wrong."}
    if ids & {"password_form_same_site", "credential"}:
        return {"risk": "credential_capture",
                "summary": "A login form was found on the page.",
                "consequence": "Anything typed in — password, OTP, card number — is in "
                               "the attacker's hands."}
    if ids & {"dangerous_ext", "downloadable", "attachment_macro"}:
        return {"risk": "malware",
                "summary": "Clicking downloads and/or runs a file.",
                "consequence": "Executables and macro documents can install remote-access "
                               "tooling; that is how ransomware starts."}
    if ids & {"upi_collect", "bec_bank_change", "phone_payment", "india_upi"}:
        return {"risk": "payment_fraud",
                "summary": "The flow ends at a payment or account-detail change.",
                "consequence": "Money moves to an attacker-controlled account and is "
                               "typically unrecoverable after ~24h."}
    if ids & {"bec_urgency", "too_good"}:
        return {"risk": "manipulation",
                "summary": "The message is engineered to make you act before checking.",
                "consequence": "The harm is a decision made under time pressure, not a payload."}
    return {"risk": "low", "summary": "No active-content or credential-capture path detected.",
            "consequence": "Residual risk is what we could not observe, not what we cleared."}


def build_receipt(verdict: dict, subject: str) -> dict:
    """Reproducible evidence chain for incident review / SOAR."""
    return {
        "receipt_id": verdict.get("receipt_id"),
        "engine_version": ENGINE_VERSION,
        "generated_at": verdict["generated_at"],
        "subject": subject,
        "verdict": {k: verdict[k] for k in ("label", "tier", "score", "confidence",
                                            "headline", "intel_ok")},
        "thresholds_applied": THRESHOLDS,
        "scoring": "weighted severity-sum with positional decay; critical signal can stand alone",
        "signals": [{"id": s["id"], "severity": s["severity"], "weight": s["weight"],
                     "category": s["category"], "evidence": s["evidence"]}
                    for s in verdict["signals"]],
        "intel_notes": verdict["intel_notes"],
        "note": "Reproducible: same input + same engine_version + same signal set yields this score.",
    }
