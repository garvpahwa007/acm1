"""URL orchestrator: lexical -> infrastructure -> reputation -> click preview.

Two speeds on purpose:
  analyze_quick()  ~5ms, no network      -> instant verdict while the user waits
  analyze_full()   ~2-12s, progressive   -> corroborated verdict, then evidence
"""
from __future__ import annotations

import hashlib
import re
from concurrent.futures import ThreadPoolExecutor

from . import data as D
from . import intel, lexical, net, store, verdict
from .lexical import sig


def analyze_quick(raw_url: str) -> dict:
    lex = lexical.analyze_url(raw_url)
    facts = lex["facts"]
    tier_guess = _tier_of(lex["signals"])
    baseline = store.observe_domain(facts.get("registrable_domain", ""), tier_guess) \
        if facts.get("registrable_domain") else {}
    signals = list(lex["signals"])
    if baseline.get("first_contact") and facts.get("registrable_domain"):
        signals.append(sig("first_contact", "First time this domain has been seen here",
                           "info", 5,
                           f"No prior mail or link in this workspace used "
                           f"'{facts['registrable_domain']}'. Novelty alone is not proof, "
                           "but it removes the benefit of the doubt.",
                           category="baseline"))
    v = verdict.judge(signals, intel_ok=False, channel="url",
                      intel_notes=["lexical pass only — infrastructure data not yet fetched"])
    v["facts"] = _public_facts(facts)
    v["speed"] = "quick"
    return v


def analyze_full(raw_url: str, do_preview: bool = True) -> dict:
    lex = lexical.analyze_url(raw_url)
    facts = lex["facts"]
    signals = list(lex["signals"])
    notes: list[str] = []
    if lex.get("error"):
        notes.append(lex["error"])

    host = facts.get("host", "")
    rd = facts.get("registrable_domain", "")
    ip_like = facts.get("is_ip")

    # ---- infrastructure, fetched in parallel so total latency stays ~1 RTT ----
    infra = {}
    if host and not ip_like:
        with ThreadPoolExecutor(max_workers=3) as pool:
            f_dns = pool.submit(net.dns_facts, rd)
            f_rdap = pool.submit(net.rdap_facts, rd)
            f_tls = pool.submit(net.tls_facts, host)
            infra = {"dns": f_dns.result(), "rdap": f_rdap.result(),
                     "tls": f_tls.result()}
        signals.extend(_infra_signals(infra, facts))
        intel_ok = infra["rdap"].get("ok") or infra["dns"].get("resolves")
        if not infra["dns"].get("resolves"):
            notes.append("domain did not resolve at scan time — could be dormant "
                         "and armed later (time-of-click risk)")
    else:
        intel_ok = False
        notes.append("raw IP host: no registration/DNS metadata to correlate")

    # ---- reputation feeds ---------------------------------------------------
    rep_sigs, rep_notes, rep_ok = [], [], False
    with ThreadPoolExecutor(max_workers=2) as pool:
        f_gsb = pool.submit(intel.safe_browsing, facts.get("input", raw_url))
        f_vt = pool.submit(intel.virustotal_url, raw_url)
        for res, label in ((f_gsb.result(), "gsb"), (f_vt.result(), "vt")):
            rep_notes.append(res.get("note", ""))
            rep_ok = rep_ok or res.get("ok", False)
            if res.get("hit"):
                rep_sigs.append(sig(
                    f"intel_{label}", f"Listed as malicious by {label.upper()}",
                    "critical", 50,
                    f"{res.get('note')} — an independent reputation feed already "
                    "classifies this URL as hostile.",
                    category="reputation"))
    signals.extend(rep_sigs)
    notes.extend([n for n in rep_notes if n])

    # ---- what happens if you click -----------------------------------------
    preview = None
    if do_preview and host:
        preview = net.fetch_page(raw_url if "://" in raw_url else "http://" + raw_url)
        if preview.get("error"):
            notes.append(f"preview: {preview['error']}")
        signals.extend(_preview_signals(preview, facts))

    # ---- org baseline + time-of-click --------------------------------------
    tier_guess = _tier_of(signals)
    baseline = store.observe_domain(rd, tier_guess) if rd else {}
    if baseline.get("first_contact") and rd:
        signals.append(sig("first_contact", "First time this domain has been seen here",
                           "info", 5,
                           f"No prior mail or link in this workspace used '{rd}'.",
                           category="baseline"))

    content_hash = _content_hash(preview)
    snap = store.check_url_snapshot(lexical.normalize_for_key(raw_url), 0, tier_guess,
                                    content_hash) if rd else {}

    # ---- judge --------------------------------------------------------------
    preview_ok = bool(preview and preview.get("ok"))
    # A shortener hides where you are going. If we could not expand it, the honest
    # answer is "unknown", not a green tick.
    force_unknown = bool(facts.get("shortener")) and not preview_ok
    if force_unknown:
        signals.append(sig("unresolved_destination",
                           "Shortened link could not be expanded", "high", 22,
                           "The real destination is hidden and we could not resolve it. "
                           "An unexpanded short link is unverifiable by construction.",
                           category="infrastructure"))
        notes.append("shortener not expanded — verdict intentionally degraded to 'unknown'")
    v = verdict.judge(signals, intel_ok=bool(intel_ok or rep_ok), intel_notes=notes,
                      channel="url", force_unknown=force_unknown)
    v["score"] = verdict.score_signals(v["signals"])  # recompute post-snapshot

    if snap.get("previously_clean_now_bad"):
        v["signals"].append(sig("link_changed", "This link has changed since we first saw it",
                                "high", 24,
                                "It was clean when first observed here and is now "
                                "suspicious — the time-of-click attack pattern.",
                                category="baseline"))
        v = verdict.judge(v["signals"], intel_ok=True, intel_notes=notes, channel="url")
    elif snap.get("content_changed"):
        notes.append("page content changed since first observation")

    v["facts"] = _public_facts(facts, infra, baseline, snap)
    v["preview"] = _public_preview(preview, facts) if preview else None
    v["speed"] = "full"
    v["receipt_id"] = store.save_receipt(facts.get("defanged") or raw_url,
                                         verdict.build_receipt(v, facts.get("defanged") or raw_url))
    return v


# ------------------------------------------------------------------ helpers -
def _infra_signals(infra: dict, facts: dict) -> list[dict]:
    out: list[dict] = []
    rdap = infra.get("rdap") or {}
    dns = infra.get("dns") or {}
    tls = infra.get("tls") or {}
    rd = facts.get("registrable_domain", "")
    brand = facts.get("brand_impersonated")

    age = rdap.get("age_days")
    if age is not None:
        if age <= 7:
            out.append(sig("domain_age", f"Domain registered {age} day(s) ago",
                           "critical", 34,
                           f"'{rd}' was registered on {rdap.get('registered')} via "
                           f"{rdap.get('registrar') or 'an unknown registrar'}. "
                           "Almost no legitimate brand or vendor domain is this new.",
                           category="infrastructure"))
        elif age <= 30:
            out.append(sig("domain_age", f"Domain only {age} days old", "high", 26,
                           f"'{rd}' registered {rdap.get('registered')} — inside the "
                           "window where phishing infrastructure is normally burned.",
                           category="infrastructure"))
        elif age <= 90:
            out.append(sig("domain_age", f"Domain only {age} days old", "medium", 15,
                           f"'{rd}' registered {rdap.get('registered')}.",
                           category="infrastructure"))
        elif age > 365 * 12:
            out.append(sig("domain_mature", f"Domain aged {age // 365} years",
                           "info", 0,
                           f"'{rd}' has existed since {rdap.get('registered')} — a mild "
                           "point in its favour (aged domains are also bought, so not proof).",
                           category="infrastructure"))

    if rd and not dns.get("resolves") and not dns.get("error"):
        out.append(sig("no_resolve", "Domain does not resolve right now", "medium", 16,
                       f"'{rd}' has no A record at scan time. Dormant domains get armed "
                       "later; a link that fails today can work tomorrow.",
                       category="infrastructure"))

    if brand and not dns.get("mx") and not dns.get("error"):
        out.append(sig("no_mx", "Claims a brand but receives no mail", "medium", 12,
                       f"'{rd}' has no MX record, so it cannot be the real "
                       f"{brand} mail domain.",
                       category="infrastructure"))
    if brand and not dns.get("dmarc") and not dns.get("error"):
        out.append(sig("no_dmarc", "No DMARC policy on a brand-claiming domain",
                       "low", 7,
                       f"'{rd}' publishes no DMARC record — typical of a lookalike "
                       "registered for a single campaign.",
                       category="infrastructure"))

    if tls.get("error") and "cert" in (tls.get("error") or ""):
        out.append(sig("bad_cert", "TLS certificate does not validate", "high", 20,
                       f"{tls['error']}. A credential page with an invalid certificate "
                       "is either misconfigured or not the site it claims to be.",
                       category="infrastructure"))
    elif tls.get("not_before_days") is not None and tls["not_before_days"] <= 7:
        out.append(sig("new_cert", f"TLS certificate issued {tls['not_before_days']} day(s) ago",
                       "low", 8,
                       f"Certificate issuer {tls.get('issuer')} — free DV certs are "
                       "instant and routinely used on phishing kits.",
                       category="infrastructure"))
    return out


def _preview_signals(preview: dict, facts: dict) -> list[dict]:
    out: list[dict] = []
    if not preview.get("ok"):
        return out
    base_host = facts.get("host", "")
    ext = preview.get("external_form_actions") or []
    same_site_pw = [f for f in preview.get("forms", [])
                    if f.get("has_password") and not f.get("is_external")]

    for form in ext:
        out.append(sig("password_form_external",
                       "Password form submits to a DIFFERENT domain",
                       "critical", 40,
                       f"The page at '{base_host}' contains a password field whose form "
                       f"POSTs to '{form['host']}'. That is credential harvesting: the "
                       "site is only a skin over someone else's collection endpoint.",
                       category="content"))
    if same_site_pw and not ext:
        out.append(sig("password_form_same_site", "Login form present",
                       "low", 8,
                       "The page asks for a password. Not malicious on its own — but "
                       "confirm the domain before typing anything.",
                       category="content"))

    title = (preview.get("title") or "")
    brand = facts.get("brand_impersonated")
    skel_title = lexical.skeleton(title)
    if brand and brand in skel_title and brand not in lexical.skeleton(base_host):
        out.append(sig("title_brand_mismatch",
                       f"Page claims to be '{brand.title()}' but is hosted on '{base_host}'",
                       "high", 28,
                       f"<title> reads “{title[:80]}” while the domain is "
                       f"'{facts.get('registrable_domain')}'. The text of a page is free; "
                       "the domain is not.",
                       category="content"))

    for target in (preview.get("js_redirects") or []) + _from_meta(preview):
        tgt_host = net.urlsplit(target).hostname or ""
        if tgt_host and not tgt_host.endswith(base_host):
            out.append(sig("redirect_offsite", "Auto-redirect to another host",
                           "medium", 14,
                           f"Page forwards to '{tgt_host}' without a click — used to swap "
                           "a benign scanner view for the hostile payload.",
                           category="content"))
            break
    return out


def _from_meta(preview: dict) -> list[str]:
    meta = preview.get("meta_refresh") or ""
    m = re.search(r"url\s*=\s*([^\s;\"']+)", meta, re.I)
    return [m.group(1)] if m else []


def _content_hash(preview: dict | None) -> str:
    if not preview:
        return ""
    blob = "|".join([
        str(preview.get("title")), str(preview.get("status")),
        ",".join(f.get("action", "") for f in preview.get("forms", [])),
        str(preview.get("html_snippet"))[:300],
    ])
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _tier_of(signals: list[dict]) -> str:
    s = verdict.score_signals(signals)
    return ("malicious" if s >= verdict.THRESHOLDS["malicious"]
            else "suspicious" if s >= verdict.THRESHOLDS["suspicious"]
            else "low" if s >= verdict.THRESHOLDS["low"] else "safe")


def _public_facts(facts: dict, infra: dict | None = None,
                  baseline: dict | None = None, snap: dict | None = None) -> dict:
    out = {
        "defanged": facts.get("defanged"),
        "host": facts.get("host"),
        "display_host": facts.get("display_host"),
        "registrable_domain": facts.get("registrable_domain"),
        "public_suffix": facts.get("public_suffix"),
        "scheme": facts.get("scheme"),
        "subdomain_depth": facts.get("subdomain_depth"),
        "is_ip": facts.get("is_ip"),
        "idn": facts.get("idn"),
        "shortener": facts.get("shortener"),
        "brand_impersonated": facts.get("brand_impersonated"),
        "path": facts.get("path"),
    }
    if infra:
        rdap = infra.get("rdap") or {}
        dns = infra.get("dns") or {}
        tls = infra.get("tls") or {}
        out["registration"] = {
            "registered": rdap.get("registered"), "age_days": rdap.get("age_days"),
            "registrar": rdap.get("registrar"), "ok": rdap.get("ok"),
            "error": rdap.get("error"),
        }
        out["dns"] = {"resolves": dns.get("resolves"), "a": (dns.get("a") or [])[:4],
                      "mx": (dns.get("mx") or [])[:4], "ns": (dns.get("ns") or [])[:3],
                      "spf": dns.get("spf"), "dmarc": dns.get("dmarc"),
                      "error": dns.get("error")}
        out["tls"] = tls
    if baseline is not None:
        out["baseline"] = baseline
    if snap:
        out["time_of_click"] = snap
    return out


def _public_preview(preview: dict | None, facts: dict) -> dict | None:
    if not preview:
        return None
    return {
        "ok": preview.get("ok"),
        "status": preview.get("status"),
        "final_url_defanged": lexical.defang(preview.get("final_url") or ""),
        "chain": [lexical.defang(u) for u in (preview.get("chain") or [])],
        "redirect_hops": max(0, len(preview.get("chain") or []) - 1),
        "title": preview.get("title"),
        "text_snippet": preview.get("html_snippet"),
        "forms": [{k: f.get(k) for k in ("action_host", "method", "has_password",
                                         "is_external", "fields")}
                  for f in (preview.get("forms") or [])][:5],
        "external_form_actions": preview.get("external_form_actions") or [],
        "meta_refresh": preview.get("meta_refresh"),
        "js_redirects": [lexical.defang(u) for u in (preview.get("js_redirects") or [])],
        "error": preview.get("error"),
        "disclaimer": "Rendered server-side in a sandbox with JavaScript disabled. "
                      "Nothing was typed, submitted or stored.",
    }
