"""Email (.eml) forensics: authentication, header anomalies, BEC language,
India scam corpus, attachments, and link extraction.

Header work is done on the real message bytes so DKIM can be verified properly.
Links are scored lexically here (fast); the UI drills into any link for a full
network + click-preview analysis on demand.
"""
from __future__ import annotations

import hashlib
import io
import re
import zipfile
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser

from . import data as D
from . import lexical, store, verdict
from .lexical import sig, defang

MAX_LINKS = 25
BODY_SCAN_CHARS = 20000


# ------------------------------------------------------------ html parsing --
class _LinkGrab(HTMLParser):
    """Collect anchors with their visible text (for display/href mismatch)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[dict] = []
        self._cur: dict | None = None
        self.text_parts: list[str] = []
        self.images: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self._cur = {"href": a["href"], "text": ""}
        elif tag == "img" and a.get("src"):
            self.images.append(a["src"])
        elif tag in ("script", "style"):
            self._skip += 1

    def handle_endtag(self, tag):
        if tag == "a" and self._cur:
            self.links.append(self._cur)
            self._cur = None
        elif tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if self._skip:
            return
        self.text_parts.append(data)
        if self._cur is not None:
            self._cur["text"] += data

    @property
    def text(self) -> str:
        return re.sub(r"\s+", " ", " ".join(self.text_parts)).strip()


# --------------------------------------------------------------- main entry -
def scan_eml(raw: bytes, *, reporter: str = "anonymous") -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    signals: list[dict] = []
    notes: list[str] = []

    headers = {k.lower(): ", ".join(str(v) for v in msg.get_all(k, []))
               for k in set(msg.keys())}
    subject = str(msg.get("subject") or "(no subject)")
    from_hdr = msg.get("from")
    from_display, from_addr = _split_addr(from_hdr)
    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
    reply_to = _addr_of(msg.get("reply-to"))
    return_path = _addr_of(msg.get("return-path")) or _addr_of(msg.get("sender"))
    msgid = str(msg.get("message-id") or "")

    # ---- 1. authentication ------------------------------------------------
    auth = _parse_auth_results(msg)
    has_dkim_sig = bool(msg.get_all("DKIM-Signature"))
    dkim_ok = _verify_dkim(raw) if has_dkim_sig else None
    spf = auth.get("spf")
    dmarc = auth.get("dmarc")
    dkim_hdr = auth.get("dkim")

    if spf in ("fail", "softfail"):
        signals.append(sig("spf_fail", f"SPF {spf}",
                           "high" if spf == "fail" else "medium",
                           26 if spf == "fail" else 14,
                           f"The sending server is not authorised for "
                           f"'{auth.get('spf_domain') or from_domain}' (SPF {spf}). "
                           "Either spoofing or a hijacked relay.", category="auth"))
    if dmarc == "fail":
        signals.append(sig("dmarc_fail", "DMARC fail", "critical", 34,
                           f"'{from_domain}' published a DMARC policy and this message "
                           "failed it. The domain owner is telling you to distrust "
                           "this exact mail.", category="auth"))
    elif dmarc == "none" or (dmarc is None and auth.get("dmarc_present", True)):
        pass
    if dkim_hdr == "fail" or (dkim_ok is False and dkim_hdr is None):
        signals.append(sig("dkim_fail", "DKIM signature invalid or missing",
                           "medium", 16,
                           "The cryptographic seal on the message does not verify. "
                           "Body or headers were altered in transit, or it was never "
                           "signed by the claimed domain.", category="auth"))
    elif dkim_ok is True or dkim_hdr == "pass":
        signals.append(sig("dkim_pass", "DKIM verified", "info", 0,
                           "Signature validates against the sender domain's published key.",
                           category="auth"))
    if not auth and dkim_ok is None:
        notes.append("no Authentication-Results header and no DKIM verification "
                     "possible — treat authentication as unknown, not as passed")

    # ---- 2. identity mismatches ------------------------------------------
    if reply_to and from_addr and _domain(reply_to) != _domain(from_addr):
        sev = "high" if _domain(reply_to) else "medium"
        signals.append(sig("replyto_mismatch", "Reply-To goes to a different domain",
                           sev, 24,
                           f"From is '{from_addr}' but replies go to '{reply_to}'. "
                           "The conversation would continue with a third party while "
                           "looking like the original sender.",
                           category="header"))
    if return_path and from_addr and _domain(return_path) != _domain(from_addr):
        signals.append(sig("return_path_mismatch", "Envelope sender differs from From",
                           "medium", 16,
                           f"Return-Path '{return_path}' vs From '{from_addr}' — "
                           "typical of bulk spoofing infrastructure and mailing abuse.",
                           category="header"))

    if from_display:
        dn_brand = _brand_in_text(from_display)
        if dn_brand and dn_brand not in lexical.skeleton(from_domain):
            signals.append(sig("display_name_spoof",
                               f"Display name claims '{dn_brand.title()}', domain does not",
                               "critical" if dn_brand in D.BRANDS else "high", 32,
                               f"Display name “{from_display}” vs address "
                               f"'{from_addr}'. The display name is arbitrary text; "
                               "only the address identifies the sender.",
                               category="header"))
    embedded = re.findall(r"[\w.+-]+@[\w.-]+\.\w+", from_display or "")
    if embedded and all(_domain(e) != from_domain for e in embedded):
        signals.append(sig("display_name_spoof", "Display name contains a different address",
                           "high", 26,
                           f"Display name shows '{embedded[0]}' but the real address is "
                           f"'{from_addr}' — a 'swallow' trick that survives casual reading.",
                           category="header"))

    if msgid and from_domain and _domain(msgid.split("<")[-1]) and \
            _domain(msgid.split("<")[-1]) != from_domain:
        signals.append(sig("msgid_mismatch", "Message-ID domain mismatch", "low", 8,
                           f"Message-ID is from '{_domain(msgid.split('<')[-1])}' while "
                           f"From is '{from_domain}'. Weak on its own; useful in combination.",
                           category="header"))

    date_sig = _date_anomaly(msg.get("date"))
    if date_sig:
        signals.append(date_sig)

    rcvd_sigs, rcvd_info = _received_chain(msg)
    signals.extend(rcvd_sigs)

    # ---- 3. body + links --------------------------------------------------
    text, html_links, images = _body_text_and_links(msg)
    scan_text = (subject + "\n" + text)[:BODY_SCAN_CHARS]

    bec = _bec_signals(scan_text, len(text), from_addr)
    signals.extend(bec)
    signals.extend(_india_signals(scan_text))

    link_reports = _score_links(html_links, from_domain)
    signals.extend(_link_signals(link_reports))

    # ---- 4. bank-detail integrity ----------------------------------------
    accounts = _extract_accounts(text)
    if accounts:
        vendor_key = from_domain or "unknown-vendor"
        chk = store.check_vendor_account(vendor_key, accounts[0])
        if chk["status"] == "changed":
            signals.append(sig("bec_bank_change",
                               "Bank details CHANGED vs this vendor's previous invoice",
                               "critical", 42,
                               f"Account/IBAN for '{vendor_key}' is now "
                               f"'{_mask(accounts[0])}', previously "
                               f"'{_mask(chk['previous'])}'. This is the single most "
                               "expensive email attack in existence — verify by phone "
                               "before any payment.",
                               category="baseline"))
        elif chk["status"] == "first_time":
            notes.append(f"baseline bank details recorded for '{vendor_key}' — "
                         "future changes will be flagged")

    # ---- 5. attachments ---------------------------------------------------
    atts, att_sigs = _attachments(msg, text)
    signals.extend(att_sigs)

    # ---- 6. sender baseline ----------------------------------------------
    baseline = store.observe_sender(from_addr, from_domain, from_display) if from_addr else {}
    if baseline.get("first_contact") and from_addr:
        signals.append(sig("first_contact", "First-ever contact from this sender",
                           "low", 8,
                           f"'{from_addr}' has never mailed this workspace before. "
                           "Novelty plus a request is the strongest single predictor "
                           "of business-email compromise.",
                           category="baseline"))
    elif baseline.get("hits", 0) >= 3:
        signals.append(sig("known_sender", f"Known sender ({baseline['hits']} prior mails)",
                           "info", -6,
                           f"'{from_addr}' has history here — a genuine point in its "
                           "favour, though accounts do get taken over.",
                           category="baseline"))
    domain_base = store.observe_domain(from_domain, "safe") if from_domain else {}
    if domain_base.get("first_contact") and from_domain and baseline.get("first_contact"):
        signals.append(sig("org_baseline_new_domain",
                           "Sending domain never seen by this organisation",
                           "low", 6,
                           f"'{from_domain}' is new to this workspace's mail history.",
                           category="baseline"))

    cluster_key = _cluster_key(subject, from_addr, link_reports)
    intel_ok = bool(auth) or dkim_ok is not None

    v = verdict.judge(signals, intel_ok=intel_ok, intel_notes=notes, channel="email")
    v["email"] = {
        "subject": subject, "from_display": from_display, "from_addr": from_addr,
        "from_domain": from_domain, "reply_to": reply_to, "return_path": return_path,
        "to": str(msg.get("to") or ""), "date": str(msg.get("date") or ""),
        "message_id": msgid, "auth": auth, "dkim_verified": dkim_ok,
        "received": rcvd_info, "text_excerpt": text[:1200],
        "body_chars": len(text),
    }
    v["links"] = link_reports
    v["attachments"] = atts
    v["accounts_found"] = [{"value": defang(_mask(a)), "vendor": from_domain}
                           for a in accounts[:3]]
    v["cluster"] = store.cluster_stats(cluster_key)
    v["cluster"]["cluster_key"] = cluster_key
    v["facts"] = {"defanged": defang(f"mailto:{from_addr}") if from_addr else "",
                  "registrable_domain": from_domain, "channel": "email"}
    v["receipt_id"] = store.save_receipt(subject, verdict.build_receipt(v, subject))
    return v


# -------------------------------------------------------------- auth parts --
def _parse_auth_results(msg) -> dict:
    """Pull spf/dkim/dmarc verdicts out of Authentication-Results headers."""
    out: dict = {}
    headers = msg.get_all("Authentication-Results") or []
    headers = headers or [h for h in (msg.get_all("Received-SPF") or [])]
    for h in headers:
        text = str(h).lower()
        for mech in ("spf", "dkim", "dmarc", "arc"):
            m = re.search(rf"\b{mech}\s*=\s*(\w+)", text)
            if m and mech not in out:
                out[mech] = m.group(1)
        m = re.search(r"smtp\.mailfrom\s*=\s*([\w.@+-]+)", text) or \
            re.search(r"header\.from\s*=\s*([\w.@+-]+)", text)
        if m:
            out["spf_domain"] = m.group(1).split("@")[-1]
    # Received-SPF: Pass (domain of ...)
    for h in (msg.get_all("Received-SPF") or []):
        m = re.match(r"\s*(\w+)", str(h))
        if m and "spf" not in out:
            out["spf"] = m.group(1).lower()
    return out


def _verify_dkim(raw: bytes):
    try:
        import dkim
        return bool(dkim.verify(raw))
    except Exception:
        return None  # cannot verify (no key in DNS, lib issue) -> 'unknown', not 'fail'


# --------------------------------------------------------- header helpers --
def _split_addr(hdr) -> tuple[str, str]:
    if not hdr:
        return "", ""
    try:
        return str(hdr.addresses[0].display_name or ""), \
               str(hdr.addresses[0].addr_spec or "")
    except Exception:
        s = str(hdr)
        m = re.search(r"<([^>]+)>", s)
        return (s.split("<")[0].strip().strip('"'), m.group(1) if m else s.strip())


def _addr_of(hdr) -> str:
    return _split_addr(hdr)[1]


def _domain(addr: str) -> str:
    addr = (addr or "").strip().strip("<>").rstrip(">")
    return addr.split("@")[-1].lower() if "@" in addr else ""


def _brand_in_text(text: str) -> str | None:
    sk = lexical.skeleton(text or "")
    for brand in D.BRANDS:
        if len(brand) >= 4 and re.search(rf"\b{brand}\b", sk):
            return brand
    return None


def _date_anomaly(date_hdr) -> dict | None:
    if not date_hdr:
        return None
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(str(date_hdr))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        skew_h = (datetime.now(timezone.utc) - dt).total_seconds() / 3600
    except Exception:
        return None
    if skew_h < -6:
        return sig("date_anomaly", f"Date header is {abs(skew_h):.0f}h in the future",
                   "medium", 12,
                   "Messages dated in the future break mail-client sorting and are "
                   "used to keep a lure at the top of the inbox.", category="header")
    if skew_h > 24 * 45:
        return sig("date_anomaly", f"Date header is {skew_h/24:.0f} days old",
                   "low", 7,
                   "An old timestamp on a supposedly current request is a replay "
                   "or template-reuse indicator.", category="header")
    return None


def _received_chain(msg) -> tuple[list[dict], dict]:
    """Walk Received headers oldest-first.

    A private IP in the FINAL delivery hop is normal (internal mail server).
    A private IP appearing *after* a public relay has been crossed is not: it
    means a hop was injected or headers were forged.
    """
    out, info = [], {"hops": 0, "private_ips": [], "anomaly": False, "first_hop": None}
    chain = [str(h) for h in (msg.get_all("Received") or [])]
    info["hops"] = len(chain)
    seen_public = False
    for i, hop in enumerate(reversed(chain)):  # oldest first
        ips = re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", hop)
        m_from = re.search(r"from\s+([^\s;]+)", hop, re.I)
        if i == 0 and m_from:
            info["first_hop"] = m_from.group(1)
        for ip in ips:
            try:
                import ipaddress
                if ipaddress.ip_address(ip).is_global:
                    seen_public = True
                elif seen_public:
                    info["private_ips"].append(ip)
            except ValueError:
                pass
        out.append({"index": i, "from": m_from.group(1) if m_from else None,
                    "ips": ips[:2]})
    sigs = []
    if info["private_ips"]:
        info["anomaly"] = True
        sigs.append(sig("private_ip_hop", "Private IP after a public relay in the mail path",
                        "medium", 12,
                        f"Address(es) {', '.join(sorted(set(info['private_ips']))[:3])} appear "
                        "below a public relay in the Received chain — that hop was injected "
                        "or the headers were forged.",
                        category="header"))
    if len(chain) == 1:
        sigs.append(sig("single_hop", "Only one Received hop", "low", 6,
                        "A single hop is unusual for internet mail and suggests "
                        "direct-to-MX injection from attacker infrastructure.",
                        category="header"))
    return sigs, info


# ------------------------------------------------------------- body / links -
def _body_text_and_links(msg) -> tuple[str, list[dict], list[str]]:
    texts, links, images = [], [], []
    for part in msg.walk():
        ctype = part.get_content_type()
        if part.is_multipart() or part.get_filename():
            continue
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            body = part.get_content()
        except Exception:
            try:
                body = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
            except Exception:
                continue
        if ctype == "text/html":
            g = _LinkGrab()
            try:
                g.feed(body)
            except Exception:
                pass
            links.extend(g.links)
            images.extend(g.images)
            texts.append(g.text)
        else:
            texts.append(body)
            for m in re.finditer(r"https?://[^\s<>\"')\]]+", body):
                links.append({"href": m.group(0), "text": ""})
    return "\n".join(texts), links, images


def _score_links(links: list[dict], from_domain: str) -> list[dict]:
    seen, out = set(), []
    for link in links:
        href = (link.get("href") or "").strip()
        if not href or href.startswith(("mailto:", "tel:", "#", "data:")):
            continue
        key = lexical.normalize_for_key(href)
        if key in seen:
            continue
        seen.add(key)
        lex = lexical.analyze_url(href)
        facts = lex["facts"]
        display = (link.get("text") or "").strip()
        mismatch = False
        if display and re.search(r"[\w-]+\.[a-z]{2,}", display, re.I) and \
                " " not in display:
            shown_host = re.sub(r"^[a-z]+://", "", display).split("/")[0].lower()
            shown_rd = lexical.split_host(shown_host)[0]
            if shown_rd and shown_rd != facts.get("registrable_domain"):
                mismatch = True
        out.append({
            "href_defanged": facts.get("defanged") or defang(href),
            "href": href,
            "display_text": display[:80],
            "display_mismatch": mismatch,
            "score": verdict.score_signals(lex["signals"]),
            "host": facts.get("host"),
            "registrable_domain": facts.get("registrable_domain"),
            "brand_impersonated": facts.get("brand_impersonated"),
            "is_same_domain_as_sender": facts.get("registrable_domain") == from_domain,
            "signals": [{"id": s["id"], "title": s["title"], "severity": s["severity"],
                         "weight": s["weight"]} for s in lex["signals"]],
        })
    out.sort(key=lambda x: x["score"], reverse=True)
    return out[:MAX_LINKS]


def _link_signals(link_reports: list[dict]) -> list[dict]:
    sigs = []
    worst = link_reports[0] if link_reports else None
    if mismatch_links := [l for l in link_reports if l["display_mismatch"]]:
        l = mismatch_links[0]
        sigs.append(sig("link_display_mismatch",
                        "Link text shows one domain, links to another",
                        "high", 30,
                        f"Shows '{l['display_text']}' but points to "
                        f"'{l['registrable_domain']}' — the whole point of anchor text "
                        "is that it can lie.", category="link"))
    if worst and worst["score"] >= verdict.THRESHOLDS["malicious"]:
        sigs.append(sig("malicious_link_in_body", "Body contains a malicious-looking link",
                        "critical", 40,
                        f"Top link '{worst['href_defanged']}' scores {worst['score']}/100 "
                        f"on lexical analysis alone ({', '.join(s['title'] for s in worst['signals'][:2])}).",
                        category="link"))
    elif worst and worst["score"] >= verdict.THRESHOLDS["suspicious"]:
        sigs.append(sig("suspicious_link_in_body", "Body contains a suspicious link",
                        "medium", 18,
                        f"Top link '{worst['href_defanged']}' scores {worst['score']}/100 "
                        "lexically. Run a full analysis before trusting it.",
                        category="link"))
    return sigs


# ------------------------------------------------------------------- BEC ----
def _bec_signals(text: str, body_chars: int, from_addr: str) -> list[dict]:
    out = []
    matched: list[str] = []
    for name, (pattern, label) in D.BEC_PATTERNS.items():
        m = re.search(pattern, text, re.I | re.M)
        if not m:
            continue
        matched.append(name)
        snippet = re.sub(r"\s+", " ", text[max(0, m.start() - 40): m.end() + 40]).strip()
        weights = {"bank_change": 34, "giftcard": 30, "secrecy": 18, "authority": 12,
                   "credential": 22, "payment_urgency": 16, "payroll_invoice": 12,
                   "callback": 10, "generic_greeting": 8, "threat_legal": 22,
                   "too_good": 26}
        sev = ("critical" if name == "bank_change"
               else "high" if weights.get(name, 0) >= 26
               else "medium" if weights.get(name, 0) >= 16 else "low")
        sid = {"payment_urgency": "bec_urgency", "bank_change": "bec_bank_change",
               "secrecy": "bec_secrecy", "giftcard": "bec_giftcard",
               "credential": "bec_credential"}.get(name, f"bec_{name}")
        out.append(sig(sid, label, sev, weights.get(name, 12),
                       f"…{snippet[:160]}…", category="language"))
    # combinations that are far worse than the sum of parts
    if {"bank_change", "payment_urgency"} <= set(matched) or \
            {"bank_change", "secrecy"} <= set(matched):
        out.append(sig("bec_compound", "Bank change + pressure/secrecy together",
                       "critical", 30,
                       "A payment-detail change bundled with urgency or a request for "
                       "silence is the textbook CEO/vendor fraud combination. Treat as "
                       "fraud until a phone call proves otherwise.", category="language"))
    if body_chars < 220 and "bec_credential" in matched:
        out.append(sig("terse_credential_lure", "Very short message with a credential ask",
                       "medium", 16,
                       "Under ~200 characters, one link, one ask — the dominant shape of "
                       "mass credential phishing.", category="language"))
    return out


def _india_signals(text: str) -> list[dict]:
    out = []
    for rule in D.INDIA_RULES:
        m = re.search(rule["pattern"], text, re.I | re.M)
        if not m:
            continue
        snippet = re.sub(r"\s+", " ", text[max(0, m.start() - 30): m.end() + 50]).strip()
        sev = "critical" if rule["weight"] >= 30 else "high" if rule["weight"] >= 24 else "medium"
        out.append(sig(f"india_{rule['id']}", rule["title"], sev, rule["weight"],
                       f"{rule['evidence']} Match: “…{snippet[:140]}…”",
                       category="india", tip=rule["tip"]))
    return out


# ------------------------------------------------------------ attachments ---
def _attachments(msg, body_text: str) -> tuple[list[dict], list[dict]]:
    atts, sigs = [], []
    body_lower = body_text.lower()
    for part in msg.walk():
        fname = part.get_filename()
        if not fname:
            continue
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        sha = hashlib.sha256(payload).hexdigest()
        ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
        inner_ext = (fname.lower().split(".")[-2] if fname.count(".") >= 2 else "")
        encrypted = False
        if ext == "zip":
            try:
                with zipfile.ZipFile(io.BytesIO(payload)) as z:
                    encrypted = any(i.flag_bits & 0x1 for i in z.infolist())
            except Exception:
                pass
        att = {"filename": defang(fname), "size": len(payload), "sha256": sha,
               "content_type": part.get_content_type(), "ext": ext,
               "encrypted_archive": encrypted,
               "macro_enabled": ext in D.MACRO_EXT,
               "double_extension": bool(inner_ext and inner_ext in D.DANGEROUS_EXT
                                        and ext in D.DANGEROUS_EXT)}
        atts.append(att)

        if ext in D.MACRO_EXT:
            sigs.append(sig("attachment_macro", f"Macro-enabled attachment ({ext})",
                            "high", 26,
                            f"'{fname}' can run VBA the moment the user clicks "
                            "'Enable Content'. Off-by-default in most orgs — check policy.",
                            category="attachment"))
        if encrypted:
            pw_in_body = bool(re.search(r"\b(password|pwd|passcode)\b\s*[:=\-]?\s*\S{4,}",
                                        body_lower))
            sigs.append(sig("attachment_archive_protected",
                            "Password-protected archive attachment",
                            "critical" if pw_in_body else "high", 34 if pw_in_body else 22,
                            f"'{fname}' is an encrypted zip"
                            + (" and the password is in the email body" if pw_in_body else "")
                            + ". That combination exists solely to defeat mail scanners.",
                            category="attachment"))
        if ext in D.DANGEROUS_EXT and ext not in D.MACRO_EXT:
            sev = "critical" if ext in ("exe", "scr", "hta", "js", "vbs", "lnk", "iso",
                                        "img", "apk", "msi", "jar", "com", "bat") else "medium"
            sigs.append(sig("attachment_dangerous", f"Executable/risky attachment ({ext})",
                            sev, 36 if sev == "critical" else 14,
                            f"'{fname}' is a .{ext} file. Mail is not a software "
                            "distribution channel for legitimate business correspondence.",
                            category="attachment"))
        if att["double_extension"]:
            sigs.append(sig("attachment_double_ext",
                            f"Double extension '{fname.rsplit('.', 2)[-2]}.{ext}'",
                            "critical", 34,
                            f"'{fname}' is really a .{ext} — the earlier extension is "
                            "decoration to defeat pattern-matching humans.",
                            category="attachment"))
    return atts, sigs


# ---------------------------------------------------------------- accounts --
def _extract_accounts(text: str) -> list[str]:
    """Priority order matters: we diff the *payment destination*, not any number.
    IBAN > digits-only account number > IFSC (branch code, used as corroboration)."""
    iban = [m.group(0) for m in re.finditer(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b", text)]
    acct = [m.group(1) for m in re.finditer(
        r"(?:account|a/c|acct)\.?\s*(?:no|number|#)?\.?\s*[:\-]?\s*(\d{9,18})",
        text, re.I)]
    bare = [m.group(0) for m in re.finditer(r"(?<![\d.])\d{11,18}(?![\d.])", text)]
    ifsc = [m.group(0) for m in re.finditer(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", text)]
    found = iban + acct + bare + ifsc
    seen, out = set(), []
    for f in found:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def _mask(v: str) -> str:
    if not v or len(v) <= 4:
        return v or ""
    return v[:2] + "*" * (len(v) - 6) + v[-4:]


def _cluster_key(subject: str, sender: str, links: list[dict]) -> str:
    norm_subj = re.sub(r"^(re|fwd?|fw)\s*:\s*", "", subject.lower().strip())
    norm_subj = re.sub(r"\d+", "#", norm_subj)[:80]
    hosts = ",".join(sorted({l["registrable_domain"] or "" for l in links})[:6])
    return hashlib.sha256(f"{norm_subj}|{sender.lower()}|{hosts}".encode()).hexdigest()[:16]
