"""URL analysis that needs no network: instant (<5ms) and the bulk of the verdict.

Everything here is deterministic and unit-testable. If the network is down or an
intel API is rate-limited, this layer still produces a usable answer.
"""
from __future__ import annotations

import ipaddress
import math
import re
from urllib.parse import parse_qsl, unquote, urlsplit

from . import data as D

# Public-suffix handling. Deliberately small + India-heavy rather than a full PSL
# dependency; extend PUBLIC_SUFFIXES as coverage grows.
MULTI_SUFFIXES = {
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "ac.in", "gov.in",
    "nic.in", "res.in", "edu.in", "mil.in", "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au", "co.nz", "co.za", "com.br", "com.sg", "com.my",
    "co.jp", "or.jp", "ne.jp", "com.cn", "com.hk", "co.kr", "com.pk", "com.bd",
    "com.np", "com.lk", "co.ae", "com.sa", "com.tr", "co.il", "com.mx", "com.ar",
}

# Non-ASCII only: ASCII digit swaps (paypa1) are "leetspeak", a different signal.
CONFUSABLE_CHARS = {k for k in D.HOMOGLYPHS if len(k) == 1 and ord(k) > 127}


def sig(sid, title, severity, weight, evidence, category="lexical", tip=None):
    return {"id": sid, "title": title, "severity": severity, "weight": weight,
            "evidence": evidence, "category": category,
            "tip": tip or D.TEACH.get(sid)}


# ------------------------------------------------------------------ helpers -
def split_host(host: str) -> tuple[str, str, list[str]]:
    """-> (registrable_domain, public_suffix, labels)"""
    host = (host or "").lower().strip(".")
    if not host:
        return "", "", []
    if re.fullmatch(r"[\d.]+", host) or ":" in host:
        return host, "", [host]
    labels = host.split(".")
    for n in (3, 2):
        if len(labels) >= n:
            cand = ".".join(labels[-n:])
            if cand in MULTI_SUFFIXES:
                return ".".join(labels[-(n + 1):]), cand, labels
    tld = labels[-1]
    return ".".join(labels[-2:]), tld, labels


def skeleton(text: str) -> str:
    """Fold homoglyphs + digit/symbol swaps to a comparable ASCII skeleton."""
    out = []
    for ch in (text or "").lower():
        low = ch.lower()
        if low in D.HOMOGLYPHS:
            out.append(D.HOMOGLYPHS[low])
        elif 0x0400 <= ord(ch) <= 0x04FF or 0x0370 <= ord(ch) <= 0x03FF:
            out.append("?")  # unmapped non-Latin -> visible difference
        else:
            out.append(ch)
    s = "".join(out).replace("rn", "m").replace("vv", "w")
    return re.sub(r"[^a-z0-9.-]", "", s)


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def edit_distance(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        best = i
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
            best = min(best, cur[j])
        if best > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def defang(url: str) -> str:
    """Make any URL safe to display: never clickable, never auto-linked."""
    s = url or ""
    s = re.sub(r"^http", "hxxp", s, flags=re.I)
    s = re.sub(r"^(javascript|data|vbscript)", r"blocked-\1", s, flags=re.I)
    s = re.sub(r"^ftp", "fxp", s, flags=re.I)
    s = s.replace("@", "[@]").replace(".", "[.]")
    return s


def normalize_for_key(url: str) -> str:
    """Stable identity for time-of-click tracking (strips query noise)."""
    try:
        p = urlsplit(url if "://" in url else "http://" + url)
        host = (p.hostname or "").lower()
        path = re.sub(r"[?#].*$", "", p.path)
        return f"{host}{path}".rstrip("/")
    except Exception:
        return url


# --------------------------------------------------------------- main entry -
def analyze_url(raw_url: str) -> dict:
    """Return {signals, facts, parsed}. Pure function, no I/O."""
    signals: list[dict] = []
    raw = (raw_url or "").strip().strip("<>()[]{}\"'")
    if not raw:
        return {"signals": [], "facts": {}, "parsed": {}, "error": "empty input"}

    known_schemes = {"http", "https", "ftp", "javascript", "data", "vbscript",
                     "file", "blob", "mailto", "tel"}
    m_scheme = re.match(r"^([a-z][a-z0-9+.-]*):", raw, re.I)
    raw_scheme = m_scheme.group(1).lower() if m_scheme and \
        m_scheme.group(1).lower() in known_schemes else None
    candidate = raw if raw_scheme else "http://" + raw
    try:
        p = urlsplit(candidate)
    except Exception as exc:
        return {"signals": [], "facts": {}, "parsed": {}, "error": f"unparseable: {exc}"}

    scheme = raw_scheme or (p.scheme or "").lower()
    raw_host = p.hostname or ""
    host = raw_host.lower()
    port = None
    try:
        port = p.port
    except ValueError:
        facts_port_error = True
    path = unquote(p.path or "")
    query = unquote(p.query or "")
    rd, suffix, labels = split_host(host)

    facts = {
        "input": raw, "defanged": defang(candidate), "scheme": scheme,
        "host": host, "port": port, "registrable_domain": rd,
        "public_suffix": suffix, "labels": labels, "path": path,
        "query_keys": [k for k, _ in parse_qsl(p.query or "", keep_blank_values=True)],
        "is_ip": False, "userinfo": None, "idn": False, "shortener": False,
        "subdomain_depth": max(0, len(labels) - len(suffix.split(".")) - 1),
    }

    # --- 1. non-http scheme -------------------------------------------------
    if scheme not in ("http", "https"):
        sev = "critical" if scheme in ("javascript", "data", "vbscript", "file") else "high"
        signals.append(sig("scheme_dangerous", f"'{scheme}:' scheme",
                           sev, 40 if sev == "critical" else 20,
                           f"Link uses '{scheme}:' instead of https — it can execute "
                           "content or read local files instead of opening a page."))
    if scheme == "http":
        signals.append(sig("no_tls", "Plain http (no encryption)", "low", 4,
                           "Page is served unencrypted — anything typed into it "
                           "travels in clear text."))

    # --- 2. IP literal host -------------------------------------------------
    try:
        ipaddress.ip_address(host.strip("[]"))
        facts["is_ip"] = True
        signals.append(sig("ip_host", "Raw IP address instead of a domain",
                           "high", 26,
                           f"Host is the bare IP {host} — no domain, no brand, "
                           "no reputation, and no certificate identity to check."))
    except ValueError:
        pass

    # --- 3. userinfo @ trick ------------------------------------------------
    if "@" in (p.netloc or ""):
        facts["userinfo"] = p.netloc.rsplit("@", 1)[0]
        ui_brand = next((b for b in D.BRANDS if len(b) >= 4 and
                         b in skeleton(facts["userinfo"])), None)
        signals.append(sig("userinfo", "Credential '@' trick in the URL",
                           "critical" if ui_brand else "high", 42 if ui_brand else 30,
                           f"'{facts['userinfo']}@' precedes the real host '{host}'. "
                           "Everything before '@' is a decoy; the browser goes to the host after it."))

    # --- 4. port ------------------------------------------------------------
    if port and port not in (80, 443, 8080, 8443):
        signals.append(sig("odd_port", f"Unusual port :{port}", "medium", 12,
                           f"Service on non-standard port {port}. Legitimate consumer "
                           "logins almost never do this."))

    # --- 5. IDN / punycode / homoglyphs ------------------------------------
    display_host = host
    if host.startswith("xn--") or ".xn--" in host:
        facts["idn"] = True
        try:
            decoded = host.encode().decode("idna")
        except Exception:
            decoded = host
        display_host = decoded
        signals.append(sig("punycode", "Punycode (internationalised) domain",
                           "high", 22,
                           f"'{host}' decodes to '{decoded}' — registered specifically "
                           "to look like a Latin-script domain."))
    if any((ch in CONFUSABLE_CHARS) or (ord(ch) > 0x024F and ch.isalpha())
           for ch in display_host):
        signals.append(sig("homoglyph", "Mixed-script / lookalike characters",
                           "critical", 34,
                           f"Host '{display_host}' mixes scripts that render almost "
                           "identically to Latin letters (e.g. Cyrillic 'а' vs 'a')."))
    facts["display_host"] = display_host

    # --- 6. brand impersonation -------------------------------------------
    skel_host = skeleton(display_host)
    skel_labels = skel_host.split(".")
    skel_rd = skeleton(rd)
    brand_hit = None

    # If the registrable label IS a brand string we cover, this is (or claims to be)
    # the real thing: typosquat scoring would produce nonsense ("icicibank" is two
    # edits from "citibank"). Brand-in-subdomain still applies.
    sld_is_known_brand = bool(rd) and (rd.split(".")[0].lower() in D.BRANDS
                                       or rd in D.LEGIT_DOMAINS)
    if rd and rd in D.LEGIT_DOMAINS:
        facts["known_good_domain"] = True
    # A user-published subdomain of a shared platform (paypal.sharepoint.com) is a
    # real attack; a brand-owned domain (outlook.office365.com) is not.
    shared_platform = any(host == t or host.endswith("." + t) for t in D.TRUSTED_HOSTING)

    for brand in D.BRANDS:
        if not brand or len(brand) < 4:
            continue
        # (a) exact brand as a non-registrable label: paypal.com.evil.xyz
        for lab in skel_labels[:-len(suffix.split(".")) - 1] if suffix else skel_labels[:-1]:
            if lab == brand or lab.replace("-", "") == brand:
                if brand not in skel_rd and (not sld_is_known_brand or shared_platform):
                    brand_hit = brand
                    signals.append(sig(
                        "brand_in_subdomain",
                        f"Brand '{brand}' used as a subdomain of '{rd}'",
                        "high" if shared_platform else "critical",
                        30 if shared_platform else 50,
                        f"Host is '{display_host}'. The actual registrable domain is "
                        f"'{rd}', which is NOT {brand}. Everything left of it is "
                        "attacker-controlled."))
                break
        if brand_hit:
            break

        # (b) typosquat of the registrable domain's second-level label
        sld_label = skel_rd.split(".")[0]
        raw_sld = (rd.split(".")[0].lower() if rd else "")
        if (not sld_is_known_brand and len(brand) >= 4 and sld_label == brand
                and raw_sld != brand and raw_sld):
            brand_hit = brand
            signals.append(sig(
                "typosquat",
                f"Digit/symbol substitution of '{brand}'",
                "critical", 40,
                f"'{raw_sld}' folds to '{brand}' once lookalike characters are "
                f"normalised ({_diff(raw_sld, brand)}). Read letter-by-letter, not by shape.",
                ))
            break
        if (not sld_is_known_brand and len(brand) >= 5 and sld_label
                and sld_label != brand and sld_label[:1] == brand[:1]):
            dist = edit_distance(sld_label, brand, cap=2)
            if 1 <= dist <= (1 if len(brand) <= 6 else 2):
                brand_hit = brand
                signals.append(sig(
                    "typosquat",
                    f"Lookalike of '{brand}' (edit distance {dist})",
                    "critical", 46,
                    f"'{skel_rd}' vs '{brand}': '{_diff(sld_label, brand)}'. One or "
                    "two-character variants are registered in bulk to catch typos "
                    "and glance-reads."))
                break

        # (c) brand embedded with filler: paypal-secure, secure-paypal, paypalverify
        if (not sld_is_known_brand and len(brand) >= 5 and brand in sld_label
                and sld_label != brand):
            fillers = ("secure", "login", "verify", "update", "account", "support",
                       "help", "service", "official", "portal", "kyc", "refund",
                       "billing", "auth", "signin", "online", "my", "in", "india",
                       "clone", "alert", "notice", "team", "care", "desk", "center",
                       "centre", "payment", "invoice", "delivery", "track", "wallet")
            if (any(f in sld_label for f in fillers)
                    or (sld_label.startswith(brand) and len(sld_label) > len(brand)
                        and sld_label[len(brand)] in "-_")):
                brand_hit = brand
                signals.append(sig(
                    "typosquat",
                    f"'{brand}' + lure word in domain",
                    "critical", 34,
                    f"'{skel_rd}' glues the brand to a trust word. Brands register "
                    "their own name, not '{brand}-secure-login' variants."))
                break

    facts["brand_impersonated"] = brand_hit

    # --- 7. risky TLD / free host / shortener ------------------------------
    if suffix in D.RISKY_TLDS or (suffix.split(".")[-1] in D.RISKY_TLDS):
        signals.append(sig("risky_tld", f"High-abuse TLD '.{suffix}'", "medium", 15,
                           f"'.{suffix}' is cheap, bulk-registered and heavily used "
                           "for throwaway phishing infrastructure."))
    for abuse in D.ABUSE_HOSTS:
        if host == abuse or host.endswith("." + abuse):
            gentle = abuse in D.TRUSTED_HOSTING
            signals.append(sig("free_host",
                               f"{'Legitimate' if gentle else 'Abused'} shared-hosting platform ({abuse})",
                               "info" if gentle else "medium", 2 if gentle else 16,
                               f"Page is hosted on {abuse}, a shared platform. "
                               + ("Legitimate, but anyone can publish here — judge the "
                                  "content, not the platform."
                                  if gentle else
                                  "Free, anonymous and commonly reused for phishing lures.")))
            break
    if rd in D.SHORTENERS or host in D.SHORTENERS:
        facts["shortener"] = True
        signals.append(sig("shortener", "URL shortener hides the destination",
                           "medium", 20,
                           f"'{rd}' hides the final destination. Shorteners are used "
                           "so the real host is invisible until after the click."))

    # --- 8. structure ------------------------------------------------------
    if facts["subdomain_depth"] >= 3:
        signals.append(sig("deep_subdomain", f"{facts['subdomain_depth']} subdomain levels",
                           "medium", 13,
                           f"'{host}' stacks {facts['subdomain_depth']} subdomains to "
                           "push the real domain off the left edge of a phone screen."))
    if len(host) > 45:
        signals.append(sig("long_host", "Unusually long hostname", "low", 8,
                           f"{len(host)} characters — length is used to bury the "
                           "registrable domain out of view."))
    hyphen_count = (rd.split(".")[0].count("-") if rd else 0)
    if hyphen_count >= 2:
        signals.append(sig("many_hyphens", f"{hyphen_count} hyphens in the domain",
                           "medium", 10,
                           "Multi-hyphen brand-ish domains are a classic "
                           "phishing-registration pattern."))

    # --- 9. path / query ---------------------------------------------------
    low_path = (path + "?" + query).lower()
    hits = sorted({w for w in D.SENSITIVE_WORDS if re.search(rf"\b{re.escape(w)}\b", low_path)})
    if len(hits) == 1 and (sld_is_known_brand or rd in D.LEGIT_DOMAINS):
        hits = []  # one generic word on a brand-owned domain means nothing
    if hits:
        weak_host = not (sld_is_known_brand or rd in D.LEGIT_DOMAINS)
        if len(hits) == 1:
            sev, weight = ("medium", 8) if weak_host else ("info", 3)
        else:
            sev, weight = ("medium" if len(hits) < 3 else "high"), min(26, 8 + 3 * len(hits))
        signals.append(sig("sensitive_path", "Credential/payment lure words in path",
                           sev, weight,
                           f"Path contains: {', '.join(hits[:6])}. These words are "
                           "chosen to make the click feel routine."))

    open_redirect = sorted({k for k in facts["query_keys"] if k.lower() in D.REDIRECT_PARAMS})
    inner_url = re.search(r"https?%3a%2f%2f|https?://", query, re.I)
    if open_redirect and inner_url:
        signals.append(sig("open_redirect", "Open-redirect wrapper",
                           "high", 24,
                           f"Parameter '{open_redirect[0]}' carries a full URL. A "
                           "trusted domain shows in the address bar while you land "
                           "somewhere else."))

    lowered = low_path
    decoded_twice = unquote(unquote(p.query or ""))
    if re.search(r"(%25|%2f%2f|%00|%0d%0a)", (p.query or "") + path, re.I) and \
            re.search(r"(https?:|//|\.php|\.exe)", decoded_twice, re.I):
        signals.append(sig("encoding_abuse", "Encoded payload in the URL",
                           "medium", 14,
                           "Multiple layers of percent-encoding hide the real target "
                           "from both the eye and naive scanners."))
    if any(ord(ch) < 32 for ch in raw) or "\u200b" in raw or "\u202e" in raw:
        signals.append(sig("control_chars", "Invisible control characters",
                           "high", 24,
                           "URL contains zero-width or bidirectional override "
                           "characters — used to reverse or hide parts of the address."))

    # --- 10. file extension / download -------------------------------------
    last_seg = re.split(r"[/?#]", path)[-1].lower()
    exts = last_seg.split(".")
    if len(exts) >= 3 and exts[-1] in D.DANGEROUS_EXT:
        signals.append(sig("dangerous_ext", f"Double extension '.{exts[-2]}.{exts[-1]}'",
                           "critical", 34,
                           f"'{last_seg}' is a '.{exts[-1]}' file dressed up as "
                           f"'.{exts[-2]}'. The OS runs the LAST extension."))
    elif len(exts) >= 2 and exts[-1] in D.DANGEROUS_EXT:
        sev = "high" if exts[-1] in ("exe", "scr", "hta", "js", "vbs", "lnk", "iso",
                                     "img", "apk", "msi", "jar") else "medium"
        signals.append(sig("downloadable", f"Direct download '.{exts[-1]}'",
                           sev, 22 if sev == "high" else 12,
                           f"URL points straight at a .{exts[-1]} file rather than a "
                           "page. Executable/archival payloads are delivered this way."))

    # --- 11. randomness / entropy -----------------------------------------
    for part, name in ((path.strip("/"), "path"), (rd.split(".")[0] if rd else "", "domain")):
        if len(part) >= 16:
            e = entropy(part)
            if e > 4.15 and re.search(r"[a-z]{5,}", part):
                signals.append(sig("high_entropy", f"Random-looking {name}",
                                   "info" if sld_is_known_brand else "medium",
                                   3 if sld_is_known_brand else 12,
                                   f"{name} entropy {e:.2f} bits/char — consistent "
                                   "with generated, single-use hostile URLs."))
                break

    facts["path_lower"] = lowered
    return {"signals": signals, "facts": facts, "parsed": {"path": path,
                                                           "query": query}}


def _diff(a: str, b: str) -> str:
    """Human-readable 'domain vs brand' character difference."""
    if len(a) == len(b):
        diffs = [f"'{x}'→'{y}'" for x, y in zip(a, b) if x != y]
        return "characters differ: " + ", ".join(diffs[:4]) if diffs else "reordered characters"
    return f"'{a}' vs '{b}' — {abs(len(a) - len(b))} character(s) " + \
           ("added" if len(a) > len(b) else "removed")
