"""Network helpers: SSRF-safe fetching, RDAP domain age, DNS sanity checks.

Design rules baked in here:
  * We NEVER hand a URL back to the user's browser to fetch. All fetching is server-side.
  * We refuse to touch private/loopback/link-local targets (SSRF guard).
  * Every network call is optional: if it fails, the caller degrades to lexical-only
    and marks the verdict low-confidence. A checker that hangs is worse than useless.
"""
from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import requests

TIMEOUT = (4, 8)          # (connect, read)
MAX_BYTES = 700 * 1024
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": USER_AGENT, "Accept-Language": "en-IN,en;q=0.9"})

# tiny TTL cache so repeat lookups are free (and we don't hammer RDAP)
_CACHE: dict[str, tuple[float, object]] = {}
CACHE_TTL = 60 * 30


def _cache_get(key):
    hit = _CACHE.get(key)
    if hit and time.time() - hit[0] < CACHE_TTL:
        return hit[1]
    return None


def _cache_put(key, value):
    _CACHE[key] = (time.time(), value)
    return value


# --------------------------------------------------------------- SSRF guard -
def resolve_ips(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return []
    return sorted({i[4][0] for i in infos})


def is_public_host(host: str) -> bool:
    """False for localhost, private ranges, link-local (cloud metadata), CGNAT."""
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        return ip.is_global
    except ValueError:
        pass
    ips = resolve_ips(host)
    if not ips:
        return False
    for raw in ips:
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            return False
        if not ip.is_global:
            return False
    return True


# --------------------------------------------------------------------- DNS --
def dns_facts(host: str) -> dict:
    """A/AAAA, MX, NS, TXT(SPF), DMARC presence. Never raises."""
    cached = _cache_get(f"dns:{host}")
    if cached is not None:
        return cached
    out = {"a": [], "mx": [], "ns": [], "spf": None, "dmarc": None,
           "resolves": False, "error": None}
    try:
        import dns.resolver

        r = dns.resolver.Resolver(configure=True)
        r.lifetime = 4.0
        for rtype, key in (("A", "a"), ("MX", "mx"), ("NS", "ns")):
            try:
                out[key] = sorted(str(x) for x in r.resolve(host, rtype))
            except Exception:
                pass
        out["resolves"] = bool(out["a"])
        try:
            txts = ["".join(b.decode() if isinstance(b, bytes) else b
                            for b in rr.strings)
                    for rr in r.resolve(host, "TXT")]
            spf = [t for t in txts if t.startswith("v=spf1")]
            out["spf"] = spf[0] if spf else None
        except Exception:
            pass
        try:
            dr = r.resolve(f"_dmarc.{host}", "TXT")
            d = [t.to_text() for t in dr]
            out["dmarc"] = next((x for x in d if "v=DMARC1" in x), None)
        except Exception:
            out["dmarc"] = None
    except Exception as exc:  # dnspython missing or resolver dead
        out["error"] = f"dns unavailable: {type(exc).__name__}"
    return _cache_put(f"dns:{host}", out)


# --------------------------------------------------------------- TLS cert ---
def tls_facts(host: str, port: int = 443) -> dict:
    cached = _cache_get(f"tls:{host}")
    if cached is not None:
        return cached
    out = {"ok": False, "issuer": None, "not_before_days": None,
           "hostname_match": None, "error": None}
    if not is_public_host(host):
        out["error"] = "refused (non-public host)"
        return out
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
        out["ok"] = True
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        out["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
        nb = cert.get("notBefore")
        if nb:
            dt = datetime.strptime(nb, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc)
            out["not_before_days"] = (datetime.now(timezone.utc) - dt).days
        out["hostname_match"] = True  # create_default_context already validates
    except ssl.SSLCertVerificationError as exc:
        out["error"] = f"cert verification failed: {exc.verify_message}"
        out["hostname_match"] = False
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}"
    return _cache_put(f"tls:{host}", out)


# -------------------------------------------------------------------- RDAP --
_RDAP_BASE = "https://rdap.org/domain/{domain}"


def rdap_facts(domain: str) -> dict:
    """Domain registration age + registrar. The single most predictive infra signal."""
    cached = _cache_get(f"rdap:{domain}")
    if cached is not None:
        return cached
    out = {"ok": False, "registered": None, "age_days": None, "registrar": None,
           "error": None}
    try:
        resp = _SESSION.get(_RDAP_BASE.format(domain=domain),
                            timeout=TIMEOUT, allow_redirects=True)
        if resp.status_code == 404:
            out["error"] = "no RDAP record (unregistered or unsupported TLD)"
            return _cache_put(f"rdap:{domain}", out)
        resp.raise_for_status()
        data = resp.json()
        created = None
        for ev in data.get("events", []):
            if ev.get("eventAction") in ("registration", "registered"):
                created = ev.get("eventDate")
                break
        for ent in data.get("entities", []):
            if "registrar" in (ent.get("roles") or []):
                for item in ent.get("vcardArray", [None, []])[1]:
                    if item[0] == "fn":
                        out["registrar"] = item[3]
        if created:
            dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            out["registered"] = dt.date().isoformat()
            out["age_days"] = (datetime.now(timezone.utc) - dt).days
            out["ok"] = True
    except Exception as exc:
        out["error"] = f"{type(exc).__name__} on RDAP"
    return _cache_put(f"rdap:{domain}", out)


# ------------------------------------------------------- guarded page fetch --
def fetch_page(url: str, max_redirects: int = 6) -> dict:
    """Follow the redirect chain server-side and describe the final page.

    Used for the 'what happens if you click' preview. We only READ html; we never
    execute JS, never POST anything, never store cookies across runs.
    """
    out = {"ok": False, "chain": [], "final_url": None, "status": None,
           "title": None, "html_snippet": None, "forms": [], "meta_refresh": None,
           "js_redirects": [], "external_form_actions": [], "error": None}
    host = urlsplit(url).hostname or ""
    if not resolve_ips(host):
        out["error"] = "host did not resolve (domain may be dormant, or not yet armed)"
        return out
    if not is_public_host(host):
        out["error"] = "refused: target resolves to a private/loopback address (SSRF guard)"
        return out
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    try:
        current = url
        for _ in range(max_redirects):
            out["chain"].append(current)
            resp = session.get(current, timeout=TIMEOUT, allow_redirects=False,
                               stream=True)
            if resp.is_redirect and resp.headers.get("location"):
                current = urljoin(current, resp.headers["location"])
                if not is_public_host(urlsplit(current).hostname or ""):
                    out["error"] = "refused: redirect to private address"
                    return out
                continue
            out["status"] = resp.status_code
            out["final_url"] = current
            ctype = resp.headers.get("content-type", "")
            if "html" in ctype or "text" in ctype:
                raw = resp.raw.read(MAX_BYTES, decode_content=True) or b""
                html = raw.decode(resp.encoding or "utf-8", errors="replace")
                out.update(_parse_html(html, current))
            out["ok"] = True
            break
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"[:200]
    finally:
        session.close()
    return out


def _parse_html(html: str, base_url: str) -> dict:
    import re

    def first(pattern, flags=re.I | re.S):
        m = re.search(pattern, html, flags)
        return m.group(1).strip() if m else None

    title = first(r"<title[^>]*>(.*?)</title>")
    meta = first(r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']([^"\']+)')
    js = re.findall(r"(?:location\.(?:href|replace)\s*=?\s*\(?\s*|window\.location\s*=\s*)"
                    r"[\"']([^\"']{4,300})[\"']", html, re.I)

    forms, external = [], []
    base_host = (urlsplit(base_url).hostname or "").lower()
    for m in re.finditer(r"<form\b[^>]*>(.*?)</form>", html, re.I | re.S):
        tag, body = m.group(0), m.group(1)
        action = (re.search(r'action\s*=\s*["\']([^"\']*)', tag, re.I) or [None, ""])[1]
        method = (re.search(r'method\s*=\s*["\']([^"\']*)', tag, re.I) or [None, "get"])[1]
        absolute = urljoin(base_url, action) if action else base_url
        fhost = (urlsplit(absolute).hostname or "").lower()
        inputs = re.findall(r"<input\b[^>]*>", body, re.I)
        types = {(re.search(r'type\s*=\s*["\']([^"\']*)', i, re.I) or [None, "text"])[1]
                 for i in inputs}
        names = [(re.search(r'name\s*=\s*["\']([^"\']*)', i, re.I) or [None, ""])[1]
                 for i in inputs]
        has_password = any(t.lower() == "password" for t in types)
        forms.append({
            "action": absolute,
            "action_host": fhost,
            "method": method.upper(),
            "fields": [n for n in names if n][:12],
            "has_password": has_password,
            "is_external": bool(fhost) and fhost != base_host,
        })
        if has_password and fhost and fhost != base_host:
            external.append({"action": absolute, "host": fhost})

    text = re.sub(r"<script.*?</script>|<style.*?</style>", " ", html,
                  flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return {
        "title": title,
        "meta_refresh": meta,
        "js_redirects": js[:6],
        "forms": forms,
        "external_form_actions": external,
        "html_snippet": text[:400],
    }
