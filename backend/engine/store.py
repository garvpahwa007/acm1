"""SQLite store. This is where the 'different' features get their memory.

  domains / senders  -> org baseline + first-contact detection
  vendors            -> bank-detail-change detection across invoices
  url_snapshots      -> time-of-click: did this link change since we last saw it?
  reports            -> report-to-sweep clustering (herd immunity)
  receipts           -> reproducible verdict evidence for audit
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

DB_PATH = os.environ.get("PHISHGUARD_DB",
                         os.path.join(os.path.dirname(__file__), "..", "data", "phishguard.db"))
_LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS domains(
  domain TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT, hits INTEGER DEFAULT 1,
  worst_tier TEXT);
CREATE TABLE IF NOT EXISTS senders(
  from_addr TEXT PRIMARY KEY, from_domain TEXT, display_name TEXT,
  first_seen TEXT, last_seen TEXT, hits INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS vendors(
  vendor_key TEXT PRIMARY KEY, account TEXT, first_seen TEXT, changed_at TEXT,
  changes INTEGER DEFAULT 0, offered TEXT, last_confirmed TEXT);
CREATE TABLE IF NOT EXISTS url_snapshots(
  url_key TEXT PRIMARY KEY, score INTEGER, tier TEXT, content_hash TEXT,
  first_seen TEXT, last_seen TEXT, hits INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS reports(
  id TEXT PRIMARY KEY, cluster_key TEXT, subject TEXT, sender TEXT, links TEXT,
  reporter TEXT, clicked INTEGER DEFAULT 0, verdict TEXT, score INTEGER,
  created_at TEXT);
CREATE TABLE IF NOT EXISTS receipts(
  receipt_id TEXT PRIMARY KEY, subject TEXT, payload TEXT, created_at TEXT);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def init():
    with _LOCK, _conn() as c:
        c.executescript(SCHEMA)
        for col in ("offered TEXT", "last_confirmed TEXT"):
            try:  # cheap forward-migration for existing databases
                c.execute(f"ALTER TABLE vendors ADD COLUMN {col}")
            except sqlite3.OperationalError:
                pass


# ------------------------------------------------------- org baseline -------
def observe_domain(domain: str, tier: str) -> dict:
    """Record a domain sighting; report whether this is first contact."""
    if not domain:
        return {"first_contact": False, "hits": 0, "first_seen": None}
    with _LOCK, _conn() as c:
        row = c.execute("SELECT * FROM domains WHERE domain=?", (domain,)).fetchone()
        if row:
            worst = row["worst_tier"]
            rank = {"malicious": 3, "suspicious": 2, "low": 1, "safe": 0}
            if rank.get(tier, 0) > rank.get(worst, 0):
                worst = tier
            c.execute("UPDATE domains SET last_seen=?, hits=hits+1, worst_tier=? "
                      "WHERE domain=?", (now(), worst, domain))
            return {"first_contact": False, "hits": row["hits"] + 1,
                    "first_seen": row["first_seen"], "worst_tier": worst}
        c.execute("INSERT INTO domains(domain,first_seen,last_seen,worst_tier) "
                  "VALUES(?,?,?,?)", (domain, now(), now(), tier))
        return {"first_contact": True, "hits": 1, "first_seen": now(), "worst_tier": tier}


def observe_sender(addr: str, domain: str, display: str) -> dict:
    if not addr:
        return {"first_contact": False, "hits": 0}
    with _LOCK, _conn() as c:
        row = c.execute("SELECT * FROM senders WHERE from_addr=?", (addr,)).fetchone()
        if row:
            c.execute("UPDATE senders SET last_seen=?, hits=hits+1 WHERE from_addr=?",
                      (now(), addr))
            return {"first_contact": False, "hits": row["hits"] + 1,
                    "first_seen": row["first_seen"]}
        c.execute("INSERT INTO senders(from_addr,from_domain,display_name,first_seen,"
                  "last_seen) VALUES(?,?,?,?,?)", (addr, domain, display, now(), now()))
        return {"first_contact": True, "hits": 1, "first_seen": now()}


# ------------------------------------------------- bank-detail integrity ----
def check_vendor_account(vendor_key: str, account: str) -> dict:
    """Compare an invoice's account/IBAN against the *trusted* baseline for that vendor.

    Critical design rule: a value taken from an unverified message never becomes the
    baseline. Otherwise a single fraudulent invoice would poison the reference and the
    second identical attempt would look clean — which is exactly how double-invoicing
    fraud beats naive diffing.
    """
    if not vendor_key or not account:
        return {"status": "unknown", "previous": None, "changed": False}
    norm = "".join(ch for ch in account.upper() if ch.isalnum())
    with _LOCK, _conn() as c:
        row = c.execute("SELECT * FROM vendors WHERE vendor_key=?",
                        (vendor_key,)).fetchone()
        if not row:
            c.execute("INSERT INTO vendors(vendor_key,account,first_seen,last_confirmed)"
                      " VALUES(?,?,?,?)", (vendor_key, norm, now(), now()))
            return {"status": "first_time", "previous": None, "changed": False}
        if row["account"] != norm:
            c.execute("UPDATE vendors SET offered=?, changed_at=?, changes=changes+1 "
                      "WHERE vendor_key=?", (norm, now(), vendor_key))
            return {"status": "changed", "previous": row["account"],
                    "previous_seen": row["last_confirmed"] or row["first_seen"],
                    "changed": True, "changes": row["changes"] + 1,
                    "trusted_baseline_kept": True}
        c.execute("UPDATE vendors SET last_confirmed=?, offered=NULL WHERE vendor_key=?",
                  (now(), vendor_key))
        return {"status": "unchanged", "previous": row["account"], "changed": False,
                "first_seen": row["first_seen"]}


def confirm_vendor_account(vendor_key: str, confirmed_by: str = "analyst") -> dict:
    """Human verified the new details out of band -> promote them to trusted baseline."""
    with _LOCK, _conn() as c:
        row = c.execute("SELECT * FROM vendors WHERE vendor_key=?",
                        (vendor_key,)).fetchone()
        if not row:
            return {"ok": False, "error": "unknown vendor"}
        if not row["offered"]:
            return {"ok": False, "error": "no pending change to confirm"}
        c.execute("UPDATE vendors SET account=?, offered=NULL, last_confirmed=?, "
                  "changed_at=NULL, changes=0 WHERE vendor_key=?",
                  (row["offered"], now(), vendor_key))
        return {"ok": True, "vendor": vendor_key, "account": row["offered"],
                "confirmed_by": confirmed_by, "confirmed_at": now()}


# ------------------------------------------------- time-of-click ------------
def check_url_snapshot(url_key: str, score: int, tier: str, content_hash: str) -> dict:
    if not url_key:
        return {"seen_before": False}
    with _LOCK, _conn() as c:
        row = c.execute("SELECT * FROM url_snapshots WHERE url_key=?",
                        (url_key,)).fetchone()
        if not row:
            c.execute("INSERT INTO url_snapshots(url_key,score,tier,content_hash,"
                      "first_seen,last_seen) VALUES(?,?,?,?,?,?)",
                      (url_key, score, tier, content_hash, now(), now()))
            return {"seen_before": False}
        changed = bool(row["content_hash"] and content_hash and
                       row["content_hash"] != content_hash)
        score_rose = score - (row["score"] or 0)
        c.execute("UPDATE url_snapshots SET score=?, tier=?, content_hash=?, last_seen=?,"
                  " hits=hits+1 WHERE url_key=?",
                  (score, tier, content_hash or row["content_hash"], now(), url_key))
        return {"seen_before": True, "previously_clean_now_bad":
                (row["tier"] in ("safe", "low") and tier in ("suspicious", "malicious")),
                "content_changed": changed, "score_delta": score_rose,
                "first_seen": row["first_seen"], "hits": row["hits"] + 1}


# ------------------------------------------------- report-to-sweep ----------
def add_report(cluster_key: str, subject: str, sender: str, links: list[str],
               reporter: str, clicked: bool, verdict: str, score: int) -> dict:
    rid = uuid.uuid4().hex[:12]
    with _LOCK, _conn() as c:
        c.execute("INSERT INTO reports(id,cluster_key,subject,sender,links,reporter,"
                  "clicked,verdict,score,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                  (rid, cluster_key, subject, sender, json.dumps(links[:20]),
                   reporter or "anonymous", 1 if clicked else 0, verdict, score, now()))
    return {"id": rid, "cluster": cluster_stats(cluster_key)}


def cluster_stats(cluster_key: str) -> dict:
    with _LOCK, _conn() as c:
        rows = c.execute("SELECT * FROM reports WHERE cluster_key=?",
                         (cluster_key,)).fetchall()
    if not rows:
        return {"cluster_key": cluster_key, "reports": 0, "clicked": 0,
                "reporters": [], "first": None, "last": None,
                "verdict": None, "score": 0}
    return {
        "cluster_key": cluster_key,
        "reports": len(rows),
        "clicked": sum(r["clicked"] for r in rows),
        "reporters": sorted({r["reporter"] for r in rows}),
        "first": min(r["created_at"] for r in rows),
        "last": max(r["created_at"] for r in rows),
        "verdict": max(rows, key=lambda r: r["score"])["verdict"],
        "score": max(r["score"] for r in rows),
        "subject": rows[0]["subject"],
        "sender": rows[0]["sender"],
    }


def all_clusters() -> list[dict]:
    with _LOCK, _conn() as c:
        keys = [r["cluster_key"] for r in c.execute(
            "SELECT DISTINCT cluster_key FROM reports").fetchall()]
    clusters = [cluster_stats(k) for k in keys]
    return sorted(clusters, key=lambda x: (x["clicked"], x["reports"]), reverse=True)


# ----------------------------------------------------- receipts ------------
def save_receipt(subject: str, payload: dict) -> str:
    rid = "RCPT-" + uuid.uuid4().hex[:10].upper()
    payload["receipt_id"] = rid
    with _LOCK, _conn() as c:
        c.execute("INSERT INTO receipts(receipt_id,subject,payload,created_at) "
                  "VALUES(?,?,?,?)", (rid, subject, json.dumps(payload), now()))
    return rid


def get_receipt(rid: str) -> dict | None:
    with _LOCK, _conn() as c:
        row = c.execute("SELECT payload FROM receipts WHERE receipt_id=?",
                        (rid,)).fetchone()
    return json.loads(row["payload"]) if row else None


def stats() -> dict:
    with _LOCK, _conn() as c:
        q = lambda sql: c.execute(sql).fetchone()[0]
        return {
            "domains_seen": q("SELECT COUNT(*) FROM domains"),
            "senders_seen": q("SELECT COUNT(*) FROM senders"),
            "vendors_tracked": q("SELECT COUNT(*) FROM vendors"),
            "urls_tracked": q("SELECT COUNT(*) FROM url_snapshots"),
            "reports": q("SELECT COUNT(*) FROM reports"),
            "clusters": q("SELECT COUNT(DISTINCT cluster_key) FROM reports"),
            "receipts": q("SELECT COUNT(*) FROM receipts"),
        }
