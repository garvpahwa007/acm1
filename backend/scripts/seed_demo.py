"""Seed the demo state so the differentiating features are visible immediately.

Idempotent-ish: run with --reset to wipe and rebuild.

What it seeds:
  * a vendor bank-detail baseline from 3 months ago -> so the BEC sample demonstrates
    a real "account number CHANGED" diff on first run, not just a lexicon match
  * two report-to-sweep clusters -> so the Org sweep tab has content and the
    "N people reported this" social proof is visible
  * a couple of domain sightings -> so first-contact detection isn't trivially noisy

Usage: python3 scripts/seed_demo.py --reset
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import store  # noqa: E402


def ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")


def seed(reset: bool):
    if reset:
        path = os.path.abspath(store.DB_PATH)
        if os.path.exists(path):
            os.remove(path)
            print(f"removed {path}")
    store.init()

    # 1. Vendor baseline: the account these invoices used for the last three months.
    #    The sample BEC email presents a different one -> 'CHANGED'.
    import sqlite3
    with sqlite3.connect(store.DB_PATH) as c:
        c.execute("INSERT OR REPLACE INTO vendors(vendor_key,account,first_seen,changed_at,changes)"
                  " VALUES(?,?,?,?,?)",
                  ("vendorsupplies-billing.co", "40188271004932", ago(96), None, 0))
        c.execute("INSERT OR REPLACE INTO vendors(vendor_key,account,first_seen,changed_at,changes)"
                  " VALUES(?,?,?,?,?)",
                  ("acme-componentworks.in", "00991188227766", ago(210), None, 0))
    print("seeded 2 vendor bank-detail baselines")

    # 2. Report-to-sweep clusters.
    clusters = [
        ("a91f4c7d2b8e1063", "URGENT: Revised remittance details for Invoice INV-2291",
         "accounts@vendorsupplies-billing.co", "malicious", 96,
         [("neha.finance", False), ("arjun.ap", True), ("deepak.treasury", False)]),
        ("brand-ish-kyc-campaign", "Your KYC is expiring today - account will be blocked",
         "alert@upi-kyc-verify.top", "malicious", 94,
         [("rohit.s", False), ("meera.k", False)]),
    ]
    for key, subject, sender, verdict, score, people in clusters:
        for who, clicked in people:
            store.add_report(key, subject, sender,
                             ["http://sbi.kyc-update-verify.top/login/verify"],
                             who, clicked, verdict, score)
    print(f"seeded {sum(len(c[5]) for c in clusters)} reports across 2 clusters")

    # 3. Domain sightings, including the legitimate ones, so first-contact means something.
    for dom, tier in [("yourcompany.com", "safe"), ("google.com", "safe"),
                      ("hdfcbank.com", "safe"), ("irctc.co.in", "safe"),
                      ("github.com", "safe")]:
        store.observe_domain(dom, tier)

    print("\nstate:", store.stats())
    print("\nNow: open the app, Email tab -> 'load sample: BEC bank-change'.")
    print("Expect: critical 'Bank details CHANGED vs this vendor's previous invoice'.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--reset", action="store_true", help="delete the database first")
    seed(ap.parse_args().reset)
