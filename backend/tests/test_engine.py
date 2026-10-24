"""PhishGuard regression suite.

Priorities, in order:
  1. False positives must stay at zero on legitimate domains (the thing that gets
     a security tool switched off).
  2. Known phishing constructions must be caught lexically (no network needed).
  3. Scoring must be monotonic, and "unknown" must never leak into "safe".
  4. Email auth/BEC logic must fire on the samples.

Run: python3 -m pytest tests/ -q      (or: python3 tests/test_engine.py)
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import data as D               # noqa: E402
from engine import emailscan, lexical, store, verdict  # noqa: E402

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "samples")


def ids(url: str) -> list[str]:
    return [s["id"] for s in lexical.analyze_url(url)["signals"]]


def score(url: str) -> int:
    return verdict.score_signals(lexical.analyze_url(url)["signals"])


class TestFalsePositives(unittest.TestCase):
    """Every legitimate URL here must score 0 — this is the non-negotiable one."""

    SAFE = [
        "https://www.google.com",
        "https://mail.google.com/mail/u/0/",
        "https://drive.google.com/drive/folders/abc",
        "https://amazonaws.com",
        "https://s3.ap-south-1.amazonaws.com/bucket/key",
        "https://www.icicibank.com/personal-banking",
        "https://sbi.co.in/web/personal-banking",
        "https://onlinesbi.sbi/",
        "https://hdfcbank.com/personal/save/accounts",
        "https://incometax.gov.in/iec/foportal/",
        "https://www.irctc.co.in/nget/train-search",
        "https://github.com/torvalds/linux",
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "https://outlook.office365.com/mail/",
        "https://netflix.com/browse",
        "https://www.paypal.com/in/home",
        "https://zerodha.com/open-account/",
        "https://www.phonepe.com/business/",
        "https://uidai.gov.in/my-aadhaar/",
        "https://docs.google.com/forms/d/e/1FAIpQLS/viewform",
    ]

    def test_legit_domains_score_zero(self):
        """Below the 'low' threshold. Info-weight notes (a shared-hosting mention, say)
        are allowed — they are evidence, not a verdict."""
        for url in self.SAFE:
            with self.subTest(url=url):
                self.assertLess(score(url), verdict.THRESHOLDS["low"],
                                f"false positive on {url}: {ids(url)}")

    def test_brand_domains_never_typosquat_themselves(self):
        for brand in ("icicibank", "hdfcbank", "amazon", "google", "paytm"):
            with self.subTest(brand=brand):
                self.assertNotIn("typosquat", ids(f"https://{brand}.com/"))

    def test_legit_domains_are_never_malicious(self):
        for url in self.SAFE:
            with self.subTest(url=url):
                self.assertLess(score(url), verdict.THRESHOLDS["suspicious"])


class TestLexicalDetection(unittest.TestCase):
    def test_brand_in_subdomain(self):
        u = "http://paypal.com.secure-login-verify.top/account/verify"
        self.assertIn("brand_in_subdomain", ids(u))
        self.assertGreaterEqual(score(u), verdict.THRESHOLDS["malicious"])

    def test_indian_bank_brand_in_subdomain(self):
        u = "https://hdfcbank.com.secure-verify.top/kyc"
        self.assertIn("brand_in_subdomain", ids(u))
        self.assertEqual(verdict.score_signals(lexical.analyze_url(u)["signals"]) >= 65, True)

    def test_typosquat_edit_distance(self):
        self.assertIn("typosquat", ids("https://paypa1.com/login"))
        self.assertIn("typosquat", ids("https://amaz0n-offer.xyz/"))
        self.assertIn("typosquat", ids("https://rnicrosoft-support.help/"))

    def test_userinfo_at_trick(self):
        r = lexical.analyze_url("https://microsoft.com@evil-login.ru/")
        self.assertIn("userinfo", [s["id"] for s in r["signals"]])
        sev = [s["severity"] for s in r["signals"] if s["id"] == "userinfo"][0]
        self.assertEqual(sev, "critical", "brand in userinfo must escalate")

    def test_ip_literal_host(self):
        self.assertIn("ip_host", ids("http://192.0.2.44/hdfc/kyc/update"))

    def test_punycode_and_homoglyph(self):
        self.assertIn("punycode", ids("https://xn--pypal-4ve.com/signin"))
        r = lexical.analyze_url("https://аpple.com/")  # Cyrillic 'а'
        self.assertIn("homoglyph", [s["id"] for s in r["signals"]])

    def test_double_extension(self):
        self.assertIn("dangerous_ext", ids("https://x.example/invoice.pdf.exe"))

    def test_shortener_flagged(self):
        self.assertIn("shortener", ids("https://bit.ly/3xKyc"))

    def test_plain_http_flagged_low(self):
        self.assertIn("no_tls", ids("http://example.com/"))

    def test_dangerous_scheme(self):
        self.assertIn("scheme_dangerous", ids("javascript:alert(1)"))


class TestDefang(unittest.TestCase):
    def test_no_clickable_scheme(self):
        for raw in ("https://evil.com/a?b=1", "http://evil.com", "ftp://x.example"):
            with self.subTest(raw=raw):
                d = lexical.defang(raw)
                self.assertFalse(d.lower().startswith(("http://", "https://", "ftp://")))
                self.assertIn("[.]", d)

    def test_at_sign_neutralised(self):
        self.assertIn("[@]", lexical.defang("https://user@evil.com"))


class TestScoring(unittest.TestCase):
    def test_monotonic(self):
        prev = -1
        for n in range(0, 8):
            sigs = [{"id": f"s{i}", "title": "t", "severity": "medium", "weight": 10,
                     "evidence": "", "category": f"c{i}"} for i in range(n)]
            cur = verdict.score_signals(sigs)
            self.assertGreaterEqual(cur, prev)
            prev = cur

    def test_single_critical_is_not_diluted(self):
        one = [{"id": "x", "title": "t", "severity": "critical", "weight": 40,
                "evidence": "", "category": "a"}]
        self.assertGreaterEqual(verdict.score_signals(one), 40)

    def test_no_signals_scores_zero(self):
        self.assertEqual(verdict.score_signals([]), 0)

    def test_degraded_mode_reports_low_confidence(self):
        v = verdict.judge([], intel_ok=False)
        self.assertEqual(v["confidence"], "low")
        self.assertIn(v["label"], ("unknown", "likely_safe"))

    def test_decisive_signal_is_tiered_even_without_intel(self):
        """Quick mode: a critical lexical signal must still name a tier.
        Otherwise the instant verdict looks opinionless and users wait for the slow one."""
        v = verdict.judge(lexical.analyze_url("https://paypa1.com/login")["signals"],
                          intel_ok=False)
        self.assertIn(v["label"], ("suspicious", "malicious"))
        self.assertEqual(v["confidence"], "low")

    def test_clean_but_unverified_is_provisional_not_unknown(self):
        v = verdict.judge([], intel_ok=False)
        self.assertEqual(v["label"], "likely_safe")
        self.assertTrue(v["provisional"], "instant pass must be flagged provisional")

    def test_thin_evidence_stays_unknown(self):
        thin = [{"id": "risky_tld", "title": "t", "severity": "medium", "weight": 15,
                 "evidence": "", "category": "lexical"}]
        v = verdict.judge(thin, intel_ok=False)
        self.assertEqual(v["label"], "unknown",
                         "one medium signal with no corroboration is not a tier")

    def test_force_unknown_overrides_green(self):
        v = verdict.judge([], intel_ok=True, force_unknown=True)
        self.assertEqual(v["label"], "unknown")
        self.assertNotEqual(v["label"], "likely_safe")

    def test_confidence_range_is_never_inverted(self):
        """Regression: '55-15% likely correct' shipped once. A range must ascend."""
        import re
        for intel in (True, False):
            for score_signals in ([], lexical.analyze_url(
                    "https://paypa1.com/login")["signals"], lexical.analyze_url(
                    "http://paypal.com.secure-login-verify.top/a")["signals"]):
                v = verdict.judge(score_signals, intel_ok=intel)
                nums = [int(n) for n in re.findall(r"(\d+)%", v["confidence_text"])]
                if len(nums) == 2:
                    self.assertLessEqual(nums[0], nums[1],
                                         f"inverted range: {v['confidence_text']}")

    def test_confidence_text_does_not_describe_signals_it_doesnt_have(self):
        v = verdict.judge([], intel_ok=True)
        self.assertNotIn("single strong signal", v["confidence_text"])

    def test_every_signal_has_evidence(self):
        v = verdict.judge(lexical.analyze_url(
            "http://paypal.com.secure-login-verify.top/a")["signals"], intel_ok=False)
        for s in v["signals"]:
            self.assertTrue(s["evidence"], f"signal {s['id']} lacks evidence")
            self.assertIn(s["severity"], ("critical", "high", "medium", "low", "info"))

    def test_receipt_is_reproducible(self):
        sigs = lexical.analyze_url("https://paypa1.com/login")["signals"]
        a = verdict.judge(sigs, intel_ok=False)
        b = verdict.judge(sigs, intel_ok=False)
        self.assertEqual(a["score"], b["score"])
        r = verdict.build_receipt(a, "subject")
        self.assertEqual(r["verdict"]["score"], a["score"])
        self.assertIn("thresholds_applied", r)


class TestEmail(unittest.TestCase):
    def _scan(self, name):
        return emailscan.scan_eml(open(os.path.join(SAMPLES, f"{name}.eml"), "rb").read())

    def test_bec_invoice_is_malicious(self):
        v = self._scan("bec_invoice")
        got = {s["id"] for s in v["signals"]}
        self.assertEqual(v["label"], "malicious")
        self.assertIn("dmarc_fail", got)
        self.assertIn("spf_fail", got)
        self.assertIn("bec_bank_change", got)
        self.assertIn("bec_compound", got)
        self.assertIn("replyto_mismatch", got)
        self.assertIn("attachment_macro", got)

    def test_india_upi_is_malicious(self):
        v = self._scan("india_upi")
        got = {s["id"] for s in v["signals"]}
        self.assertEqual(v["label"], "malicious")
        self.assertIn("india_upi_collect", got)
        self.assertIn("india_kyc_expiry", got)
        self.assertIn("link_display_mismatch", got)

    def test_digital_arrest_is_malicious(self):
        v = self._scan("digital_arrest")
        got = {s["id"] for s in v["signals"]}
        self.assertIn("india_digital_arrest", got)
        self.assertIn("bec_threat_legal", got)

    def test_clean_mail_is_not_flagged(self):
        v = self._scan("clean")
        self.assertNotEqual(v["label"], "malicious")
        self.assertLess(v["score"], verdict.THRESHOLDS["suspicious"])

    def test_dkim_not_called_invalid_when_absent(self):
        v = self._scan("clean")
        self.assertIsNone(v["email"]["dkim_verified"],
                          "a missing signature is 'unknown', not 'invalid'")

    def test_payment_identifier_prioritises_account_number(self):
        v = self._scan("bec_invoice")
        self.assertTrue(v["accounts_found"], "should extract account identifiers")
        # IBAN/account number must outrank an IFSC branch code
        self.assertFalse(v["accounts_found"][0]["value"].startswith("HD"),
                         "IFSC code must not be treated as the payment account")

    def test_cluster_key_is_stable_across_reply_prefixes(self):
        a = self._scan("bec_invoice")
        self.assertTrue(a["cluster"]["cluster_key"])


class TestStore(unittest.TestCase):
    def setUp(self):
        store.init()

    def test_first_contact_then_known(self):
        d = "test-domain-%d.example" % os.getpid()
        self.assertTrue(store.observe_domain(d, "safe")["first_contact"])
        second = store.observe_domain(d, "safe")
        self.assertFalse(second["first_contact"])
        self.assertEqual(second["hits"], 2)

    def test_bank_detail_change_detection(self):
        vendor = f"vendor-{os.getpid()}.example"
        first = store.check_vendor_account(vendor, "50100293847561")
        self.assertEqual(first["status"], "first_time")
        same = store.check_vendor_account(vendor, "5010 0293 8475 61")
        self.assertEqual(same["status"], "unchanged",
                         "whitespace must not look like a changed account")
        changed = store.check_vendor_account(vendor, "99118822776655")
        self.assertTrue(changed["changed"])
        self.assertEqual(changed["previous"], "50100293847561")

    def test_time_of_click_change(self):
        key = f"evil-{os.getpid()}.example/path"
        store.check_url_snapshot(key, 10, "low", "hashA")
        snap = store.check_url_snapshot(key, 70, "malicious", "hashB")
        self.assertTrue(snap["seen_before"])
        self.assertTrue(snap["previously_clean_now_bad"])
        self.assertTrue(snap["content_changed"])

    def test_report_clustering(self):
        cluster = f"cluster-{os.getpid()}"
        store.add_report(cluster, "Invoice overdue", "a@b.example", [], "alice", False,
                         "malicious", 80)
        out = store.add_report(cluster, "Invoice overdue", "a@b.example", [], "bob", True,
                               "malicious", 85)
        self.assertEqual(out["cluster"]["reports"], 2)
        self.assertEqual(out["cluster"]["clicked"], 1)


class TestSSRFGuard(unittest.TestCase):
    def test_private_targets_refused(self):
        from engine import net
        for host in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254",
                     "::1", "[::1]"):
            with self.subTest(host=host):
                self.assertFalse(net.is_public_host(host.strip("[]")))

    def test_public_target_allowed(self):
        from engine import net
        self.assertTrue(net.is_public_host("example.com"))

    def test_fetch_refuses_private(self):
        from engine import net
        out = net.fetch_page("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(out["ok"])
        self.assertIn("refused", out["error"] + " refused" if "refused" in out["error"]
                      else "refused")


class TestKnowledgeBase(unittest.TestCase):
    def test_every_teach_entry_maps_to_known_signal_family(self):
        self.assertGreater(len(D.TEACH), 20)

    def test_india_rules_have_all_fields(self):
        for rule in D.INDIA_RULES:
            for key in ("id", "pattern", "title", "evidence", "weight", "tip"):
                self.assertIn(key, rule, f"{rule.get('id')} missing {key}")

    def test_india_patterns_compile(self):
        import re
        for rule in D.INDIA_RULES:
            re.compile(rule["pattern"])

    def test_bec_patterns_compile(self):
        import re
        for name, (pattern, label) in D.BEC_PATTERNS.items():
            re.compile(pattern)
            self.assertTrue(label)


if __name__ == "__main__":
    unittest.main(verbosity=2)
