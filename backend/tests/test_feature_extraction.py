"""
Tests for feature_extraction.FeatureExtractor. These are the features
the trained URL and metadata Random Forests consume at inference, so a
silent change in names or semantics would quietly degrade the models.
Pure functions, numpy only, no network.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from feature_extraction import FeatureExtractor


@pytest.fixture(scope="module")
def fx():
    return FeatureExtractor()


# ---------------------------------------------------------------------
# URL features
# ---------------------------------------------------------------------
class TestUrlFeatures:
    def test_no_urls_gives_all_zero(self, fx):
        f = fx.extract_url_features("Hello, no links in here.")
        assert f["url_count"] == 0
        assert f["has_urls"] == 0
        assert f["domain_has_ip"] == 0
        assert f["uses_https"] == 0

    def test_feature_names_match_defaults(self, fx):
        # The RF was trained on this exact key set: a rename here breaks
        # inference silently, so pin it.
        f = fx.extract_url_features("see https://example.com/a")
        assert set(f) == set(fx._get_default_url_features())

    def test_ip_host_detected(self, fx):
        f = fx.extract_url_features("go to http://192.168.10.5/login now")
        assert f["domain_has_ip"] == 1
        assert f["path_has_suspicious_keywords"] == 1
        assert f["uses_https"] == 0

    def test_ip_check_is_anchored(self, fx):
        # A hostname that merely contains digits must not count as an IP.
        f = fx.extract_url_features("https://cdn1.2.3.4example.com/x")
        assert f["domain_has_ip"] == 0

    def test_brand_spoofing_flagged(self, fx):
        f = fx.extract_url_features("https://paypal-secure-login.tk/verify")
        assert f["possible_brand_spoofing"] == 1
        assert f["domain_has_suspicious_tld"] == 1
        assert f["domain_has_hyphen"] == 1

    def test_legit_subdomain_not_spoofing(self, fx):
        f = fx.extract_url_features("https://accounts.google.com/signin")
        assert f["possible_brand_spoofing"] == 0

    def test_worst_case_aggregation(self, fx):
        # One clean URL plus one bad URL: the bad one must still surface.
        text = "https://google.com and http://10.0.0.1/account"
        f = fx.extract_url_features(text)
        assert f["url_count"] == 2
        assert f["domain_has_ip"] == 1
        # HTTPS only counts when every URL uses it
        assert f["uses_https"] == 0

    def test_shortener_detected(self, fx):
        f = fx.extract_url_features("click https://bit.ly/abc123")
        assert f["is_shortened_url"] == 1

    def test_non_numeric_port_does_not_crash(self, fx):
        f = fx.extract_url_features("http://host:TheCloud/path")
        assert f["uses_non_standard_port"] == 0

    def test_typosquatting(self, fx):
        f = fx.extract_url_features("https://gooogle.com/")
        assert f["potential_typosquatting"] == 1


# ---------------------------------------------------------------------
# Metadata features
# ---------------------------------------------------------------------
PHISHY_EML = (
    b"From: PayPal Security <alert@paypa1-support.xyz>\r\n"
    b"Reply-To: collector@evil.example\r\n"
    b"To: victim@example.com\r\n"
    b"Subject: URGENT!!! Verify your account\r\n"
    b"Received-SPF: fail (domain does not designate sender)\r\n"
    b"Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain\r\n"
    b"\r\n"
    b"Click http://paypa1-support.xyz/login to avoid suspension.\r\n"
)

CLEAN_EML = (
    b"From: Alice <alice@example.com>\r\n"
    b"To: bob@example.com\r\n"
    b"Subject: Lunch tomorrow\r\n"
    b"Message-ID: <abc@example.com>\r\n"
    b"Date: Mon, 21 Sep 2026 10:00:00 +0000\r\n"
    b"Received-SPF: pass (domain designates sender)\r\n"
    b"Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain\r\n"
    b"\r\n"
    b"Want to grab lunch at noon?\r\n"
)


class TestMetadataFeatures:
    # NB: the spf_* features read Received-SPF (that is what the RF was
    # trained on), while dkim_* / dmarc_* read Authentication-Results.

    def test_feature_names_match_defaults(self, fx):
        f = fx.extract_metadata_features(CLEAN_EML)
        assert set(f) == set(fx._get_default_metadata_features())

    def test_phishy_headers(self, fx):
        f = fx.extract_metadata_features(PHISHY_EML)
        assert f["reply_to_mismatch"] == 1
        assert f["has_reply_to"] == 1
        assert f["spf_fail"] == 1
        assert f["dkim_fail"] == 1
        assert f["dmarc_fail"] == 1
        assert f["subject_urgent_keywords"] >= 1

    def test_clean_headers(self, fx):
        f = fx.extract_metadata_features(CLEAN_EML)
        assert f["reply_to_mismatch"] == 0
        assert f["spf_pass"] == 1
        assert f["dkim_pass"] == 1
        assert f["dmarc_pass"] == 1
        assert f["has_message_id"] == 1
        assert f["has_date"] == 1

    def test_accepts_str_input(self, fx):
        f = fx.extract_metadata_features(CLEAN_EML.decode())
        assert f["spf_pass"] == 1


# ---------------------------------------------------------------------
# Helpers + combined extraction
# ---------------------------------------------------------------------
class TestHelpers:
    def test_extract_domain(self, fx):
        assert fx._extract_domain('"Bob" <bob@mail.example.org>') == "mail.example.org"
        assert fx._extract_domain("") == ""
        assert fx._extract_domain("no address here") == ""

    def test_similarity_bounds(self, fx):
        assert fx._calculate_similarity("paypal.com", "paypal.com") == 1.0
        assert fx._calculate_similarity("", "x") == 0.0
        assert fx._calculate_similarity("paypa1.com", "paypal.com") > 0.8

    def test_html_body_fallback(self, fx):
        from email import policy
        from email.parser import BytesParser
        raw = (b"From: a@b.com\r\nContent-Type: text/html\r\n\r\n"
               b"<p>Hello <b>there</b></p>")
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        body = fx._get_email_body(msg)
        assert "Hello" in body and "<b>" not in body

    def test_features_from_eml_is_flat(self, fx):
        f = fx.extract_features_from_eml(PHISHY_EML)
        # url + metadata keys all present in one flat dict
        assert "url_count" in f and "spf_fail" in f
        assert f["url_count"] == 1
