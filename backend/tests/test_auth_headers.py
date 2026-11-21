"""
Tests for auth_headers.parse_authentication_results and the derived
alignment / crypto-verified logic. These are pure-function tests, no
network, no I/O, so they run in ~10 ms.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from auth_headers import org_domain, parse_authentication_results


# Organisational-domain reduction
class TestOrgDomain:
    def test_two_labels_untouched(self):
        assert org_domain("paypal.com") == "paypal.com"

    def test_three_labels_stripped_to_two(self):
        assert org_domain("mail.paypal.com") == "paypal.com"

    def test_deep_subdomain(self):
        assert org_domain("smtp.eu.mail.paypal.com") == "paypal.com"

    def test_two_part_tld_kept(self):
        # co.uk is a two-part TLD: keep 3 labels
        assert org_domain("bank.co.uk") == "bank.co.uk"
        assert org_domain("service.bank.co.uk") == "bank.co.uk"

    def test_empty(self):
        assert org_domain("") == ""

    def test_case_insensitive(self):
        assert org_domain("Mail.PayPal.COM") == "paypal.com"


# Authentication-Results parsing
class TestParseAuthResults:
    def test_no_header_present(self):
        v = parse_authentication_results({"from": "x@paypal.com"})
        assert v.header_present is False
        assert v.aligned is False
        assert v.cryptographically_verified is False

    def test_legit_all_pass_aligned(self):
        # PayPal signs with @paypal.com, mailfrom @paypal.com,
        # header.from paypal.com: canonical happy path.
        ar = (
            "mx.google.com; "
            "dkim=pass header.i=@paypal.com header.s=s1; "
            "spf=pass smtp.mailfrom=service@paypal.com; "
            "dmarc=pass header.from=paypal.com"
        )
        v = parse_authentication_results(
            {"from": "service@paypal.com", "authentication-results": ar}
        )
        assert v.spf == "pass"
        assert v.dkim == "pass"
        assert v.dmarc == "pass"
        assert v.aligned is True
        assert v.cryptographically_verified is True

    def test_spoof_dkim_by_attacker_domain(self):
        # This is the case that broke the old static allowlist:
        # attacker DKIM-signs their own domain but puts From: paypal.com.
        # The alignment check must reject this.
        ar = (
            "mx.google.com; "
            "dkim=pass header.i=@attacker.tld header.s=x; "
            "spf=pass smtp.mailfrom=noreply@attacker.tld; "
            "dmarc=fail header.from=paypal.com"
        )
        v = parse_authentication_results(
            {"from": "service@paypal.com", "authentication-results": ar}
        )
        assert v.dkim == "pass"  # DKIM verdict itself is a "pass"…
        assert v.aligned is False  # …but it aligns with attacker.tld, not paypal.com
        assert v.cryptographically_verified is False

    def test_subdomain_alignment(self):
        # DKIM signed by mail.paypal.com must count as aligned with
        # From: paypal.com: that's the organisational-domain rule.
        ar = (
            "mx.google.com; "
            "dkim=pass header.i=@mail.paypal.com; "
            "spf=pass smtp.mailfrom=x@mail.paypal.com; "
            "dmarc=pass header.from=paypal.com"
        )
        v = parse_authentication_results(
            {"from": "service@paypal.com", "authentication-results": ar}
        )
        assert v.aligned is True
        assert v.cryptographically_verified is True

    def test_dkim_fail_disables_crypto_verified_even_when_spf_passes(self):
        # SPF passing on an aligned domain is not enough for
        # cryptographically_verified: DKIM is the crypto piece.
        ar = (
            "mx.google.com; "
            "spf=pass smtp.mailfrom=x@paypal.com; "
            "dkim=fail header.i=@paypal.com; "
            "dmarc=fail header.from=paypal.com"
        )
        v = parse_authentication_results({"from": "x@paypal.com", "authentication-results": ar})
        assert v.cryptographically_verified is False

    def test_alignment_requires_pass_not_just_matching_domain(self):
        # A dmarc=fail with header.from=paypal.com must NOT count as
        # aligned even if the domains happen to match: the verdict is
        # what matters.
        ar = "mx.google.com; dkim=none; spf=none; dmarc=fail header.from=paypal.com"
        v = parse_authentication_results({"from": "x@paypal.com", "authentication-results": ar})
        assert v.aligned is False


class TestOrgDomainPublicSuffixes:
    """Two organisations under the same public suffix never align."""

    def test_country_code_registries(self):
        assert org_domain("billing.paypal.co.uk") == "paypal.co.uk"
        assert org_domain("attacker.co.uk") != org_domain("paypal.co.uk")
        assert org_domain("ib.firstbank.com.ng") == "firstbank.com.ng"
        assert org_domain("attacker.com.ng") != org_domain("firstbank.com.ng")
        assert org_domain("portal.unilag.edu.ng") == "unilag.edu.ng"
        assert org_domain("mail.uct.ac.za") == "uct.ac.za"

    def test_shared_hosting_suffixes(self):
        assert org_domain("victim.github.io") == "victim.github.io"
        assert org_domain("evil.github.io") != org_domain("victim.github.io")
        assert org_domain("x.anzouk.duckdns.org") == "anzouk.duckdns.org"

    def test_suffix_alone_and_plain_domains(self):
        assert org_domain("co.uk") == "co.uk"
        assert org_domain("a.b.example.com") == "example.com"
        assert org_domain("example.ng") == "example.ng"

    def test_dkim_from_other_org_under_same_suffix_is_not_verified(self):
        v = parse_authentication_results(
            {
                "from": "PayPal <service@paypal.co.uk>",
                "authentication-results": "mx.google.com; dkim=pass header.i=@attacker.co.uk; "
                "spf=pass smtp.mailfrom=attacker.co.uk",
            }
        )
        assert v.aligned is False and v.cryptographically_verified is False


def test_a_failing_brand_signature_does_not_lend_its_domain_to_a_passing_one():
    from auth_headers import parse_authentication_results

    v = parse_authentication_results(
        {
            "from": "PayPal <service@paypal.com>",
            "authentication-results": "mx.google.com; dkim=fail header.i=@paypal.com header.s=s1; "
            "dkim=pass header.i=@attacker.example header.s=s2; spf=pass smtp.mailfrom=attacker.example; "
            "dmarc=fail (p=REJECT) header.from=paypal.com",
        }
    )
    assert v.dkim == "pass" and v.dkim_domain == "attacker.example"
    assert not v.cryptographically_verified and not v.aligned


def test_the_aligned_signature_is_kept_whatever_its_place():
    from auth_headers import parse_authentication_results

    v = parse_authentication_results(
        {
            "from": "Bank <alerts@bank.example>",
            "authentication-results": "mx.google.com; dkim=pass header.i=@esp.example header.s=a; "
            "dkim=pass header.i=@bank.example header.s=b; spf=pass smtp.mailfrom=esp.example",
        }
    )
    assert v.dkim_domain == "bank.example" and v.cryptographically_verified


def test_an_address_in_the_display_name_is_not_the_sender():
    from auth_headers import parse_authentication_results

    v = parse_authentication_results(
        {
            "from": '"support@paypal.com" <scam@attacker.example>',
            "authentication-results": "mx.google.com; dkim=pass header.i=@attacker.example",
        }
    )
    assert v.from_domain == "attacker.example"
