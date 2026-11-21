"""Bypasses of the sender checks: Authentication-Results parsing, the From:
header, display names and brand impersonation."""

from __future__ import annotations

import asyncio
import base64

import pytest

import auth_headers as ah
import email_parsing as ep
import sender_trust as st
import structured_agents as sa
from extension_backend import AnalyseRequest, _from_value, _resolve_email

QUOTED_LOCAL_PART = (
    'mx.google.com; spf=pass (google.com: domain of "dkim=pass header.i=@paypal.com "'
    "@attacker.example designates 192.0.2.1 as permitted sender) "
    'smtp.mailfrom="dkim=pass header.i=@paypal.com "@attacker.example; '
    "dkim=fail header.i=@paypal.com"
)


def verdict(ar: str, from_: str = "service@paypal.com", **extra) -> ah.AuthVerdict:
    return ah.parse_authentication_results({"from": from_, "authentication-results": ar, **extra})


def test_result_in_quoted_address_or_comment_ignored():
    v = verdict(QUOTED_LOCAL_PART)
    assert v.dkim == "fail"
    assert v.spf_domain == "attacker.example"
    assert not v.cryptographically_verified


def test_a_result_must_start_its_clause():
    v = verdict(
        "mx.example; spf=pass smtp.mailfrom=x@attacker.example dkim=pass header.d=paypal.com"
    )
    assert v.dkim == "none"
    assert not v.cryptographically_verified


def test_microsoft_365_results_without_server_name():
    ar = (
        "spf=pass (sender IP is 192.0.2.1) smtp.mailfrom=contoso.com; dkim=pass "
        "(signature was verified) header.d=contoso.com;dmarc=pass action=none "
        "header.from=contoso.com;compauth=pass reason=100"
    )
    v = verdict(ar, from_="a@contoso.com")
    assert (v.spf, v.dkim, v.dmarc) == ("pass", "pass", "pass")
    assert v.cryptographically_verified


def test_arc_results_alone_prove_nothing():
    v = ah.parse_authentication_results(
        {
            "from": "service@paypal.com",
            "arc-authentication-results": "i=1; mx.google.com; dkim=pass header.d=paypal.com",
        }
    )
    assert v.header_present and v.dkim == "pass"
    assert not v.cryptographically_verified and not v.aligned


def test_two_from_headers_prove_nothing():
    headers = ep.header_dict(
        [
            ("From", "PayPal <service@paypal.com>"),
            ("From", "x@attacker.example"),
            ("Authentication-Results", "mx.google.com; dkim=pass header.d=paypal.com"),
        ]
    )
    assert headers["from"] == "PayPal <service@paypal.com>"
    assert not ah.parse_authentication_results(headers).cryptographically_verified


def test_message_cannot_set_duplicate_marker():
    headers = ep.header_dict([("From", "a@b.example"), (ep.FROM_UNPROVEN, "0")])
    assert ep.FROM_UNPROVEN not in headers


def test_lenient_parser_decodes_encoded_words():
    assert ep.header_dict([("From", "=?utf-8?b?UGF5UGFs?= <a@evil.example>")])["from"] == (
        "PayPal <a@evil.example>"
    )


def test_gmail_values_not_host_names_dropped():
    ctx = {"origin": "gmail", "gmail_signed_by": "paypal.com; dmarc=pass header.from=paypal.com"}
    assert st.synthesize_auth_results(ctx, "a@paypal.com") == ""
    ctx = {"origin": "gmail", "gmail_signed_by": "paypal.com"}
    v = verdict(st.synthesize_auth_results(ctx, "a@paypal.com"), from_="a@paypal.com")
    assert v.cryptographically_verified and v.dmarc == "pass"


@pytest.mark.parametrize(
    "from_",
    [
        '"PayPal" <service@paypal.xyz>',
        '"PayPal" <service@paypal.duckdns.org>',
        '"E.Leclerc" <info@e.xyz>',
        '"Chrono​post" <x@evil.example>',
        '"Chrono­post" <x@evil.example>',
        '"Chronopost' + " " * 600 + '" <x@evil.example>',
        '"PаyPаl" <x@evil.example>',
        '"DНL" <x@evil.example>',
        '"PayPal\\" <x@evil.example>',
        "PayPal <x@evil.example> <service@paypal.com>",
        '"PayPal" <service@paypal.tk>',
        '"PayPal" <service@paypal.co>',
        '"Chronopost" <colis@chronopost.ml>',
        '"Impots.gouv.fr" <avis@gouv.com>',
        '"FIRS" <x@gov.com>',
        '"' + "\u200b" * 300 + 'PayPal" <x@evil.example>',
        '"Info" <x@evil.example>, "PayPal" <x@evil.example>',
        '"Chronopost" <info@chronopost.us>',
        '"PayPal" <service@paypal.vc>',
        '"GTBank" <alerts@gtbank.in>',
        '"PayPal" <service@paypal.info>',
        '"PayPal" <service@paypal.com>, <scam@evil.example>',
        '"Amel\u0131" <x@evil.example>',
        '"PayPa\u0142" <x@evil.example>',
        '"\u1d18\u1d00\u028f\u1d18\u1d00\u029f" <x@evil.example>',
        "\u1d1c\u1d18\ua731 <x@evil.example>",
    ],
)
def test_impersonation_variants_are_caught(from_):
    assert st.impersonated_brand(from_)


@pytest.mark.parametrize(
    "from_",
    [
        "PayPal <service@paypal.com>",
        "PayPal <service@mail.paypal.co.uk>",
        "PayPal <service@paypal.de>",
        "E.Leclerc <info@e.leclerc>",
        "BNP Paribas <x@mabanque.bnpparibas>",
        "Impots <x@dgfip.finances.gouv.fr>",
        "Amazon <x@amazon.co.jp>",
        "PayPal <service@paypal.fr>",
        "DHL <noreply@dhl.de>",
        "GTBank <alerts@gtbank.com>",
        "Airtel <x@airtel.com.ng>",
        "Societe Generale <x@particuliers.sg.fr>",
        "service@paypal.com",
    ],
)
def test_the_brands_own_addresses_are_not_impersonation(from_):
    assert st.impersonated_brand(from_) is None


def test_invisible_padding_removed_before_name_cut():
    value = _from_value("x@evil.example", "\u200b" * 300 + "PayPal")
    assert st.impersonated_brand(value) == "paypal"


def test_rule_sender_score_checks_impersonation():
    assert sa.metadata_agent({"from": "Chronopost <x@qdsodd.example>"}) == pytest.approx(0.5)


def test_a_name_ending_in_a_backslash_keeps_its_quotes():
    value = _from_value("x@evil.example", "PayPal\\")
    assert st.impersonated_brand(value) == "paypal"
    assert st.sender_domain(value) == "evil.example"


def test_only_the_topmost_result_header_is_read():
    # On Gmail, the sender's headers come right after Gmail's own
    # Authentication-Results: a second one, wherever it sits, could be the
    # sender's, so it is never joined (docs/threat-model.md, R11).
    headers = ep.header_dict(
        [
            ("Received", "from evil by mx.google.com"),
            ("Authentication-Results", "mx.google.com; spf=pass smtp.mailfrom=evil.example"),
            ("Authentication-Results", "mx.google.com; dkim=pass header.d=bank.example"),
            ("Received", "from x by y"),
            ("From", "Bank <alerts@bank.example>"),
        ]
    )
    assert "bank.example" not in headers["authentication-results"]
    assert not ah.parse_authentication_results(headers).cryptographically_verified


def test_a_from_with_several_addresses_proves_nothing():
    v = verdict(
        "mx.google.com; dkim=pass header.d=paypal.com",
        from_='"PayPal" <service@paypal.com>, <scam@evil.example>',
    )
    assert not v.cryptographically_verified


@pytest.mark.parametrize(
    ("answer", "listed"),
    [("127.0.1.4", "phish"), ("127.0.1.99", "listed_unknown_code"), ("127.255.255.254", None)],
)
def test_spamhaus_answers(monkeypatch, answer, listed):
    monkeypatch.setattr(ah.socket, "gethostbyname", lambda _q: answer)
    out = asyncio.run(ah.spamhaus_dbl("evil.example"))
    assert (out or {}).get("category") == listed


def test_spaces_cannot_push_address_past_checks():
    headers = ep.header_dict([("From", '"PayPal' + " " * 3000 + '" <scam@evil.example>')])
    assert st.impersonated_brand(headers["from"]) == "paypal"
    headers = ep.header_dict(
        [
            ("From", '"PayPal" <service@paypal.com>' + " " * 3000 + ", <scam@evil.example>"),
            ("Authentication-Results", "mx.google.com; dkim=pass header.d=paypal.com"),
        ]
    )
    assert not ah.parse_authentication_results(headers).cryptographically_verified
    long_from = ep.header_dict([("From", "x" * 9000 + "@a.example")])
    assert ep.FROM_UNPROVEN in long_from


def test_attached_email_proves_nothing():
    eml = (
        b"From: GTBank <alerts@gtbank.com>\r\n"
        b"Authentication-Results: mx.google.com; dkim=pass header.i=@gtbank.com; "
        b"dmarc=pass header.from=gtbank.com\r\n\r\nYour account statement is ready."
    )
    req = AnalyseRequest(
        raw_email_b64=base64.b64encode(eml).decode(),
        client_context={"headers_source": "attachment"},
    )
    _body, _u, headers, _raw = _resolve_email(req)
    assert "authentication-results" not in headers


@pytest.mark.parametrize("padding", [" " * 32_000, "​" * 9_000])
def test_padding_keeps_second_from_address(padding):
    headers = ep.header_dict(
        [
            ("From", '"PayPal" <service@paypal.com>' + padding + ", <scam@evil.example>"),
            ("Authentication-Results", "mx.google.com; dkim=pass header.d=paypal.com"),
        ]
    )
    assert "scam@evil.example" in headers["from"]
    assert st.impersonated_brand(headers["from"]) == "paypal"
    assert not ah.parse_authentication_results(headers).cryptographically_verified


def test_padded_display_name_keeps_brand():
    value = _from_value("x@evil.example", "͏" * 300 + "PayPal")
    assert st.impersonated_brand(value) == "paypal"


def test_two_address_from_survives_page_sender():
    eml = b'From: "PayPal" <service@paypal.com>, <scam@evil.example>\r\n\r\nHello there friend'
    req = AnalyseRequest(
        raw_email_b64=base64.b64encode(eml).decode(),
        sender_email="service@paypal.com",
        sender_name="PayPal",
    )
    _body, _urls, headers, _raw = _resolve_email(req)
    assert "scam@evil.example" in headers["from"]
    assert headers.get(ep.FROM_UNPROVEN) == "1"


@pytest.mark.parametrize(
    "header",
    [
        '"PayPal" <service@paypal.com> <scam@evil.example>',
        '"PayPal" <"service@paypal.com"@evil.example>',
        '"support@paypal.com" <scam@evil.example',
        "PayPal <service@paypal.com@evil.example>",
        "Pay\u064b\u200c\u064bPal <x@evil.example>",
        "Pay\u093c\u200d\u093cPal <x@evil.example>",
        "Pay\x7fPal <x@evil.example>",
        "V\u180berify PayPal <x@evil.example>",
    ],
)
def test_every_domain_of_a_from_is_checked(header):
    assert st.impersonated_brand(header) == "paypal"
    assert ah.sender_domain(header) == "evil.example"


def test_a_from_naming_two_domains_proves_nothing():
    v = ah.parse_authentication_results(
        {
            "from": '"PayPal" <service@paypal.com> <scam@evil.example>',
            "authentication-results": "mx.google.com; dkim=pass header.d=paypal.com; "
            "spf=pass smtp.mailfrom=paypal.com; dmarc=pass header.from=paypal.com",
        }
    )
    assert not v.cryptographically_verified
    assert ah.sender_domains('"Jane (jane@gmail.com) via Docs" <drive@google.com>') == [
        "google.com"
    ]


def test_two_angle_addresses_keep_from():
    eml = b'From: "PayPal" <service@paypal.com> <scam@evil.example>\r\n\r\nHello there friend'
    req = AnalyseRequest(
        raw_email_b64=base64.b64encode(eml).decode(),
        sender_email="service@paypal.com",
        sender_name="PayPal",
    )
    _body, _urls, headers, _raw = _resolve_email(req)
    assert "scam@evil.example" in headers["from"]
    assert headers.get(ep.FROM_UNPROVEN) == "1"


def test_from_read_as_written_not_rebuilt():
    body, _urls, headers = ep.parse_eml(
        b'From: "PayPal" <service@paypal.com> <scam@evil.example>\r\nSubject: Hi\r\n\r\nHello'
    )
    assert "scam@evil.example" in headers["from"]
    _b, _u, headers = ep.parse_eml("From: Andr\u00e9 <a@example.com>\r\n\r\nHi".encode())
    assert headers["from"] == "Andr\u00e9 <a@example.com>"


@pytest.mark.parametrize(
    "name",
    [
        "Amaz\u0585n <x@evil.example>",
        "\u13e2ayPal <x@evil.example>",
        "p\u0251yp\u0251l <x@evil.example>",
    ],
)
def test_more_look_alike_letters(name):
    assert st.impersonated_brand(name) in ("amazon", "paypal")


@pytest.mark.parametrize(
    "header",
    [
        '"=?utf-8?b?UGF5UGFs?=" <a@evil.example>',
        "=?utf-8?b?UGF5UGFs?=<a@evil.example>",
        "=?utf-8?b?UGF5?==?utf-8?b?UGFs?= <a@evil.example>",
        "=?utf-8?b?UGF5?= =?utf-8?b?UGFs?= <a@evil.example>",
    ],
)
def test_encoded_names_wherever_they_stand(header):
    _b, _u, headers = ep.parse_eml(f"From: {header}\r\n\r\nHello".encode())
    assert st.impersonated_brand(headers["from"]) == "paypal"


@pytest.mark.parametrize(
    "header",
    [
        '"Jane <jane@gmail.com> (via Google Docs)" <drive-shares-noreply@google.com>',
        '"jane@example.org via LinkedIn" <messages-noreply@linkedin.com>',
        "Jane Doe (jane@gmail.com) <notifications@github.com>",
    ],
)
def test_display_name_addresses_not_senders(header):
    assert len(ah.sender_domains(header)) == 1
    assert st.impersonated_brand(header) is None


def test_webmail_address_alone_in_name_claims_brand():
    assert st.impersonated_brand('"security@gmail.com" <alerts@evil.example>') == "gmail"


@pytest.mark.parametrize(
    ("raw", "domains", "brand"),
    [
        (
            b"From: =?UTF-8?Q?Andr=C3=A9_=3Candre=40gmail=2Ecom=3E_=28via_Google_Docs=29?= "
            b"<drive-shares-dm-noreply@google.com>\r\n\r\nHi",
            ["google.com"],
            None,
        ),
        (b"From: =?UTF-8?Q?Doe=2C_Jane?= <jane@corp.example>\r\n\r\nHi", ["corp.example"], None),
        (
            b"From: =?utf-8?b?UGF5?=\r\n =?utf-8?b?UGFs?= <a@evil.example>\r\n\r\nHi",
            ["evil.example"],
            "paypal",
        ),
    ],
)
def test_encoded_names_stay_names(raw, domains, brand):
    _b, _u, headers = ep.parse_eml(raw)
    assert ah.sender_domains(headers["from"]) == domains
    assert st.impersonated_brand(headers["from"]) == brand


@pytest.mark.parametrize(
    ("header", "brand"),
    [
        ('"Security <security@gmail.com>" <scam@evil.example>', "gmail"),
        ('"Support (support@outlook.com)" <scam@evil.example>', "outlook"),
        ("PayPal <scam@evil.example", "paypal"),
        ("scam@evil.example (PayPal)", "paypal"),
        ("<scam@evil.example> (PayPal)", "paypal"),
        ("Jane Doe (jane@gmail.com) <notifications@github.com>", None),
    ],
)
def test_names_in_every_form(header, brand):
    assert st.impersonated_brand(header) == brand


def test_address_in_quoted_local_part_proves_nothing():
    v = ah.parse_authentication_results(
        {
            "from": '<"ceo@victim.example"@evil.example>',
            "authentication-results": "mx.google.com; dkim=pass header.d=evil.example",
        }
    )
    assert not v.cryptographically_verified
    assert ah.sender_domain('<"ceo@victim.example"@evil.example>') == "evil.example"


@pytest.mark.parametrize(
    "header",
    [
        '"Jane (jane@outlook.com) (via Google Docs)" <drive-shares-dm-noreply@google.com>',
        '"Jane (jane@icloud.com)" <dse@docusign.net>',
        '"Jane <jane@hotmail.com> via Dropbox" <no-reply@dropboxmail.com>',
    ],
)
def test_sharing_services_carry_their_users_webmail(header):
    assert st.impersonated_brand(header) is None


@pytest.mark.parametrize(
    ("raw", "domains", "brand"),
    [
        (
            b'From: "=?UTF-8?Q?Andr=C3=A9_=3Candre=40gmail=2Ecom=3E?= (via Google Docs)" '
            b"<drive-shares-dm-noreply@google.com>\r\n\r\nHi",
            ["google.com"],
            None,
        ),
        (
            b'From: "PayPal" <service@paypal.com> =?UTF-8?Q?=3Cscam=40evil=2Eexample=3E?=\r\n\r\nHi',
            ["paypal.com", "evil.example"],
            "paypal",
        ),
        (
            b'From: "=?UTF-8?Q?a=22_=3Cservice=40paypal=2Ecom=3E_=22b?=" <scam@evil.example>\r\n\r\nHi',
            ["evil.example"],
            "paypal",
        ),
    ],
)
def test_encoded_words_keep_the_quoting_they_stand_in(raw, domains, brand):
    _b, _u, headers = ep.parse_eml(raw)
    assert ah.sender_domains(headers["from"]) == domains
    assert st.impersonated_brand(headers["from"]) == brand


@pytest.mark.parametrize(
    "header",
    [
        '"Info" <x@evil.example>, PayPal <scam@evil.example',
        "<scam@evil.example> (PayPal (Support))",
    ],
)
def test_names_after_address_and_nested_comments(header):
    assert st.impersonated_brand(header) == "paypal"


@pytest.mark.parametrize(
    ("header", "brand"),
    [
        (
            '"Jane Doe (jane@microsoft.com) (via Google Docs)" <drive-shares-dm-noreply@google.com>',
            None,
        ),
        ('"Jane Doe (jane@amazon.com)" <dse@docusign.net>', None),
        ('"Jane Doe (via SharePoint)" <no-reply@sharepointonline.com>', None),
        ('"Amazon Pay" <no-reply@amazonpay.com>', None),
        ('"La Poste Colissimo" <noreply@colissimo.fr>', None),
        (
            '"PayPal Security (attacker@gmail.com) (via Google Docs)" <drive-shares-dm-noreply@google.com>',
            "paypal",
        ),
        ('"Jane (jane@microsoft.com)" <x@evil.example>', "microsoft"),
    ],
)
def test_real_senders_and_their_users_addresses(header, brand):
    assert st.impersonated_brand(header) == brand
