"""
Allowlisted sender domains.

An authenticated sender from one of these domains (or a subdomain) gets
the trusted_sender path: the text agent's weight is halved and only a
Safe Browsing hit can force the phishing verdict. The list never applies
to an unauthenticated sender (see sender_trust.is_trusted_domain and the
trust paths in docs/architecture.md).

Criteria for adding a domain: an institution whose legitimate
transactional mail ("verify", "statement", "alert") is often mistaken for
phishing by the text model, and that only sends from its own domain.
Personal mail providers (gmail.com, outlook.com...) are never listed.

The default list is Nigerian-centric (the project started at Nile
University of Nigeria); a fork for another region should extend it.
"""

TRUSTED_DOMAINS = frozenset({
    # Nigerian banks
    "ubagroup.com", "gtbank.com", "gtco.com", "zenithbank.com",
    "accessbankplc.com", "firstbanknigeria.com", "sterlingbankng.com",
    "ecobank.com", "fcmb.com", "fbnholdings.com", "wemabank.com",
    "polarisbanklimited.com", "unionbankng.com", "stanbicibtcbank.com",
    # Nigerian telcos
    "mtnonline.com", "mtn.ng", "airtel.com", "airtel.com.ng",
    "9mobile.com.ng", "glo.com",
    # Nigerian payment processors and fintech
    "flutterwave.com", "paystack.com", "interswitchgroup.com",
    "kuda.com", "opay.com",
    # Nigerian government and universities
    "nimc.gov.ng", "firs.gov.ng", "frsc.gov.ng", "nile.edu.ng",
    "nileuniversity.edu.ng", "abu.edu.ng", "unilag.edu.ng",
    # Nigerian hospitals
    "nizamiye.ng", "lasuth.ng", "uithniseason.org",
    # International services whose support and billing mail comes from these domains
    "google.com", "googlemail.com",
    "microsoft.com", "outlook.office365.com",
    "apple.com", "icloud.com",
    "amazon.com", "amazon.co.uk", "amazonpay.com",
    "paypal.com", "stripe.com",
    "github.com", "gitlab.com",
    "linkedin.com", "facebook.com", "facebookmail.com",
    "twitter.com", "x.com",
    "anthropic.com",
})
