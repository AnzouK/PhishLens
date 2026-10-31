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
Personal mail providers (gmail.com, googlemail.com, icloud.com...) are
never listed, nor platforms that send their users' own words under their
domain: document shares, invoices and money requests, signature
envelopes, private messages and notifications (google.com, paypal.com,
docusign.net, dropbox.com, linkedin.com, facebookmail.com, github.com,
x.com...). Their signed mail still gets the crypto_verified path, where
links leading away from the platform with phishing-like wording are
flagged; here, only a Safe Browsing hit would.

The list started with Nigerian institutions and now also covers large
European and international senders; a fork for another region should
extend it. Mail providers whose users have addresses on the domain
(orange.fr, free.fr, laposte.net...) are left out.
"""

TRUSTED_DOMAINS = frozenset(
    {
        # Nigerian banks
        "ubagroup.com",
        "gtbank.com",
        "gtco.com",
        "zenithbank.com",
        "accessbankplc.com",
        "firstbanknigeria.com",
        "sterlingbankng.com",
        "ecobank.com",
        "fcmb.com",
        "fbnholdings.com",
        "wemabank.com",
        "polarisbanklimited.com",
        "unionbankng.com",
        "stanbicibtcbank.com",
        # Nigerian telcos
        "mtnonline.com",
        "mtn.ng",
        "airtel.com",
        "airtel.com.ng",
        "9mobile.com.ng",
        "glo.com",
        # Nigerian payment processors and fintech
        "flutterwave.com",
        "paystack.com",
        "interswitchgroup.com",
        "kuda.com",
        "opay.com",
        # Nigerian government and universities
        "nimc.gov.ng",
        "firs.gov.ng",
        "frsc.gov.ng",
        "nile.edu.ng",
        "nileuniversity.edu.ng",
        "abu.edu.ng",
        "unilag.edu.ng",
        # Nigerian hospitals
        "nizamiye.ng",
        "lasuth.ng",
        "uithniseason.org",
        # International services whose support and billing mail comes from these domains
        "microsoft.com",
        "outlook.office365.com",
        "apple.com",
        "amazon.com",
        "amazon.co.uk",
        "amazonpay.com",
        "stripe.com",
        "facebook.com",
        "anthropic.com",
        # International services, continued
        "netflix.com",
        "spotify.com",
        "coinbase.com",
        "booking.com",
        "airbnb.com",
        "dhl.com",
        "ups.com",
        "fedex.com",
        # France
        "laposte.fr",
        "chronopost.fr",
        "ameli.fr",
        "impots.gouv.fr",
        "dgfip.finances.gouv.fr",
        "caf.fr",
        "service-public.fr",
        "francetravail.fr",
        "edf.fr",
        "credit-agricole.fr",
        "bnpparibas.com",
        "societegenerale.fr",
        "labanquepostale.fr",
        "boursorama.com",
        # Elsewhere in Europe
        "correos.es",
        "ctt.pt",
        "deutschepost.de",
        "postnl.nl",
        "bpost.be",
        "royalmail.com",
        "posteitaliane.it",
    }
)
