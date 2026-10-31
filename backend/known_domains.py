"""
Brands and domains the link and sender checks know about.

BRANDS            a name a sender may display ("Chronopost", "La Poste"),
                  and the domain names the brand really sends from. A
                  From: that shows the name but comes from another domain
                  is impersonation (sender_trust.impersonated_brand).
WELL_KNOWN        organisational domains of large sites; links that only
                  go there are not scored by the trained URL model, which
                  mistakes their long tracking links for phishing.
SUSPICIOUS_TLDS   top-level domains mostly seen in abuse (free or
                  near-free registration).
CLOUD_FILE_HOSTS  hosts where anyone can publish a file or a page: a link
                  to them is a sign (phishing pages are often hosted
                  there), not a proof.
USER_CONTENT_HOSTS  the parts of large known sites where anyone can
                  publish a form or a document (forms.office.com...), or
                  that only send the reader elsewhere (l.facebook.com).

Names are matched as whole words, lower case, accents removed. A brand's
domains are matched on the first label of the organisational domain
("chronopost" for chronopost.fr or chronopost.com) under .com, .net,
.org or a home-market country code (sender_trust._brand_owns); a name
with a dot is a whole organisational domain ("e.leclerc"). Ambiguous words
(Orange, Free, Post...) are left out on purpose.
"""

from __future__ import annotations

BRANDS: dict[str, frozenset[str]] = {
    name: frozenset(labels.split())
    for name, labels in {
        # Global
        "paypal": "paypal",
        "apple": "apple icloud",
        "icloud": "apple icloud",
        "itunes": "apple",
        "google": "google youtube googlemail gmail",
        "gmail": "google googlemail gmail",
        "youtube": "google youtube",
        "microsoft": "microsoft microsoftonline office outlook live office365 sharepoint sharepointonline onedrive",
        "office 365": "microsoft microsoftonline office office365 sharepoint sharepointonline",
        "outlook": "microsoft outlook live office",
        "onedrive": "microsoft live onedrive sharepoint sharepointonline",
        "sharepoint": "microsoft sharepoint sharepointonline onedrive",
        "amazon": "amazon amazonaws aws primevideo amazonpay",
        "aws": "amazon amazonaws aws",
        "netflix": "netflix",
        "spotify": "spotify",
        "facebook": "facebook facebookmail meta",
        "instagram": "instagram facebookmail meta",
        "whatsapp": "whatsapp facebookmail meta",
        "linkedin": "linkedin",
        "dropbox": "dropbox dropboxmail",
        "docusign": "docusign",
        "adobe": "adobe adobesign",
        "wetransfer": "wetransfer",
        "dhl": "dhl dpdhl deutschepost",
        "fedex": "fedex",
        "ups": "ups",
        "usps": "usps",
        "dpd": "dpd dpdgroup",
        "coinbase": "coinbase",
        "binance": "binance",
        "metamask": "metamask consensys",
        "booking.com": "booking",
        "airbnb": "airbnb",
        "disney": "disney disneyplus",
        "steam": "steampowered steamcommunity valvesoftware",
        "tiktok": "tiktok",
        "zoom": "zoom zoomgov",
        # France
        "chronopost": "chronopost",
        "la poste": "laposte colissimo",
        "colissimo": "laposte colissimo",
        "mondial relay": "mondialrelay",
        "ameli": "ameli assurance-maladie",
        "assurance maladie": "ameli assurance-maladie",
        "impots": "impots.gouv.fr finances.gouv.fr",
        "antai": "antai.gouv.fr interieur.gouv.fr",
        "caf": "caf",
        "france travail": "francetravail",
        "edf": "edf",
        "engie": "engie",
        "sfr": "sfr",
        "bouygues": "bouyguestelecom bouygues",
        "credit agricole": "credit-agricole ca-paris ca-cib",
        "bnp paribas": "bnpparibas mabanque.bnpparibas",
        "societe generale": "societegenerale sg.fr",
        "la banque postale": "labanquepostale",
        "boursorama": "boursorama boursobank",
        "vinted": "vinted",
        "leboncoin": "leboncoin",
        # E.Leclerc also sends from its own top-level domain.
        "leclerc": "e-leclerc leclerc mouvement-leclerc e.leclerc",
        # Elsewhere in Europe
        "correos": "correos",
        "ctt": "ctt",
        "deutsche post": "deutschepost dhl",
        "poste italiane": "posteitaliane poste.it",
        "postnl": "postnl",
        "bpost": "bpost",
        "royal mail": "royalmail",
        # Nigeria
        "gtbank": "gtbank gtco",
        "stanbic": "stanbicibtc stanbicibtcbank stanbic standardbank",
        "zenith bank": "zenithbank",
        "access bank": "accessbankplc",
        "first bank": "firstbanknigeria fbnholdings",
        "uba": "ubagroup",
        "mtn": "mtn mtnonline",
        "airtel": "airtel",
        "jumia": "jumia",
        "opay": "opay opayweb",
        "palmpay": "palmpay",
        "moniepoint": "moniepoint",
        "kuda": "kuda kudabank",
        "flutterwave": "flutterwave",
        "paystack": "paystack",
        "firs": "firs.gov.ng",
        "nimc": "nimc.gov.ng",
    }.items()
}

_WELL_KNOWN_TEXT = """
    amazon.com amazon.co.uk amazon.de amazon.fr amazon.es amazon.it amazon.nl amazon.ca
    apple.com icloud.com microsoft.com live.com office.com outlook.com linkedin.com
    facebook.com instagram.com whatsapp.com youtube.com netflix.com spotify.com
    paypal.com stripe.com coinbase.com binance.com github.com gitlab.com
    wikipedia.org mozilla.org x.com twitter.com reddit.com medium.com
    booking.com airbnb.com uber.com zoom.us slack.com notion.so atlassian.com
    dhl.com fedex.com ups.com usps.com dpd.com dpd.fr
    laposte.fr laposte.net chronopost.fr mondialrelay.fr ameli.fr service-public.fr
    edf.fr engie.fr sfr.fr orange.fr free.fr bouyguestelecom.fr leboncoin.fr vinted.fr
    credit-agricole.fr bnpparibas.com mabanque.bnpparibas societegenerale.fr labanquepostale.fr boursorama.com
    correos.es ctt.pt deutschepost.de postnl.nl bpost.be royalmail.com
    gtbank.com zenithbank.com accessbankplc.com firstbanknigeria.com ubagroup.com
    mtn.ng mtnonline.com airtel.com.ng jumia.com.ng flutterwave.com paystack.com
    brain.fm
"""
WELL_KNOWN = frozenset(_WELL_KNOWN_TEXT.split())

_CLOUD_FILE_HOSTS_TEXT = """
    storage.googleapis.com firebasestorage.googleapis.com storage.cloud.google.com
    appspot.com web.app firebaseapp.com blob.core.windows.net web.core.windows.net
    r2.dev pages.dev workers.dev ipfs.io dweb.link cloudflare-ipfs.com
    s3.amazonaws.com netlify.app vercel.app glitch.me github.io
"""
CLOUD_FILE_HOSTS = frozenset(_CLOUD_FILE_HOSTS_TEXT.split())

# Parts of large known sites where anyone can publish a form, a document
# or a page: a link there is never "to a known site" (well_known_link),
# though the rest of the site is.
USER_CONTENT_HOSTS = frozenset(
    [
        "forms.office.com",
        "l.facebook.com",
        "lm.facebook.com",
        "l.instagram.com",
        "l.messenger.com",
        "safelinks.protection.outlook.com",
        "t.co",
        "lnkd.in",
        "forms.microsoft.com",
        "forms.cloud.microsoft",
        "sway.office.com",
        "sway.cloud.microsoft",
        "onedrive.live.com",
        "1drv.ms",
        "sharepoint.com",
        "docs.google.com",
        "drive.google.com",
        "sites.google.com",
        "forms.gle",
        "script.google.com",
    ]
)

SUSPICIOUS_TLDS = frozenset(
    {
        "zip",
        "review",
        "click",
        "country",
        "kim",
        "cricket",
        "science",
        "work",
        "party",
        "gq",
        "tk",
        "ml",
        "ga",
        "cf",
    }
)
