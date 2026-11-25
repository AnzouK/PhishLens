"""
PhishLens backend settings.

The version, the environment variables and every scoring constant live
here. Environment variables are read once at import. Each constant is
documented where it is defined, and docs/architecture.md explains the
trust paths that use them.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# The extension uses the same version (extension/manifest.json) and CI
# checks that they match.
VERSION = "2.2.0"

# Text model
# MODEL_DIR holds the text model checkpoint. When it is empty, the model
# is downloaded from HF_MODEL_REPO on startup.
MODEL_DIR = Path(os.environ.get("MODEL_DIR", Path(__file__).parent / "model"))
HF_MODEL_REPO = os.environ.get("HF_MODEL_REPO", "AnzouKiona/phishlens-distilbert")
# Full commit sha of the model repository to download. If unset we take
# the latest commit, which means anyone who can push to that repository
# can change the model the server runs.
HF_MODEL_REVISION = os.environ.get("HF_MODEL_REVISION") or None
# float32 by default because it is faster than float16 on most CPUs.
MODEL_DTYPE = os.environ.get("MODEL_DTYPE", "float32")
MAX_LEN = 256  # tokens, same as in training
CLASS_NAMES = ["Safe", "Phishing"]
# LIME forward passes per explanation. 100 gives the same top words as
# 200 at half the latency on a CPU host.
LIME_NUM_SAMPLES = int(os.environ.get("LIME_NUM_SAMPLES", "100"))
LIME_MAX_CHARS = 800  # LIME explains the start of the body

# URL and metadata agents (trained Random Forests, optional)
HF_AGENTS_REPO = os.environ.get("HF_AGENTS_REPO", "AnzouKiona/phishlens-agents")
HF_AGENTS_REVISION = os.environ.get("HF_AGENTS_REVISION") or None  # see HF_MODEL_REVISION
# skops files are loaded with a type allowlist. Pickle (joblib) runs code
# when loaded, so it is refused unless AGENTS_ALLOW_PICKLE=1 (only for an
# old local copy of the agents that was never converted).
AGENTS_ALLOW_PICKLE = os.environ.get("AGENTS_ALLOW_PICKLE", "0") == "1"

# Server
PORT = int(os.environ.get("PORT", "8000"))
# The public backend serves any extension install. Self-hosted servers
# can restrict this.
CORS_ALLOW_ORIGINS = os.environ.get("CORS_ALLOW_ORIGINS", "*").split(",")
METRICS_ENABLED = os.environ.get("METRICS_ENABLED", "1") != "0"
# Secret shared with the reverse proxy (the phishlens.dev Pages Function).
# When set, requests without it in X-PhishLens-Proxy get a 403. That stops
# people from calling the host directly and forging X-Forwarded-For to
# dodge the rate limits. Leave it empty for self-hosted Docker.
PROXY_SECRET = os.environ.get("PROXY_SECRET", "")
ENABLE_DBL = os.environ.get("REPUTATION_ENABLE_DBL", "1") != "0"
# The metadata Random Forest was trained on old corpora whose headers
# differ from today's (ARC, long Received chains, mailing-list headers),
# and it scores most modern legitimate mail near 1.0. It is off by
# default and we use rules and the real SPF/DKIM/DMARC results instead.
METADATA_MODEL_ENABLED = os.environ.get("METADATA_MODEL_ENABLED", "0") == "1"

RATE_LIMIT_DEFAULT = os.environ.get("RATE_LIMIT_DEFAULT", "60/minute")
RATE_LIMIT_STORAGE = os.environ.get("SLOWAPI_STORAGE_URI", "memory://")
RATE_LIMIT_ANALYSE = os.environ.get("RATE_LIMIT_ANALYSE", "30/minute")
RATE_LIMIT_ATTACHMENT = os.environ.get("RATE_LIMIT_ATTACHMENT", "20/minute")
RATE_LIMIT_EXPLAIN = os.environ.get("RATE_LIMIT_EXPLAIN", "15/minute")
RATE_LIMIT_FEEDBACK = os.environ.get("RATE_LIMIT_FEEDBACK", "20/hour")

# Where reports from the extension go (feedback.py). Empty disables them.
FEEDBACK_DIR = os.environ.get("FEEDBACK_DIR", "")
FEEDBACK_MAX_MB = float(os.environ.get("FEEDBACK_MAX_MB", "200"))
# Optional push notification for each new report, such as an ntfy topic
# URL. It never includes the report's text.
FEEDBACK_NOTIFY_URL = os.environ.get("FEEDBACK_NOTIFY_URL", "")
# Optional https:// URL the notification opens when tapped. The report
# reference is appended after a #.
FEEDBACK_NOTIFY_CLICK = os.environ.get("FEEDBACK_NOTIFY_CLICK", "")

# Request size limits. Gmail accepts 25 MB emails and base64 adds a third.
# attachment_analysis caps a single attachment at 10 MB. Bigger bodies are
# refused before parsing.
MAX_EMAIL_B64_CHARS = 40_000_000
MAX_TEXT_CHARS = 2_000_000
# Most page text (raw_text) we read after removing markup noise. The
# extension never sends more and the text model reads far less.
MAX_PAGE_TEXT_CHARS = 20_000
# In a longer page text we still look for URLs up to this point.
MAX_URL_SCAN_CHARS = 200_000
MAX_ATTACHMENT_B64_CHARS = 15_000_000
MAX_BODY_BYTES = 45_000_000

# Caps on link targets from the extension (client_context.link_urls) and
# on links kept per email from all sources.
MAX_LINK_URLS = 50
MAX_EMAIL_URLS = 100
# Below this many words the text agent is left out of the fusion. This
# covers image-only emails and bare links.
MIN_TEXT_WORDS = 3


# Scoring
@dataclass(frozen=True)
class TrustPath:
    """How one trust path weighs the agents.

    text_factor   multiplies the text agent's weight (1 = full weight)
    threshold     fused score from which the verdict is phishing
    forcing       the signs that make the verdict phishing on their own,
                  whatever the fused score (fusion.FORCING_SIGNS)
    """

    name: str
    text_factor: float
    threshold: float
    forcing: tuple[str, ...] = ("safe_browsing",)


# Base weights of the three agents on an email.
W_TEXT, W_URL, W_META = 0.34, 0.33, 0.33

# On the default path, one agent above this forces phishing. For an email
# the URL agent also needs a threat-intel hit or
# structured_agents.strong_link_sign. Attachments are covered below.
HIGH_CONF_OVERRIDE = 0.85
# Rule score a link in an attachment needs before the URL agent alone can
# force the verdict. Any one concrete sign is enough (plain http 0.25, raw
# IP 0.40, "@" 0.35, suspicious TLD 0.30). Length or keywords alone (0.15,
# 0.10) are not.
URL_OVERRIDE_RULE_MIN = 0.25

# The text model mistakes legitimate transactional mail ("verify your
# account") for phishing, so its weight is lowered when the sender is
# proven. Only a Safe Browsing hit can then force the verdict.
PATH_TRUSTED = TrustPath("trusted_sender", text_factor=0.5, threshold=0.65)
# A signature proves the domain, not that the sender is honest. If every
# link leads elsewhere and the wording looks like phishing, it protects
# nothing.
PATH_CRYPTO = TrustPath(
    "crypto_verified", text_factor=0.5, threshold=0.65, forcing=("safe_browsing", "links_elsewhere")
)
PATH_INBOX_SOFT = TrustPath("gmail_inbox_soft", text_factor=0.6, threshold=0.62)
PATH_OUTLOOK_INTERNAL = TrustPath("outlook_internal", text_factor=0.6, threshold=0.62)
PATH_DEFAULT = TrustPath(
    "default",
    text_factor=1.0,
    threshold=0.5,
    forcing=("confident_text", "confident_sender", "confirmed_link"),
)
# Sender score floor when the From: shows a brand name over someone else's
# address (sender_trust.impersonated_brand). It is at or above
# HIGH_CONF_OVERRIDE, so it decides the verdict on the default path.
IMPERSONATION_META = 0.9
# Metadata score ceiling for an authenticated allowlisted sender.
TRUSTED_META_CEILING = 0.05
# On the crypto_verified path (DKIM aligned, sender not on the allowlist),
# links that all lead away from the sender's domain plus a text score of
# at least CRYPTO_LINK_TEXT_MIN force phishing (link_alignment.py). We
# measured it on fresh phishing and on the running server
# (docs/evaluation.md). CRYPTO_LINK_RULE=0 turns it off.
CRYPTO_LINK_RULE = os.environ.get("CRYPTO_LINK_RULE", "1") != "0"
CRYPTO_LINK_TEXT_MIN = 0.5

# A Safe Browsing match lifts the URL score to at least GSB_URL_FLOOR.
# Other threat feeds blend in with REP_BLEND.
GSB_URL_FLOOR = 0.95
REP_BLEND = 0.7

# Attachments. The text and URL agents share the weight and risky features
# add a bonus (FEATURE_RISK and attachment_feature_bonus in fusion.py).
ATTACHMENT_THRESHOLD = 0.55
# When the parent email is authenticated, the text weight is halved and
# the threshold goes up.
ATTACHMENT_TRUSTED_TEXT_FACTOR = 0.5
ATTACHMENT_TRUSTED_THRESHOLD = 0.72
ATTACHMENT_FEATURE_BONUS_MAX = 0.7
# Text score from which a file inside an archive is reported for its wording.
INNER_FILE_WORDING_THRESHOLD = 0.7
