"""
PhishLens backend settings: the version, the environment variables and
every scoring constant in one place.

Environment variables are read once, at import. The scoring constants
(weights, thresholds, overrides) are documented where they are defined;
docs/architecture.md explains the trust paths that use them.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# Shared by the backend and the extension (extension/manifest.json);
# the CI checks that both say the same.
VERSION = "2.0.3"

# ---------------------------------------------------------------------
# Text model
# ---------------------------------------------------------------------
# MODEL_DIR holds the text model checkpoint. When it is empty, the model
# is downloaded from HF_MODEL_REPO on startup.
MODEL_DIR = Path(os.environ.get("MODEL_DIR", Path(__file__).parent / "model"))
HF_MODEL_REPO = os.environ.get("HF_MODEL_REPO", "AnzouKiona/phishlens-distilbert")
# float32 by default: faster than float16 on most CPUs.
MODEL_DTYPE = os.environ.get("MODEL_DTYPE", "float32")
MAX_LEN = 256  # tokens; the value used in training
CLASS_NAMES = ["Safe", "Phishing"]
# LIME forward passes per explanation: 100 gives the same top words as
# 200 at half the latency on a CPU host.
LIME_NUM_SAMPLES = int(os.environ.get("LIME_NUM_SAMPLES", "100"))
LIME_MAX_CHARS = 800  # LIME explains the start of the body

# ---------------------------------------------------------------------
# URL and metadata agents (trained Random Forests, optional)
# ---------------------------------------------------------------------
HF_AGENTS_REPO = os.environ.get("HF_AGENTS_REPO", "AnzouKiona/phishlens-agents")
# skops files are loaded with a type allowlist; pickle (joblib) is only a
# fallback and AGENTS_ALLOW_PICKLE=0 refuses it (production setting).
AGENTS_ALLOW_PICKLE = os.environ.get("AGENTS_ALLOW_PICKLE", "1") != "0"

# ---------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------
PORT = int(os.environ.get("PORT", "8000"))
# The public backend serves any extension install; self-hosted servers
# can restrict this.
CORS_ALLOW_ORIGINS = os.environ.get("CORS_ALLOW_ORIGINS", "*").split(",")
METRICS_ENABLED = os.environ.get("METRICS_ENABLED", "1") != "0"
ENABLE_DBL = os.environ.get("REPUTATION_ENABLE_DBL", "1") != "0"

RATE_LIMIT_DEFAULT = os.environ.get("RATE_LIMIT_DEFAULT", "60/minute")
RATE_LIMIT_STORAGE = os.environ.get("SLOWAPI_STORAGE_URI", "memory://")
RATE_LIMIT_ANALYSE = os.environ.get("RATE_LIMIT_ANALYSE", "30/minute")
RATE_LIMIT_ATTACHMENT = os.environ.get("RATE_LIMIT_ATTACHMENT", "20/minute")
RATE_LIMIT_EXPLAIN = os.environ.get("RATE_LIMIT_EXPLAIN", "15/minute")
RATE_LIMIT_FEEDBACK = os.environ.get("RATE_LIMIT_FEEDBACK", "20/hour")

# Reports sent from the extension (feedback.py). Empty: not collected.
FEEDBACK_DIR = os.environ.get("FEEDBACK_DIR", "")
FEEDBACK_MAX_MB = float(os.environ.get("FEEDBACK_MAX_MB", "200"))
# Optional push message for each new report (an ntfy topic URL, for
# example). Empty: no message. Never carries the report's text.
FEEDBACK_NOTIFY_URL = os.environ.get("FEEDBACK_NOTIFY_URL", "")
# Optional https:// address the notification opens when tapped; the
# report's reference is added after a #.
FEEDBACK_NOTIFY_CLICK = os.environ.get("FEEDBACK_NOTIFY_CLICK", "")

# Request size limits. An email with its attachments can be large (Gmail
# accepts 25 MB) and base64 adds a third; an attachment is capped at
# 10 MB by attachment_analysis. Bigger bodies are refused before parsing.
MAX_EMAIL_B64_CHARS = 40_000_000
MAX_TEXT_CHARS = 2_000_000
MAX_ATTACHMENT_B64_CHARS = 15_000_000
MAX_BODY_BYTES = 45_000_000

# Link targets sent by the extension (client_context.link_urls).
MAX_LINK_URLS = 50
# Below this many words the text agent is left out of the fusion
# (image-only emails, a bare link).
MIN_TEXT_WORDS = 3


# ---------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------
@dataclass(frozen=True)
class TrustPath:
    """How one trust path weighs the agents.

    text_factor   multiplies the text agent's weight (1 = full weight)
    threshold     fused score from which the verdict is phishing
    """

    name: str
    text_factor: float
    threshold: float


# Base weights of the three agents on an email.
W_TEXT, W_URL, W_META = 0.34, 0.33, 0.33

# One agent above this forces the phishing verdict on the default path
# (the URL agent needs a confirming sign, see URL_OVERRIDE_RULE_MIN).
HIGH_CONF_OVERRIDE = 0.85
# Rule-based URL score a link needs before the URL agent alone may force
# the verdict: one concrete sign (plain http 0.25, raw IP 0.40, "@" 0.35,
# suspicious TLD 0.30); length or keywords alone (0.15, 0.10) are not.
URL_OVERRIDE_RULE_MIN = 0.25

# The text model mistakes legitimate transactional mail ("verify your
# account") for phishing, so its weight is lowered when the sender is
# proven. Only a Safe Browsing hit can then force the verdict.
PATH_TRUSTED = TrustPath("trusted_sender", text_factor=0.5, threshold=0.65)
PATH_CRYPTO = TrustPath("crypto_verified", text_factor=0.5, threshold=0.65)
PATH_INBOX_SOFT = TrustPath("gmail_inbox_soft", text_factor=0.6, threshold=0.62)
PATH_OUTLOOK_INTERNAL = TrustPath("outlook_internal", text_factor=0.6, threshold=0.62)
PATH_DEFAULT = TrustPath("default", text_factor=1.0, threshold=0.5)
# Metadata score ceiling for an authenticated allowlisted sender.
TRUSTED_META_CEILING = 0.05

# Threat intelligence on the URL score: a Safe Browsing match lifts it to
# at least GSB_URL_FLOOR; another source blends in with REP_BLEND.
GSB_URL_FLOOR = 0.95
REP_BLEND = 0.7

# Attachments: text and URL agents share the weight, the risky features
# found in the file add a bonus (attachment_risk in fusion.py).
ATTACHMENT_THRESHOLD = 0.55
# Parent email authenticated: text weight halved, higher bar.
ATTACHMENT_TRUSTED_TEXT_FACTOR = 0.5
ATTACHMENT_TRUSTED_THRESHOLD = 0.72
ATTACHMENT_FEATURE_BONUS_MAX = 0.7
# Text score from which a file inside an archive is reported for its wording.
INNER_FILE_WORDING_THRESHOLD = 0.7
