"""Scores to verdict (fusion.py): every rule, without a server."""

from __future__ import annotations

import pytest

import fusion
from settings import (
    ATTACHMENT_FEATURE_BONUS_MAX,
    PATH_CRYPTO,
    PATH_DEFAULT,
    PATH_INBOX_SOFT,
    PATH_OUTLOOK_INTERNAL,
    PATH_TRUSTED,
)

NO_REP = fusion.summarize_reputation([])
GSB = fusion.summarize_reputation(
    [{"url": "u", "malicious": True, "score": 1.0, "sources": ["google_safe_browsing"]}]
)
URLHAUS = fusion.summarize_reputation(
    [
        {
            "url": "u",
            "malicious": True,
            "score": 0.8,
            "sources": ["urlhaus"],
            "threat_types": ["malware"],
        }
    ]
)


class TestReputation:
    def test_summary_keeps_only_malicious_verdicts(self):
        rep = fusion.summarize_reputation(
            [
                {"url": "a", "malicious": False, "score": 0.9, "sources": ["phishtank"]},
                {
                    "url": "b",
                    "malicious": True,
                    "score": 0.8,
                    "sources": ["urlhaus"],
                    "threat_types": ["malware"],
                },
            ]
        )
        assert rep.max_score == 0.8 and rep.sources == {"urlhaus"} and not rep.gsb_hit
        d = rep.as_dict()
        assert d["checked"] == 2 and d["malicious_count"] == 1 and d["threat_types"] == ["malware"]

    def test_gsb_lifts_the_url_score(self):
        assert fusion.apply_reputation(0.1, GSB) == pytest.approx(0.95)
        assert fusion.apply_reputation(0.99, GSB) == pytest.approx(0.99)

    def test_other_sources_blend_in(self):
        assert fusion.apply_reputation(0.1, URLHAUS) == pytest.approx(0.7 * 0.8 + 0.3 * 0.1)
        assert fusion.apply_reputation(0.1, NO_REP) == 0.1


class TestTrustPath:
    @pytest.mark.parametrize(
        ("flags", "expected"),
        [
            ({"trusted_sender": True, "crypto_verified": True}, PATH_TRUSTED),
            ({"crypto_verified": True, "inbox_soft": True}, PATH_CRYPTO),
            ({"inbox_soft": True}, PATH_INBOX_SOFT),
            ({"inbox_soft": True, "outlook_internal": True}, PATH_OUTLOOK_INTERNAL),
            ({}, PATH_DEFAULT),
        ],
    )
    def test_precedence(self, flags, expected):
        args = {
            "trusted_sender": False,
            "crypto_verified": False,
            "inbox_soft": False,
            "outlook_internal": False,
        }
        args.update(flags)
        assert fusion.choose_trust_path(**args) is expected


class TestDecideEmail:
    def decide(
        self,
        p_text=0.0,
        p_url=0.0,
        p_meta=0.0,
        path=PATH_DEFAULT,
        rep=NO_REP,
        rule=0.0,
        text_used=True,
    ):
        return fusion.decide_email(
            p_text, p_url, p_meta, text_used=text_used, path=path, rep=rep, url_rule_score=rule
        )

    def test_weighted_sum_below_threshold_is_safe(self):
        v = self.decide(0.6, 0.5, 0.3)
        assert v.fused == pytest.approx(0.34 * 0.6 + 0.33 * 0.5 + 0.33 * 0.3)
        assert not v.is_phishing and v.trust_path == "default"

    def test_confident_text_forces_phishing_on_default_path(self):
        v = self.decide(p_text=0.9)
        assert v.is_phishing and v.high_conf

    def test_confident_text_does_not_count_without_text(self):
        assert not self.decide(p_text=0.99, text_used=False).high_conf

    def test_without_text_url_and_metadata_share_the_weight(self):
        v = self.decide(p_text=0.99, p_url=0.6, p_meta=0.6, text_used=False)
        assert v.fused == pytest.approx(0.6)

    def test_text_override_follows_the_model(self):
        # a calibrated model forces the verdict from its own threshold
        v = fusion.decide_email(
            0.75,
            0.0,
            0.0,
            text_used=True,
            path=PATH_DEFAULT,
            rep=NO_REP,
            url_rule_score=0.0,
            text_override=0.7,
        )
        assert v.high_conf and v.is_phishing
        assert not self.decide(p_text=0.75).high_conf

    def test_url_model_alone_needs_a_confirming_sign(self):
        assert not self.decide(p_url=0.95, rule=0.15).high_conf
        assert self.decide(p_url=0.95, rule=0.25).high_conf
        assert self.decide(p_url=0.95, rep=URLHAUS).high_conf

    @pytest.mark.parametrize(
        "path", [PATH_TRUSTED, PATH_CRYPTO, PATH_INBOX_SOFT, PATH_OUTLOOK_INTERNAL]
    )
    def test_soft_paths_only_override_on_safe_browsing(self, path):
        assert not self.decide(p_text=0.99, p_meta=0.99, path=path).high_conf
        assert self.decide(path=path, rep=GSB).is_phishing

    def test_soft_path_lowers_text_weight_and_raises_threshold(self):
        v = self.decide(p_text=1.0, p_url=0.5, p_meta=0.5, path=PATH_CRYPTO)
        assert v.fused == pytest.approx(0.34 * 0.5 + 0.33 * 0.5 + 0.33 * 0.5)
        assert v.threshold == 0.65 and not v.is_phishing


class TestAttachments:
    def test_feature_bonus_adds_up_and_is_capped(self):
        assert fusion.attachment_feature_bonus(["contains_javascript"]) == pytest.approx(0.20)
        assert fusion.attachment_feature_bonus(
            ["contains_form", "contains_password_field"]
        ) == pytest.approx(0.65)
        many = ["contains_macros", "remote_template", "dde_field"]
        assert fusion.attachment_feature_bonus(many) == ATTACHMENT_FEATURE_BONUS_MAX
        assert fusion.attachment_feature_bonus(["unknown_flag"]) == 0.0

    def test_dropper_techniques(self):
        assert fusion.dropper_techniques(
            ["contains_macros", "contains_form", "double_extension"]
        ) == [
            "contains_macros",
            "double_extension",
        ]

    def decide(
        self, p_text=0.0, p_url=0.0, bonus=0.0, parent=False, rep=NO_REP, dropper=(), rule=0.0
    ):
        return fusion.decide_attachment(
            p_text,
            p_url,
            feature_bonus=bonus,
            parent_trusted=parent,
            rep=rep,
            dropper=list(dropper),
            url_rule_score=rule,
        )

    def test_trusted_parent_absorbs_a_text_false_positive(self):
        assert self.decide(p_text=0.9).is_phishing
        v = self.decide(p_text=0.9, parent=True)
        assert not v.is_phishing and v.trust_path == "parent_trusted"

    def test_dropper_and_safe_browsing_override_a_trusted_parent(self):
        assert self.decide(parent=True, dropper=["contains_macros"]).is_phishing
        assert self.decide(parent=True, rep=GSB).is_phishing

    def test_score_is_capped_at_one(self):
        assert self.decide(p_text=1.0, p_url=1.0, bonus=0.7).fused == 1.0
