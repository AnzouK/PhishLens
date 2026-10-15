import json
from pathlib import Path

import pytest

from redaction import redact

CASES = json.loads(
    (
        Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "redaction_cases.json"
    ).read_text()
)


@pytest.mark.parametrize("case", CASES, ids=[c["text"][:30] for c in CASES])
def test_same_result_as_the_extension(case):
    assert redact(case["text"], case["terms"]) == case["expected"]


def test_nothing_personal_is_left():
    out = redact(
        "Hi Kalinda, wire 250000 to FR7630006000011234567890189, call +234 803 123 4567, "
        "mail kalinda.o@example.org, profile @kal_99 https://x.example/u/kalinda?ref=1",
        ["kalinda"],
    )
    for leak in ("Kalinda", "kalinda", "250000", "FR76", "803", "kal_99", "/u/"):
        assert leak not in out, leak
    assert "<URL:x.example>" in out
