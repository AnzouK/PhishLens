"""
Reports that users choose to send from the extension: a wrong verdict
(with the redacted email text), a wrongly detected language, or their
reviewed scan statistics without any email content.

Stored as JSON lines, one file per month, in FEEDBACK_DIR. Nothing is
stored when FEEDBACK_DIR is empty (the default), and the endpoint then
answers 503. No IP address or other request metadata is written; the
reference returned to the user is the only link between a person and a
report (to have it deleted).
"""

from __future__ import annotations

import json
import os
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from redaction import redact
from settings import FEEDBACK_DIR, FEEDBACK_MAX_MB

Kind = Literal["false_positive", "false_negative", "wrong_language", "stats"]
_LOCK = threading.Lock()
_LANG = Field(None, max_length=8, pattern=r"^[a-z]{2,3}$|^und$|^other$")


class AgentScores(BaseModel):
    text: float = Field(0.0, ge=0, le=1)
    url: float = Field(0.0, ge=0, le=1)
    metadata: float = Field(0.0, ge=0, le=1)


class StatRow(BaseModel):
    """One reviewed scan, without subject, sender or text."""

    day: str | None = Field(None, max_length=10, pattern=r"^\d{4}-\d{2}-\d{2}$")
    source: str | None = Field(None, max_length=30)
    verdict: Literal["phishing", "safe"]
    score: float = Field(0.0, ge=0, le=1)
    agents: AgentScores = AgentScores()
    trusted: bool = False
    label: Literal["correct", "wrong"] | None = None
    lang: str | None = _LANG
    lang_user: str | None = _LANG


class FeedbackRequest(BaseModel):
    kind: Kind
    text: str | None = Field(None, max_length=20_000)
    verdict: Literal["phishing", "safe"] | None = None
    fused_score: float | None = Field(None, ge=0, le=1)
    agents: AgentScores | None = None
    trust_path: str | None = Field(None, max_length=40)
    source: str | None = Field(None, max_length=30)
    lang: str | None = _LANG
    lang_user: str | None = _LANG
    ui_lang: str | None = _LANG
    version: str | None = Field(None, max_length=20)
    rows: list[StatRow] | None = Field(None, max_length=500)


def enabled() -> bool:
    return bool(FEEDBACK_DIR)


def _dir_size_mb(path: Path) -> float:
    return sum(f.stat().st_size for f in path.glob("*.jsonl")) / 1_000_000


def store(req: FeedbackRequest) -> str:
    """Write one report, return its reference. Raises ValueError when the
    request makes no sense for its kind, OSError when storage is full."""
    if req.kind == "stats":
        if not req.rows:
            raise ValueError("No statistics to send.")
        body: dict[str, Any] = {"rows": [r.model_dump() for r in req.rows]}
    else:
        if not req.text or len(req.text.split()) < 3:
            raise ValueError("The report has no text.")
        body = {
            "text": redact(req.text),
            "verdict": req.verdict,
            "fused_score": req.fused_score,
            "agents": req.agents.model_dump() if req.agents else None,
            "trust_path": req.trust_path,
            "source": req.source,
            "lang": req.lang,
            "lang_user": req.lang_user,
        }
    now = datetime.now(timezone.utc)
    reference = secrets.token_hex(6)
    record = {
        "reference": reference,
        "received": now.date().isoformat(),
        "kind": req.kind,
        "version": req.version,
        "ui_lang": req.ui_lang,
        **body,
    }
    folder = Path(FEEDBACK_DIR)
    with _LOCK:
        folder.mkdir(parents=True, exist_ok=True)
        if _dir_size_mb(folder) >= FEEDBACK_MAX_MB:
            raise OSError("report storage is full")
        path = folder / f"feedback-{now:%Y-%m}.jsonl"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return reference
