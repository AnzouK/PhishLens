"""
Reports that users choose to send from the extension: a wrong verdict
(with the redacted email text), a wrongly detected language, or their
reviewed scan statistics without any email content.

Each report is its own file, FEEDBACK_DIR/YYYY-MM/<reference>.json,
created once and never rewritten: on a Cloud Storage bucket mounted as a
folder, deleting one report is removing one object, and no write can
undo it or be lost to it. Older servers appended to one JSON lines file
per month (feedback-YYYY-MM.jsonl); those files are still read, never
written. Nothing is stored when FEEDBACK_DIR is empty (the default), and
the endpoint then answers 503. No IP address or other request metadata is written; the
reference returned to the user is the only link between a person and a
report (to have it deleted).
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
import urllib.request
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from redaction import redact
from settings import FEEDBACK_DIR, FEEDBACK_MAX_MB, FEEDBACK_NOTIFY_CLICK, FEEDBACK_NOTIFY_URL

logger = logging.getLogger("phishlens." + __name__.split(".")[-1])
Kind = Literal["false_positive", "false_negative", "wrong_language", "stats"]
_LANG = Field(None, max_length=8, pattern=r"^[a-z]{2,3}$|^und$|^other$")
# Short identifiers only ("gmail", "trusted_sender", "2.0.11"): these are
# stored as they are and shown in the report notification, unlike the
# text, which is redacted.
_WORD = r"^[a-z0-9_.-]{1,40}$"


class AgentScores(BaseModel):
    text: float = Field(0.0, ge=0, le=1)
    url: float = Field(0.0, ge=0, le=1)
    metadata: float = Field(0.0, ge=0, le=1)


class StatRow(BaseModel):
    """One reviewed scan, without subject, sender or text."""

    day: str | None = Field(None, max_length=10, pattern=r"^\d{4}-\d{2}-\d{2}$")
    source: str | None = Field(None, max_length=30, pattern=_WORD)
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
    trust_path: str | None = Field(None, max_length=40, pattern=_WORD)
    source: str | None = Field(None, max_length=30, pattern=_WORD)
    lang: str | None = _LANG
    lang_user: str | None = _LANG
    ui_lang: str | None = _LANG
    version: str | None = Field(None, max_length=20, pattern=_WORD)
    rows: list[StatRow] | None = Field(None, max_length=500)


def enabled() -> bool:
    return bool(FEEDBACK_DIR)


def _report_files(folder: Path) -> list[Path]:
    """Legacy monthly files first, then one file per report."""
    return sorted(folder.glob("feedback-*.jsonl")) + sorted(folder.glob("[0-9]*-[0-9]*/*.json"))


def _dir_size_mb(folder: Path) -> float:
    return sum(f.stat().st_size for f in _report_files(folder)) / 1_000_000


def read_all(folder: Path) -> Iterator[dict[str, Any]]:
    """Every stored report, old monthly lines and single files alike,
    oldest first within each kind of file. Unreadable entries are skipped."""
    for path in _report_files(folder):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        lines = text.splitlines() if path.suffix == ".jsonl" else [text]
        for line in lines:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict):
                yield record


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
    folder = Path(FEEDBACK_DIR)
    if folder.is_dir() and _dir_size_mb(folder) >= FEEDBACK_MAX_MB:
        raise OSError("report storage is full")
    month = folder / f"{now:%Y-%m}"
    month.mkdir(parents=True, exist_ok=True)
    record: dict[str, Any] = {}
    for _ in range(5):
        record = {
            "reference": secrets.token_hex(6),
            "received": now.date().isoformat(),
            "kind": req.kind,
            "version": req.version,
            "ui_lang": req.ui_lang,
            **body,
        }
        if _create(month / f"{record['reference']}.json", record):
            break
    else:
        raise OSError("no free reference")
    notify(record)
    return record["reference"]


def _create(path: Path, record: dict[str, Any]) -> bool:
    """Write a new file; False when one already has that name."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return True


def notification_text(record: dict[str, Any]) -> str:
    """One line about a new report: what kind, which languages, where it
    came from and its reference. Never the text of the email."""
    parts = [record["kind"].replace("_", " ")]
    if record["kind"] == "stats":
        parts.append(f"{len(record.get('rows') or [])} scans")
    else:
        parts.append(f"verdict {record.get('verdict') or '?'}")
        lang = record.get("lang") or "?"
        if record.get("lang_user") and record["lang_user"] != lang:
            lang += f" (user: {record['lang_user']})"
        parts.append(f"language {lang}")
        if record.get("source"):
            parts.append(f"from {record['source']}")
    parts.append(f"ref {record['reference']}")
    return " · ".join(parts)


def _post(url: str, message: str, click: str = "") -> None:
    headers = {"Title": "PhishLens report"}
    if click:
        headers["Click"] = click
    req = urllib.request.Request(url, data=message.encode(), headers=headers, method="POST")
    try:
        urllib.request.urlopen(req, timeout=5).close()
    except OSError as e:
        logger.warning("report notification failed: %s", type(e).__name__)


def _spawn(fn, *args) -> None:
    threading.Thread(target=fn, args=args, daemon=True).start()


def notify(record: dict[str, Any]) -> None:
    """Sends notification_text() to FEEDBACK_NOTIFY_URL in the background."""
    if not FEEDBACK_NOTIFY_URL.startswith("https://"):
        return
    click = (
        f"{FEEDBACK_NOTIFY_CLICK}#{record['reference']}"
        if FEEDBACK_NOTIFY_CLICK.startswith("https://")
        else ""
    )
    _spawn(_post, FEEDBACK_NOTIFY_URL, notification_text(record), click)
