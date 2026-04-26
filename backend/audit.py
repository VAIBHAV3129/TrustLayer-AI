"""
Safe audit logging for TrustLayer AI.

This system is designed with input validation, adversarial resistance, and
controlled execution to ensure reliability in real-world environments.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
import re
from typing import Dict


LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "trustlayer_audit.log"

LOGGER = logging.getLogger("trustlayer.audit")
if not LOGGER.handlers:
    handler = RotatingFileHandler(LOG_FILE, maxBytes=512_000, backupCount=3)
    handler.setFormatter(logging.Formatter("%(message)s"))
    LOGGER.addHandler(handler)
LOGGER.setLevel(logging.INFO)
LOGGER.propagate = False


SENSITIVE_PATTERNS = [
    r"\botp\b",
    r"\b0tp\b",
    r"\bpassword\b",
    r"\bp[a@]ssw[o0]rd\b",
    r"\bpin\b",
    r"\bcvv\b",
    r"\bpasscode\b",
    r"\bverification code\b",
]


def _redact_sensitive_markers(text: str) -> str:
    redacted = text
    for pattern in SENSITIVE_PATTERNS:
        redacted = re.sub(pattern, "[redacted]", redacted, flags=re.IGNORECASE)
    return redacted


def _build_safe_preview(text: str) -> str:
    compact = re.sub(r"(?is)<script.*?>.*?</script>", " ", text)
    compact = re.sub(r"(?is)<style.*?>.*?</style>", " ", compact)
    compact = re.sub(r"(?s)<[^>]*>", " ", compact)
    compact = re.sub(r"\s+", " ", compact).strip()
    return _redact_sensitive_markers(compact)[:140]


def log_analysis_event(client_ip: str, raw_text: str, result: Dict[str, object], status: str) -> None:
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client_ip": client_ip,
        "status": status,
        "text_sha256_prefix": hashlib.sha256(raw_text.encode("utf-8")).hexdigest()[:16],
        "text_preview": _build_safe_preview(raw_text),
        "score": result.get("score"),
        "risk": result.get("risk"),
        "category": result.get("category"),
        "confidence": result.get("confidence"),
    }
    LOGGER.info(json.dumps(payload, ensure_ascii=True))
