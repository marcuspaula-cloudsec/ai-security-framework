"""
Structured Audit Logger for LLM Interactions
GDPR-compliant: logs hashes instead of raw PII, timestamps in UTC.
Produces JSON logs compatible with CloudWatch, ELK, Splunk.

Author: Marcus Paula | Cloud Security Architect
"""

import json
import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("llm_audit")
logger.setLevel(logging.INFO)


def log_interaction(
    user_id: str,
    input_text: str,
    output_text: str,
    model: str,
    tokens_in: int,
    tokens_out: int,
    security_flags: Optional[list] = None,
    blocked: bool = False,
    latency_ms: Optional[float] = None,
) -> dict:
    """
    Log an LLM interaction with security-relevant metadata.
    PII-safe: stores hashes of input/output, never raw content.
    """
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "llm_interaction",
        "user_id_hash": _hash(user_id),
        "input_hash": _hash(input_text),
        "input_length": len(input_text),
        "output_hash": _hash(output_text),
        "output_length": len(output_text),
        "model": model,
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "tokens_total": tokens_in + tokens_out,
        "security_flags": security_flags or [],
        "blocked": blocked,
        "latency_ms": latency_ms,
    }

    if security_flags:
        record["severity"] = "WARNING" if not blocked else "CRITICAL"
    else:
        record["severity"] = "INFO"

    logger.info(json.dumps(record))
    return record


def log_security_event(
    event_type: str,
    user_id: str,
    details: dict,
    severity: str = "WARNING",
) -> dict:
    """Log a security-specific event (injection attempt, PII leak, etc)."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": f"security_{event_type}",
        "user_id_hash": _hash(user_id),
        "severity": severity,
        "details": details,
    }

    logger.warning(json.dumps(record))
    return record


def _hash(value: str) -> str:
    """SHA-256 hash for audit logging (never store raw PII)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
