"""
LLM Output Validator
Validates LLM responses before returning to user.
Checks: PII leakage, system prompt disclosure, response limits.

Author: Marcus Paula | Cloud Security Architect
"""

import re
import json
import logging
from typing import Optional
from . import pii_filter

logger = logging.getLogger(__name__)

MAX_OUTPUT_LENGTH = 8192

SYSTEM_PROMPT_INDICATORS = [
    r"my\s+(system|initial)\s+(prompt|instructions)\s+(is|are|says)",
    r"i\s+was\s+(told|instructed|programmed)\s+to",
    r"my\s+guidelines?\s+(state|say|require)",
    r"here\s+(is|are)\s+my\s+(system|full)\s+(prompt|instructions)",
    r"the\s+developer\s+(told|instructed)\s+me",
]


def validate_output(
    output: str,
    check_pii: bool = True,
    check_system_leak: bool = True,
    max_length: Optional[int] = None,
) -> dict:
    """
    Validate LLM output before returning to user.

    Returns:
        dict with keys: safe (bool), output (str), flags (list), redacted (bool)
    """
    result = {
        "safe": True,
        "output": output,
        "flags": [],
        "redacted": False,
    }

    limit = max_length or MAX_OUTPUT_LENGTH

    # Length check
    if len(output) > limit:
        result["output"] = output[:limit]
        result["flags"].append(f"truncated:{len(output)}->{limit}")

    # PII leakage check
    if check_pii:
        pii_findings = pii_filter.scan(output)
        if pii_findings:
            redacted_output, _ = pii_filter.redact(output)
            result["output"] = redacted_output
            result["flags"].append(f"pii_redacted:{len(pii_findings)}_items")
            result["redacted"] = True
            result["safe"] = False

            logger.warning(json.dumps({
                "event": "pii_in_output",
                "pii_types": list(set(f["type"] for f in pii_findings)),
                "count": len(pii_findings),
            }))

    # System prompt disclosure check
    if check_system_leak:
        output_lower = output.lower()
        for pattern in SYSTEM_PROMPT_INDICATORS:
            if re.search(pattern, output_lower):
                result["flags"].append("system_prompt_leak_attempt")
                result["safe"] = False
                result["output"] = (
                    "I'm unable to share information about my system configuration. "
                    "How can I help you with something else?"
                )
                break

    if not result["safe"]:
        logger.warning(json.dumps({
            "event": "output_validation_failed",
            "flags": result["flags"],
        }))

    return result
