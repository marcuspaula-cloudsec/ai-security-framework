"""
Prompt Injection Defense Module
Sanitizes and validates LLM inputs to prevent prompt injection attacks.
OWASP LLM Top 10 — LLM01: Prompt Injection

Author: Marcus Paula | Cloud Security Architect
"""

import re
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Known injection patterns (regex)
INJECTION_PATTERNS = [
    r"ignore\s+(previous|above|all)\s+(instructions|prompts|rules)",
    r"disregard\s+(your|the|all)\s+(instructions|rules|guidelines)",
    r"you\s+are\s+now\s+(a|an|acting\s+as)",
    r"pretend\s+(you|to\s+be|that)",
    r"forget\s+(everything|your|all)",
    r"system\s*prompt",
    r"reveal\s+(your|the)\s+(system|initial|original)\s+(prompt|instructions)",
    r"what\s+(are|were)\s+your\s+(instructions|rules|guidelines)",
    r"translate\s+the\s+above",
    r"repeat\s+(everything|all|the\s+text)\s+(above|before)",
    r"\[\s*INST\s*\]",
    r"<\s*/?\s*system\s*>",
    r"```\s*(system|admin|root)",
    r"ADMIN\s*MODE",
    r"developer\s*mode",
    r"DAN\s*mode",
    r"jailbreak",
]

MAX_INPUT_LENGTH = 4096
MAX_LINE_COUNT = 50


def validate_input(user_input: str) -> dict:
    """
    Validate and sanitize user input before sending to LLM.

    Returns:
        dict with keys: safe (bool), input (str), flags (list), blocked (bool)
    """
    result = {
        "safe": True,
        "input": user_input,
        "flags": [],
        "blocked": False,
    }

    if not user_input or not user_input.strip():
        result["flags"].append("empty_input")
        result["blocked"] = True
        result["safe"] = False
        return result

    # Length check
    if len(user_input) > MAX_INPUT_LENGTH:
        result["flags"].append(f"exceeds_max_length:{len(user_input)}")
        result["input"] = user_input[:MAX_INPUT_LENGTH]
        result["safe"] = False

    # Line count check (prompt stuffing)
    if user_input.count("\n") > MAX_LINE_COUNT:
        result["flags"].append(f"excessive_lines:{user_input.count(chr(10))}")
        result["safe"] = False

    # Injection pattern scan
    input_lower = user_input.lower()
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, input_lower):
            result["flags"].append(f"injection_pattern:{pattern[:40]}")
            result["safe"] = False
            result["blocked"] = True

    # Unicode obfuscation detection
    if _has_unicode_tricks(user_input):
        result["flags"].append("unicode_obfuscation")
        result["safe"] = False

    # Log security event
    if not result["safe"]:
        logger.warning(json.dumps({
            "event": "input_validation_failed",
            "flags": result["flags"],
            "blocked": result["blocked"],
            "input_length": len(user_input),
        }))

    return result


def _has_unicode_tricks(text: str) -> bool:
    """Detect Unicode homoglyphs and invisible characters used to bypass filters."""
    suspicious_ranges = [
        (0x200B, 0x200F),  # Zero-width characters
        (0x2028, 0x202F),  # Line/paragraph separators
        (0x2060, 0x2064),  # Invisible operators
        (0xFEFF, 0xFEFF),  # BOM
        (0xE0000, 0xE007F),  # Tags block
    ]
    for char in text:
        code = ord(char)
        for start, end in suspicious_ranges:
            if start <= code <= end:
                return True
    return False


def sanitize_for_context(user_input: str, role: str = "user") -> str:
    """
    Wrap user input in clear delimiters to prevent role confusion.
    """
    sanitized = user_input.replace("```", "'''")
    return f"[START {role.upper()} INPUT]\n{sanitized}\n[END {role.upper()} INPUT]"
