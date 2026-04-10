"""
PII Detection and Redaction Module
Detects and redacts personally identifiable information before it reaches an LLM.
GDPR-aligned: data minimization principle (Art. 5(1)(c)).

Covers: emails, phones, credit cards, Irish PPS numbers, Brazilian CPF,
passport numbers, IBANs.

Author: Marcus Paula | Cloud Security Architect
"""

import re
from typing import List, Tuple

REDACTION_MARKER = "[REDACTED]"

PII_PATTERNS: List[Tuple[str, str]] = [
    # Email addresses
    ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),

    # Phone numbers (international formats)
    ("phone", r"(?:\+\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}"),

    # Credit card numbers (Visa, MC, Amex)
    ("credit_card", r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{3,4}\b"),

    # Irish PPS Number (7 digits + 1-2 letters)
    ("pps_ireland", r"\b\d{7}[A-Z]{1,2}\b"),

    # Brazilian CPF (xxx.xxx.xxx-xx)
    ("cpf_brazil", r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"),

    # Brazilian CNPJ (xx.xxx.xxx/xxxx-xx)
    ("cnpj_brazil", r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b"),

    # Passport number (generic: 1-2 letters + 6-9 digits)
    ("passport", r"\b[A-Z]{1,2}\d{6,9}\b"),

    # IBAN (2 letter country + 2 check digits + up to 30 alphanum)
    ("iban", r"\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}[\s]?[\dA-Z]{4}[\s]?[\dA-Z]{4}[\s]?[\dA-Z]{0,16}\b"),

    # IPv4 addresses
    ("ip_address", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),

    # AWS Access Key ID
    ("aws_key", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),

    # AWS Secret Key (40 char base64)
    ("aws_secret", r"\b[A-Za-z0-9/+=]{40}\b"),
]


def scan(text: str) -> List[dict]:
    """
    Scan text for PII. Returns list of findings with type and position.
    Does NOT modify the text.
    """
    findings = []
    for pii_type, pattern in PII_PATTERNS:
        for match in re.finditer(pattern, text):
            findings.append({
                "type": pii_type,
                "start": match.start(),
                "end": match.end(),
                "value_preview": f"{match.group()[:3]}...{match.group()[-2:]}",
            })
    return findings


def redact(text: str) -> Tuple[str, List[dict]]:
    """
    Scan and redact all PII from text.
    Returns (redacted_text, findings).
    GDPR: ensures no PII reaches the LLM.
    """
    findings = scan(text)
    if not findings:
        return text, []

    # Sort by position (reverse) to replace without shifting indices
    findings_sorted = sorted(findings, key=lambda f: f["start"], reverse=True)
    redacted = text
    for finding in findings_sorted:
        marker = f"{REDACTION_MARKER}_{finding['type'].upper()}"
        redacted = redacted[:finding["start"]] + marker + redacted[finding["end"]:]

    return redacted, findings


def validate_cpf(cpf: str) -> bool:
    """Validate Brazilian CPF checksum."""
    cpf = re.sub(r"[^\d]", "", cpf)
    if len(cpf) != 11 or cpf == cpf[0] * 11:
        return False

    for i in range(9, 11):
        total = sum(int(cpf[j]) * ((i + 1) - j) for j in range(i))
        digit = (total * 10 % 11) % 10
        if int(cpf[i]) != digit:
            return False
    return True
