"""Tests for PII filter — real patterns from BR, IE, and EU."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from controls.pii_filter import scan, redact, validate_cpf


def test_email_detection():
    text = "Contact me at marcus.gestor@me.com for details"
    findings = scan(text)
    assert any(f["type"] == "email" for f in findings)


def test_irish_pps():
    text = "My PPS number is 1234567T"
    findings = scan(text)
    assert any(f["type"] == "pps_ireland" for f in findings)


def test_brazilian_cpf():
    text = "CPF: 123.456.789-09"
    findings = scan(text)
    assert any(f["type"] == "cpf_brazil" for f in findings)


def test_cpf_validation():
    assert validate_cpf("529.982.247-25") == True
    assert validate_cpf("111.111.111-11") == False
    assert validate_cpf("123.456.789-00") == False


def test_credit_card():
    text = "Card: 4111-1111-1111-1111"
    findings = scan(text)
    assert any(f["type"] == "credit_card" for f in findings)


def test_aws_key():
    text = "Key: AKIAIOSFODNN7EXAMPLE"
    findings = scan(text)
    assert any(f["type"] == "aws_key" for f in findings)


def test_redaction():
    text = "Email: test@example.com and CPF: 123.456.789-09"
    redacted, findings = redact(text)
    assert "test@example.com" not in redacted
    assert "123.456.789-09" not in redacted
    assert "[REDACTED]" in redacted
    assert len(findings) >= 2


def test_no_pii():
    text = "This is a normal message with no personal data."
    findings = scan(text)
    assert len(findings) == 0


def test_iban():
    text = "IBAN: IE29 AIBK 9311 5212 3456 78"
    findings = scan(text)
    assert any(f["type"] == "iban" for f in findings)
