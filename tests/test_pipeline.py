from pathlib import Path

import pytest

from app.compliance import evaluate, load_controls
from app.parsers.cisco import parse_cisco
from app.risk_scoring import calculate_risk_score, classify_risk
from app.vendor_detection import detect_vendor


def test_cisco_detection():
    text = Path("samples/cisco_noncompliant.conf").read_text(encoding="utf-8")
    result = detect_vendor(text)
    assert result.vendor == "cisco"
    assert result.method == "deterministic"


def test_cisco_parser_and_rules():
    text = Path("samples/cisco_noncompliant.conf").read_text(encoding="utf-8")
    normalized = parse_cisco(text, "TEST123", "demo.conf")
    controls = load_controls("config/controls.json")
    cisco_controls = [c for c in controls if c.source.startswith("demo:cisco:")]
    findings = evaluate(normalized, cisco_controls)

    assert normalized.controls["ssh_version"] == 1
    assert normalized.controls["telnet_enabled"] is True
    failed = [f for f in findings if f.status == "FAIL"]
    assert failed
    assert all(f.risk_score is not None for f in failed)
    assert all(0 <= f.risk_score <= 100 for f in failed)
    assert all(f.risk_level in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} for f in failed)
    assert all(set(f.risk_parameters) == {"severity", "likelihood", "impact", "exposure", "exploitability"} for f in failed)


def test_missing_field_is_unknown_not_false():
    text = Path("samples/cisco_compliant.conf").read_text(encoding="utf-8")
    normalized = parse_cisco(text, "TEST456", "demo.conf")

    controls = load_controls("config/controls.json")
    cisco_controls = [c for c in controls if c.source.startswith("demo:cisco:")]
    findings = evaluate(normalized, cisco_controls)

    password_finding = next(
        f for f in findings if f.control_id == "DEMO-CISCO-PASS-001"
    )
    assert password_finding.status == "PASS"
    assert password_finding.risk_score == 0.0
    assert password_finding.risk_level == "INFORMATIONAL"
    assert "logging_enabled" in normalized.controls


def test_risk_score_and_classification():
    score = calculate_risk_score(
        severity="HIGH",
        likelihood=4,
        impact=5,
        exposure=4,
        exploitability=4,
    )
    assert score == 84.0
    assert classify_risk(score) == "CRITICAL"


def test_severity_floor():
    # LOW severity can never be classified below the LOW band in this prototype policy.
    score = calculate_risk_score(
        severity="LOW",
        likelihood=1,
        impact=1,
        exposure=1,
        exploitability=1,
    )
    assert score == 25.0
    assert classify_risk(score) == "LOW"


def test_invalid_risk_rating_rejected():
    with pytest.raises(ValueError):
        calculate_risk_score(
            severity="HIGH",
            likelihood=6,
            impact=3,
            exposure=3,
            exploitability=3,
        )


def test_unsupported_operator_rejected(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(
        '{"controls":[{"control_id":"X","framework":"DEMO","title":"x","field":"x",'
        '"operator":"execute_code","expected":true,"severity":"HIGH",'
        '"likelihood":3,"impact":3,"exposure":3,"exploitability":3,'
        '"remediation":"x","source":"demo:cisco:temporary"}]}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_controls(bad)
