from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from app.models import Control, Finding, NormalizedConfig
from app.risk_scoring import calculate_risk_score, classify_risk, severity_to_rating


SUPPORTED_OPERATORS = {
    "equals",
    "not_equals",
    "greater_than_or_equal",
    "less_than_or_equal",
    "greater_than",
    "less_than",
    "contains",
    "not_contains",
}


def load_controls(path: str | Path) -> list[Control]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    controls = [Control(**item) for item in data.get("controls", []) if item.get("enabled", True)]
    for control in controls:
        if control.operator not in SUPPORTED_OPERATORS:
            raise ValueError(f"Unsupported rule operator: {control.operator}")
    return controls


def _evaluate(operator: str, observed: Any, expected: Any) -> bool | None:
    if observed is None:
        return None

    if operator == "equals":
        return observed == expected
    if operator == "not_equals":
        return observed != expected

    if operator == "greater_than_or_equal":
        try:
            return observed >= expected
        except TypeError:
            return False

    if operator == "less_than_or_equal":
        try:
            return observed <= expected
        except TypeError:
            return False

    if operator == "greater_than":
        try:
            return observed > expected
        except TypeError:
            return False

    if operator == "less_than":
        try:
            return observed < expected
        except TypeError:
            return False

    if operator == "contains":
        try:
            return expected in observed
        except TypeError:
            return False

    if operator == "not_contains":
        try:
            return expected not in observed
        except TypeError:
            return False

    raise ValueError(f"Unsupported operator: {operator}")


def _finding_id(analysis_id: str, control_id: str) -> str:
    digest = hashlib.sha256(f"{analysis_id}:{control_id}".encode()).hexdigest()[:10]
    return f"FND-{digest.upper()}"


def evaluate(config: NormalizedConfig, controls: list[Control]) -> list[Finding]:
    findings: list[Finding] = []

    for control in controls:
        observed = config.controls.get(control.field)
        passed = _evaluate(control.operator, observed, control.expected)

        if passed is None:
            status = "UNKNOWN"
            evidence = f"No observed value for normalized field '{control.field}'."
            finding_severity = control.severity.strip().upper()
            risk_score = None
            risk_level = "UNKNOWN"
        elif passed:
            status = "PASS"
            evidence = (
                f"Observed '{control.field}={observed}' satisfies "
                f"{control.operator} {control.expected}."
            )
            finding_severity = "INFO"
            risk_score = 0.0
            risk_level = "INFORMATIONAL"
        else:
            status = "FAIL"
            evidence = (
                f"Observed '{control.field}={observed}' does not satisfy "
                f"{control.operator} {control.expected}."
            )
            finding_severity = control.severity.strip().upper()
            risk_score = calculate_risk_score(
                severity=finding_severity,
                likelihood=control.likelihood,
                impact=control.impact,
                exposure=control.exposure,
                exploitability=control.exploitability,
            )
            risk_level = classify_risk(risk_score)

        risk_parameters = {
            "severity": severity_to_rating(finding_severity),
            "likelihood": control.likelihood,
            "impact": control.impact,
            "exposure": control.exposure,
            "exploitability": control.exploitability,
        }

        findings.append(
            Finding(
                finding_id=_finding_id(config.analysis_id, control.control_id),
                analysis_id=config.analysis_id,
                device_id=f"{config.device.vendor}:{config.device.hostname or 'unknown'}",
                control_id=control.control_id,
                framework=control.framework,
                status=status,
                severity=finding_severity,
                observed_value=observed,
                expected_value=control.expected,
                evidence=evidence,
                remediation_reference=control.remediation,
                risk_score=risk_score,
                risk_level=risk_level,
                risk_parameters=risk_parameters,
            )
        )

    return findings
