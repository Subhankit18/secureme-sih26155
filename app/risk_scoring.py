from __future__ import annotations

from typing import Final

# Temporary prototype scoring policy only.
# Replace these values later with the team-approved scoring methodology.
SEVERITY_TO_RATING: Final[dict[str, int]] = {
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}

SEVERITY_FLOOR: Final[dict[str, float]] = {
    "INFO": 0.0,
    "LOW": 20.0,
    "MEDIUM": 40.0,
    "HIGH": 60.0,
    "CRITICAL": 80.0,
}

RISK_BANDS: Final[tuple[tuple[float, float, str], ...]] = (
    (0.0, 19.99, "INFORMATIONAL"),
    (20.0, 39.99, "LOW"),
    (40.0, 59.99, "MEDIUM"),
    (60.0, 79.99, "HIGH"),
    (80.0, 100.0, "CRITICAL"),
)

WEIGHTS: Final[dict[str, float]] = {
    "severity": 0.25,
    "likelihood": 0.25,
    "impact": 0.20,
    "exposure": 0.15,
    "exploitability": 0.15,
}


def _validate_rating(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer from 1 to 5.")
    if not 1 <= value <= 5:
        raise ValueError(f"{name} must be between 1 and 5.")
    return value


def _severity_rating(severity: str) -> int:
    normalized = severity.strip().upper()
    if normalized not in SEVERITY_TO_RATING:
        allowed = ", ".join(SEVERITY_TO_RATING)
        raise ValueError(f"Unsupported severity '{severity}'. Allowed: {allowed}")
    return SEVERITY_TO_RATING[normalized]


def calculate_risk_score(
    *,
    severity: str,
    likelihood: int,
    impact: int,
    exposure: int,
    exploitability: int,
) -> float:
    """Return a deterministic 0-100 risk score.

    Each rating is 1..5. Severity is also derived from the control's severity label.
    A severity floor prevents a HIGH/CRITICAL control from receiving a misleadingly
    low overall risk score.
    """
    severity_rating = _severity_rating(severity)
    likelihood = _validate_rating("likelihood", likelihood)
    impact = _validate_rating("impact", impact)
    exposure = _validate_rating("exposure", exposure)
    exploitability = _validate_rating("exploitability", exploitability)

    weighted_rating = (
        severity_rating * WEIGHTS["severity"]
        + likelihood * WEIGHTS["likelihood"]
        + impact * WEIGHTS["impact"]
        + exposure * WEIGHTS["exposure"]
        + exploitability * WEIGHTS["exploitability"]
    )

    raw_score = (weighted_rating / 5.0) * 100.0
    floor = SEVERITY_FLOOR[severity.strip().upper()]
    return round(min(100.0, max(floor, raw_score)), 2)


def classify_risk(score: float) -> str:
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise ValueError("Risk score must be numeric.")
    if not 0.0 <= float(score) <= 100.0:
        raise ValueError("Risk score must be between 0 and 100.")

    score = float(score)
    for lower, upper, label in RISK_BANDS:
        if lower <= score <= upper:
            return label

    # Defensive fallback for floating-point edge cases.
    return "CRITICAL"


def severity_to_rating(severity: str) -> int:
    """Expose the deterministic severity mapping for reporting/tests."""
    return _severity_rating(severity)
