from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field, field_validator


class Evidence(BaseModel):
    line_number: int
    source: str


class DeviceInfo(BaseModel):
    vendor: str
    hostname: str | None = None
    model: str | None = None
    serial: str | None = None


class NormalizedConfig(BaseModel):
    analysis_id: str
    source_file: str
    device: DeviceInfo
    controls: dict[str, Any]
    unknown_lines: list[Evidence] = Field(default_factory=list)


class Control(BaseModel):
    control_id: str
    framework: str
    title: str
    field: str
    operator: str
    expected: Any
    severity: str
    remediation: str
    source: str
    likelihood: int = 3
    impact: int = 3
    exposure: int = 3
    exploitability: int = 3
    enabled: bool = True

    @field_validator("likelihood", "impact", "exposure", "exploitability")
    @classmethod
    def validate_risk_rating(cls, value: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 5:
            raise ValueError("Risk parameters must be integers from 1 to 5.")
        return value


class Finding(BaseModel):
    finding_id: str
    analysis_id: str
    device_id: str
    control_id: str
    framework: str
    status: str
    severity: str
    observed_value: Any
    expected_value: Any
    evidence: str
    remediation_reference: str
    risk_score: float | None = None
    risk_level: str
    risk_parameters: dict[str, int] = Field(default_factory=dict)
    ai_enrichment: dict[str, Any] | None = None


class VendorDetection(BaseModel):
    vendor: str
    confidence: float
    method: str
    evidence: list[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    analysis_id: str
    source_file: str
    vendor_detection: VendorDetection
    normalized: NormalizedConfig
    findings: list[Finding]
    summary: dict[str, Any]
    ai: dict[str, Any] | None = None
