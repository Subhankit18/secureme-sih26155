from __future__ import annotations

import json
import uuid
from pathlib import Path

from sqlalchemy.orm import Session

from app.compliance import evaluate, load_controls
from app.db_models import AuditHistory, ReviewMapping
from app.models import AnalysisResult, Evidence
from app.normalizer import validate_normalized
from app.pipeline import _parse, _read_config
from app.vendor_detection import detect_vendor


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run_reaudit(
    parent_analysis_id: str,
    config_path: Path,
    db: Session,
) -> AnalysisResult:

    source_file, text = _read_config(str(config_path))

    detection = detect_vendor(text)

    if detection.vendor == "unknown":
        raise ValueError(
            "Unable to detect vendor during re-audit."
        )

    analysis_id = uuid.uuid4().hex[:12]

    normalized = _parse(
        detection.vendor,
        text,
        analysis_id,
        source_file,
    )

    controls = load_controls(
        PROJECT_ROOT / "config" / "controls.json"
    )

    vendor_controls = [
        c
        for c in controls
        if c.enabled
        and c.source.startswith(
            f"{detection.vendor}:"
        )
        and c.field in normalized.controls
    ]

    allowed_fields = {
        c.field
        for c in controls
        if c.enabled
        and c.source.startswith(
            f"{detection.vendor}:"
        )
    }

    approved_reviews = (
        db.query(ReviewMapping)
        .filter(
            ReviewMapping.analysis_id == parent_analysis_id,
            ReviewMapping.status == "APPROVED",
        )
        .order_by(ReviewMapping.line_number)
        .all()
    )

    applied_mappings = []

    for review in approved_reviews:

        field = review.normalized_field
        value = review.normalized_value

        if not field:
            continue

        if field not in allowed_fields:
            continue

        if not isinstance(value, dict):
            continue

        if "value" not in value:
            continue

        matching_unknown = next(
            (
                item
                for item in normalized.unknown_lines
                if item.line_number == review.line_number
            ),
            None,
        )

        if matching_unknown is None:
            continue

        if field in normalized.controls:
            continue

        normalized.controls[field] = value["value"]

        normalized.evidence.setdefault(
            field,
            [],
        ).append(
            Evidence(
                line_number=review.line_number,
                source=review.source_command,
            )
        )

        applied_mappings.append(
            {
                "review_id": str(review.id),
                "line_number": review.line_number,
                "field": field,
            }
        )

    applied_lines = {
        item["line_number"]
        for item in applied_mappings
    }

    normalized.unknown_lines = [
        item
        for item in normalized.unknown_lines
        if item.line_number not in applied_lines
    ]

    validate_normalized(normalized)

    vendor_controls = [
        c
        for c in controls
        if c.enabled
        and c.source.startswith(
            f"{detection.vendor}:"
        )
        and c.field in normalized.controls
    ]

    findings = evaluate(
        normalized,
        vendor_controls,
    )

    fail_count = sum(
        f.status == "FAIL"
        for f in findings
    )

    unknown_count = sum(
        f.status == "UNKNOWN"
        for f in findings
    )

    failed_findings = [
        f
        for f in findings
        if (
            f.status == "FAIL"
            and f.risk_score is not None
        )
    ]

    overall_risk_score = max(
        (
            f.risk_score
            for f in failed_findings
        ),
        default=0.0,
    )

    overall_risk_level = (
        max(
            failed_findings,
            key=lambda f: f.risk_score,
        ).risk_level
        if failed_findings
        else "INFORMATIONAL"
    )

    summary = {
        "total_controls": len(findings),
        "pass": sum(
            f.status == "PASS"
            for f in findings
        ),
        "fail": fail_count,
        "unknown": unknown_count,
        "severity_counts": {
            "CRITICAL": sum(
                f.severity == "CRITICAL"
                and f.status == "FAIL"
                for f in findings
            ),
            "HIGH": sum(
                f.severity == "HIGH"
                and f.status == "FAIL"
                for f in findings
            ),
            "MEDIUM": sum(
                f.severity == "MEDIUM"
                and f.status == "FAIL"
                for f in findings
            ),
            "LOW": sum(
                f.severity == "LOW"
                and f.status == "FAIL"
                for f in findings
            ),
            "INFO": sum(
                f.severity == "INFO"
                and f.status == "FAIL"
                for f in findings
            ),
        },
        "overall_risk_score": overall_risk_score,
        "overall_risk_level": overall_risk_level,
        "parser_unknown_count": len(
            normalized.unknown_lines
        ),
        "parser_stats": normalized.parser_stats,
        "audit_type": "REAUDIT",
        "parent_analysis_id": parent_analysis_id,
        "approved_mappings_applied": len(
            applied_mappings
        ),
        "applied_mappings": applied_mappings,
    }

    result = AnalysisResult(
        analysis_id=analysis_id,
        source_file=source_file,
        vendor_detection=detection,
        normalized=normalized,
        findings=findings,
        summary=summary,
        ai=None,
    )

    output_dir = PROJECT_ROOT / "output"
    output_dir.mkdir(exist_ok=True)

    output_path = (
        output_dir
        / f"analysis_{analysis_id}.json"
    )

    output_path.write_text(
        json.dumps(
            result.model_dump(),
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    total = len(findings)
    passed = sum(
        f.status == "PASS"
        for f in findings
    )

    compliance = (
        round(
            (passed / total) * 100,
            2,
        )
        if total
        else 0.0
    )

    history = AuditHistory(
        analysis_id=analysis_id,
        parent_analysis_id=parent_analysis_id,
        audit_type="REAUDIT",
        compliance_percent=compliance,
        risk_score=overall_risk_score,
        total_controls=total,
        passed_controls=passed,
        failed_controls=fail_count,
        unknown_controls=unknown_count,
        approved_mapping_count=len(
            applied_mappings
        ),
    )

    db.add(history)
    db.commit()

    return result