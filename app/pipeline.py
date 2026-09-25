from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

from sqlalchemy.orm import Session

from app.ai.groq_service import GroqAIService
from app.compliance import evaluate, load_controls
from app.database import SessionLocal
from app.db_models import AuditHistory, ReviewMapping
from app.models import AnalysisResult
from app.normalizer import validate_normalized
from app.parsers.cisco import parse_cisco
from app.parsers.fortinet import parse_fortinet
from app.vendor_detection import detect_vendor


ALLOWED_EXTENSIONS = {".conf", ".cfg", ".txt", ".log"}
DEFAULT_MAX_KB = 512
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _max_size_bytes() -> int:
    kb = int(os.getenv("MAX_CONFIG_SIZE_KB", str(DEFAULT_MAX_KB)))
    return kb * 1024


def _read_config(path: str) -> tuple[str, str]:
    file_path = Path(path).expanduser().resolve()

    if not file_path.is_file():
        raise FileNotFoundError(
            f"Configuration file not found: {file_path}"
        )

    if file_path.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise ValueError(
            f"Unsupported file extension '{file_path.suffix}'. "
            f"Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        )

    if file_path.stat().st_size > _max_size_bytes():
        raise ValueError(
            f"Configuration file is larger than "
            f"{_max_size_bytes() // 1024} KB."
        )

    text = file_path.read_text(
        encoding="utf-8",
        errors="strict",
    )

    return file_path.name, text


def _parse(
    vendor: str,
    text: str,
    analysis_id: str,
    source_file: str,
):
    if vendor == "cisco":
        return parse_cisco(
            text,
            analysis_id,
            source_file,
        )

    if vendor == "fortinet":
        return parse_fortinet(
            text,
            analysis_id,
            source_file,
        )

    raise ValueError(
        "Vendor is unsupported or ambiguous. "
        "This prototype supports deterministic "
        "Cisco/Fortinet identification only."
    )


def _json_value(value):
    if isinstance(value, dict):
        return value

    return {
        "value": value
    }


def _save_review_mappings(
    result: AnalysisResult,
    db: Session,
) -> int:
    unknown_lines = result.normalized.unknown_lines

    if not unknown_lines:
        return 0

    ai_items = []

    if result.ai and isinstance(result.ai, dict):
        ai_items = result.ai.get(
            "unknown_command_interpretations",
            [],
        )

    ai_by_line = {}

    for item in ai_items:
        try:
            line_number = int(item.get("line_number"))
            ai_by_line[line_number] = item
        except (TypeError, ValueError):
            continue

    created_count = 0

    for unknown in unknown_lines:
        ai_item = ai_by_line.get(
            unknown.line_number,
            {},
        )

        suggested_category = ai_item.get(
            "suggested_category"
        )

        suggested_value = ai_item.get(
            "suggested_value"
        )

        confidence = ai_item.get(
            "confidence"
        )

        explanation = ai_item.get(
            "explanation"
        )

        mapping = ReviewMapping(
            analysis_id=result.analysis_id,
            line_number=unknown.line_number,
            source_command=unknown.source,
            ai_category=suggested_category,
            ai_interpretation=explanation,
            ai_confidence=confidence,
            normalized_field=None,
            normalized_value=(
                _json_value(suggested_value)
                if suggested_value is not None
                else None
            ),
            status="PENDING",
            reviewed_by=None,
        )

        db.add(mapping)
        created_count += 1

    return created_count


def _save_audit_history(
    result: AnalysisResult,
    db: Session,
    approved_mapping_count: int = 0,
) -> None:
    summary = result.summary

    audit = AuditHistory(
        analysis_id=result.analysis_id,
        parent_analysis_id=None,
        audit_type="INITIAL",
        compliance_percent=(
            (
                summary["pass"]
                / summary["total_controls"]
                * 100
            )
            if summary["total_controls"]
            else 0
        ),
        risk_score=summary["overall_risk_score"],
        total_controls=summary["total_controls"],
        passed_controls=summary["pass"],
        failed_controls=summary["fail"],
        unknown_controls=summary["unknown"],
        approved_mapping_count=approved_mapping_count,
    )

    db.add(audit)


def _persist_database_records(
    result: AnalysisResult,
) -> None:
    db = SessionLocal()

    try:
        _save_review_mappings(
            result,
            db,
        )

        _save_audit_history(
            result,
            db,
        )

        db.commit()

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


def run_pipeline(path: str) -> AnalysisResult:
    source_file, text = _read_config(path)

    analysis_id = uuid.uuid4().hex[:12]

    detection = detect_vendor(text)

    normalized = _parse(
        detection.vendor,
        text,
        analysis_id,
        source_file,
    )

    validate_normalized(normalized)

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
    }

    ai_service = GroqAIService()

    should_call_ai = bool(
        fail_count
        or unknown_count
        or normalized.unknown_lines
    )

    ai_result = None

    if should_call_ai and ai_service.available:
        ai_result = ai_service.enrich(
            vendor=detection.vendor,
            findings=[
                f.model_dump()
                for f in findings
            ],
            unknown_lines=[
                u.model_dump()
                for u in normalized.unknown_lines
            ],
        )

    elif should_call_ai:
        ai_result = {
            "status": "SKIPPED",
            "reason": (
                "No GROQ_API_KEY available "
                "or AI_ENABLED=false."
            ),
        }

    result = AnalysisResult(
        analysis_id=analysis_id,
        source_file=source_file,
        vendor_detection=detection,
        normalized=normalized,
        findings=findings,
        summary=summary,
        ai=ai_result,
    )

    # -----------------------------------------------------
    # Save JSON output
    # -----------------------------------------------------

    output_dir = PROJECT_ROOT / "output"
    output_dir.mkdir(
        exist_ok=True
    )

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

    # -----------------------------------------------------
    # Save review mappings + audit history
    # -----------------------------------------------------

    _persist_database_records(result)

    return result


def _risk_banner(summary: dict) -> str:
    return str(
        summary.get(
            "overall_risk_level",
            "INFORMATIONAL",
        )
    )


def print_terminal_report(
    result: AnalysisResult,
) -> None:

    print("\n" + "=" * 72)
    print("ANALYSIS RESULT")
    print("=" * 72)

    print(
        f"Analysis ID : {result.analysis_id}"
    )

    print(
        f"Source file : {result.source_file}"
    )

    print(
        f"Vendor      : "
        f"{result.vendor_detection.vendor}"
    )

    print(
        f"Confidence  : "
        f"{result.vendor_detection.confidence}"
    )

    print(
        f"Method      : "
        f"{result.vendor_detection.method}"
    )

    print(
        "Evidence    : "
        + (
            ", ".join(
                result.vendor_detection.evidence
            )
            or "none"
        )
    )

    print("\nNORMALIZED JSON")
    print("-" * 72)

    print(
        json.dumps(
            result.normalized.model_dump(),
            indent=2,
            ensure_ascii=False,
        )
    )

    print("\nDETERMINISTIC COMPLIANCE")
    print("-" * 72)

    for finding in result.findings:

        icon = {
            "PASS": "[PASS]",
            "FAIL": "[FAIL]",
            "UNKNOWN": "[UNKNOWN]",
        }[finding.status]

        print(
            f"{icon} "
            f"{finding.control_id} | "
            f"{finding.framework} | "
            f"Severity: {finding.severity} | "
            f"Risk: {finding.risk_level}"
        )

        print(
            f"      Observed       : "
            f"{finding.observed_value}"
        )

        print(
            f"      Expected       : "
            f"{finding.expected_value}"
        )

        risk_score = (
        finding.risk_score
        if finding.risk_score is not None
        else "N/A"
    )

        print(
        f"      Risk Score     : "
          f"{risk_score} / 100"
        )

        print(
            "      Parameters     : "
            f"Severity="
            f"{finding.risk_parameters.get('severity', 'N/A')}/5, "
            f"Likelihood="
            f"{finding.risk_parameters.get('likelihood', 'N/A')}/5, "
            f"Impact="
            f"{finding.risk_parameters.get('impact', 'N/A')}/5, "
            f"Exposure="
            f"{finding.risk_parameters.get('exposure', 'N/A')}/5, "
            f"Exploitability="
            f"{finding.risk_parameters.get('exploitability', 'N/A')}/5"
        )

        print(
            f"      Evidence       : "
            f"{finding.evidence}"
        )

        print(
            f"      Remediation    : "
            f"{finding.remediation_reference}"
        )

    print("\nRISK SUMMARY")
    print("-" * 72)

    print(
        f"Overall Risk Score : "
        f"{result.summary['overall_risk_score']} / 100"
    )

    print(
        f"Overall Risk Level : "
        f"{_risk_banner(result.summary)}"
    )

    print(
        f"Controls           : "
        f"{result.summary['total_controls']}"
    )

    print(
        f"PASS               : "
        f"{result.summary['pass']}"
    )

    print(
        f"FAIL               : "
        f"{result.summary['fail']}"
    )

    print(
        f"UNKNOWN            : "
        f"{result.summary['unknown']}"
    )

    print(
        f"Unknown config lines: "
        f"{result.summary['parser_unknown_count']}"
    )

    for level, count in result.summary[
        "severity_counts"
    ].items():
        print(
            f"{level:<19}: {count}"
        )

    if result.normalized.unknown_lines:

        print(
            "\nUNKNOWN CONFIGURATION LINES"
        )

        print("-" * 72)

        for item in result.normalized.unknown_lines:
            print(
                f"line {item.line_number}: "
                f"{item.source}"
            )

    print("\nAI ASSISTANCE")
    print("-" * 72)

    if result.ai is None:

        print(
            "Not required: deterministic checks "
            "produced no failures/unknowns."
        )

    elif result.ai.get("status") == "SKIPPED":

        print(
            f"Skipped: "
            f"{result.ai.get('reason')}"
        )

    else:

        print(
            f"Summary: "
            f"{result.ai.get('summary')}"
        )

        print(
            f"Risk explanation: "
            f"{result.ai.get('risk_explanation')}"
        )

        print(
            f"Remediation: "
            f"{result.ai.get('remediation')}"
        )

        for item in result.ai.get(
            "unknown_command_interpretations",
            [],
        ):

            print(
                f"Unknown line "
                f"{item['line_number']}: "
                f"{item['command']}\n"
                f"  Category : "
                f"{item['suggested_category']}\n"
                f"  Value    : "
                f"{item['suggested_value']}\n"
                f"  Confidence: "
                f"{item['confidence']:.2f}\n"
                f"  Review   : REQUIRED\n"
                f"  Why      : "
                f"{item['explanation']}"
            )

    print("\nJSON saved to:")
    print(
        f"  output/"
        f"analysis_{result.analysis_id}.json"
    )

    print(
        "\nNOTE: PASS/FAIL above was "
        "produced by deterministic rules."
    )

    print("=" * 72)