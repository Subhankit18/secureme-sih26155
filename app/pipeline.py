from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

from app.ai.groq_service import GroqAIService
from app.compliance import evaluate, load_controls
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
        raise FileNotFoundError(f"Configuration file not found: {file_path}")

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

    # Strict text mode. The file is data only; never executed.
    text = file_path.read_text(encoding="utf-8", errors="strict")
    return file_path.name, text


def _parse(vendor: str, text: str, analysis_id: str, source_file: str):
    if vendor == "cisco":
        return parse_cisco(text, analysis_id, source_file)
    if vendor == "fortinet":
        return parse_fortinet(text, analysis_id, source_file)
    raise ValueError(
        "Vendor is unsupported or ambiguous. "
        "This prototype supports deterministic Cisco/Fortinet identification only."
    )


def run_pipeline(path: str) -> AnalysisResult:
    source_file, text = _read_config(path)
    analysis_id = uuid.uuid4().hex[:12]

    detection = detect_vendor(text)
    normalized = _parse(detection.vendor, text, analysis_id, source_file)
    validate_normalized(normalized)

    controls = load_controls(PROJECT_ROOT / "config" / "controls.json")
    # Temporary demo control set is filtered by vendor.
    vendor_controls = [
        c for c in controls
        if c.enabled and c.source.startswith(f"demo:{detection.vendor}:")
    ]

    findings = evaluate(normalized, vendor_controls)

    fail_count = sum(f.status == "FAIL" for f in findings)
    unknown_count = sum(f.status == "UNKNOWN" for f in findings)

    failed_findings = [f for f in findings if f.status == "FAIL" and f.risk_score is not None]
    overall_risk_score = max((f.risk_score for f in failed_findings), default=0.0)
    overall_risk_level = (
        max(failed_findings, key=lambda f: f.risk_score).risk_level
        if failed_findings
        else "INFORMATIONAL"
    )

    summary = {
        "total_controls": len(findings),
        "pass": sum(f.status == "PASS" for f in findings),
        "fail": fail_count,
        "unknown": unknown_count,
        "severity_counts": {
            "CRITICAL": sum(f.severity == "CRITICAL" and f.status == "FAIL" for f in findings),
            "HIGH": sum(f.severity == "HIGH" and f.status == "FAIL" for f in findings),
            "MEDIUM": sum(f.severity == "MEDIUM" and f.status == "FAIL" for f in findings),
            "LOW": sum(f.severity == "LOW" and f.status == "FAIL" for f in findings),
            "INFO": sum(f.severity == "INFO" and f.status == "FAIL" for f in findings),
        },
        "overall_risk_score": overall_risk_score,
        "overall_risk_level": overall_risk_level,
        "parser_unknown_count": len(normalized.unknown_lines),
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
            findings=[f.model_dump() for f in findings],
            unknown_lines=[u.model_dump() for u in normalized.unknown_lines],
        )

        # AI is enrichment only: never modify findings or summary.
    elif should_call_ai:
        ai_result = {
            "status": "SKIPPED",
            "reason": "No GROQ_API_KEY available or AI_ENABLED=false.",
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

    output_dir = PROJECT_ROOT / "output"
    output_dir.mkdir(exist_ok=True)
    output_path = output_dir / f"analysis_{analysis_id}.json"
    output_path.write_text(
        json.dumps(result.model_dump(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return result


def _risk_banner(summary: dict) -> str:
    return str(summary.get("overall_risk_level", "INFORMATIONAL"))


def print_terminal_report(result: AnalysisResult) -> None:
    print("\n" + "=" * 72)
    print("ANALYSIS RESULT")
    print("=" * 72)

    print(f"Analysis ID : {result.analysis_id}")
    print(f"Source file : {result.source_file}")
    print(f"Vendor      : {result.vendor_detection.vendor}")
    print(f"Confidence  : {result.vendor_detection.confidence}")
    print(f"Method      : {result.vendor_detection.method}")
    print(f"Evidence    : {', '.join(result.vendor_detection.evidence) or 'none'}")

    print("\nNORMALIZED JSON")
    print("-" * 72)
    print(json.dumps(result.normalized.model_dump(), indent=2, ensure_ascii=False))

    print("\nDETERMINISTIC COMPLIANCE")
    print("-" * 72)

    for finding in result.findings:
        icon = {"PASS": "[PASS]", "FAIL": "[FAIL]", "UNKNOWN": "[UNKNOWN]"}[finding.status]
        print(
            f"{icon} {finding.control_id} | {finding.framework} | "
            f"Severity: {finding.severity} | Risk: {finding.risk_level}"
        )
        print(f"      Observed       : {finding.observed_value}")
        print(f"      Expected       : {finding.expected_value}")
        print(f"      Risk Score     : {finding.risk_score if finding.risk_score is not None else 'N/A'} / 100")
        print(
            "      Parameters     : "
            f"Severity={finding.risk_parameters.get('severity', 'N/A')}/5, "
            f"Likelihood={finding.risk_parameters.get('likelihood', 'N/A')}/5, "
            f"Impact={finding.risk_parameters.get('impact', 'N/A')}/5, "
            f"Exposure={finding.risk_parameters.get('exposure', 'N/A')}/5, "
            f"Exploitability={finding.risk_parameters.get('exploitability', 'N/A')}/5"
        )
        print(f"      Evidence       : {finding.evidence}")
        print(f"      Remediation    : {finding.remediation_reference}")

    print("\nRISK SUMMARY")
    print("-" * 72)
    print(f"Overall Risk Score : {result.summary['overall_risk_score']} / 100")
    print(f"Overall Risk Level : {_risk_banner(result.summary)}")
    print(f"Controls           : {result.summary['total_controls']}")
    print(f"PASS               : {result.summary['pass']}")
    print(f"FAIL               : {result.summary['fail']}")
    print(f"UNKNOWN            : {result.summary['unknown']}")
    print(f"Unknown config lines: {result.summary['parser_unknown_count']}")
    for level, count in result.summary["severity_counts"].items():
        print(f"{level:<19}: {count}")

    if result.normalized.unknown_lines:
        print("\nUNKNOWN CONFIGURATION LINES")
        print("-" * 72)
        for item in result.normalized.unknown_lines:
            print(f"line {item.line_number}: {item.source}")

    print("\nAI ASSISTANCE")
    print("-" * 72)

    if result.ai is None:
        print("Not required: deterministic checks produced no failures/unknowns.")
    elif result.ai.get("status") == "SKIPPED":
        print(f"Skipped: {result.ai.get('reason')}")
    else:
        print(f"Summary: {result.ai.get('summary')}")
        print(f"Risk explanation: {result.ai.get('risk_explanation')}")
        print(f"Remediation: {result.ai.get('remediation')}")

        for item in result.ai.get("unknown_command_interpretations", []):
            print(
                f"Unknown line {item['line_number']}: {item['command']}\n"
                f"  Category : {item['suggested_category']}\n"
                f"  Value    : {item['suggested_value']}\n"
                f"  Confidence: {item['confidence']:.2f}\n"
                f"  Review   : REQUIRED\n"
                f"  Why      : {item['explanation']}"
            )

    print("\nJSON saved to:")
    print(f"  output/analysis_{result.analysis_id}.json")
    print("\nNOTE: PASS/FAIL above was produced by deterministic rules.")
    print("=" * 72)
