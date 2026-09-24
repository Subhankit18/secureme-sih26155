from __future__ import annotations

from io import BytesIO
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def _text(value: Any) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, (dict, list)):
        return str(value)
    return str(value)


def _p(value: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(_text(value)).replace("\n", "<br/>"), style)


def build_pdf_report(data: dict[str, Any]) -> bytes:
    """Build a PDF directly from a completed SecureMe analysis result."""
    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=14 * mm,
        leftMargin=14 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
        title="SecureMe Security Compliance Analysis",
        author="SecureMe",
    )

    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=20,
        leading=24,
        alignment=TA_CENTER,
        spaceAfter=8,
    )
    heading = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading2"],
        fontSize=12,
        leading=15,
        spaceBefore=10,
        spaceAfter=6,
    )
    body = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontSize=8.5,
        leading=11,
    )
    small = ParagraphStyle(
        "ReportSmall",
        parent=body,
        fontSize=7.5,
        leading=9.5,
    )

    story = [
        Paragraph("SecureMe", title),
        Paragraph(
            "Network Security Compliance Analysis Report",
            ParagraphStyle(
                "Subtitle",
                parent=body,
                alignment=TA_CENTER,
                spaceAfter=12,
            ),
        ),
    ]

    summary = data.get("summary") or {}
    detection = data.get("vendor_detection") or {}
    normalized = data.get("normalized") or {}
    device = normalized.get("device") or {}

    meta = [
        ["Analysis ID", _text(data.get("analysis_id"))],
        ["Source File", _text(data.get("source_file"))],
        ["Vendor", _text(detection.get("vendor") or device.get("vendor"))],
        ["Detection Method", _text(detection.get("method"))],
        ["Detection Confidence", _text(detection.get("confidence"))],
        ["Overall Risk", f"{_text(summary.get('overall_risk_score'))} / 100"],
        ["Risk Level", _text(summary.get("overall_risk_level"))],
    ]

    table = Table(meta, colWidths=[42 * mm, 135 * mm], repeatRows=0)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef3f8")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5df")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.extend([table, Spacer(1, 5 * mm)])

    story.append(Paragraph("Compliance Summary", heading))
    summary_rows = [
        ["Total Controls", _text(summary.get("total_controls"))],
        ["PASS", _text(summary.get("pass"))],
        ["FAIL", _text(summary.get("fail"))],
        ["UNKNOWN", _text(summary.get("unknown"))],
        ["Unknown Configuration Lines", _text(summary.get("parser_unknown_count"))],
    ]
    t = Table(summary_rows, colWidths=[70 * mm, 30 * mm])
    t.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5df")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.extend([t, Spacer(1, 3 * mm)])

    story.append(Paragraph("Device", heading))
    device_rows = [
        ["Hostname", _text(device.get("hostname"))],
        ["Vendor", _text(device.get("vendor"))],
        ["Model", _text(device.get("model"))],
        ["Serial", _text(device.get("serial"))],
    ]
    dt = Table(device_rows, colWidths=[42 * mm, 135 * mm])
    dt.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f7f9fb")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d5dce3")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("PADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.extend([dt, Spacer(1, 3 * mm)])

    story.append(Paragraph("Deterministic Findings", heading))
    findings = data.get("findings") or []
    finding_rows = [
        [
            _p("Control", small),
            _p("Status", small),
            _p("Severity", small),
            _p("Observed", small),
            _p("Expected", small),
            _p("Risk", small),
        ]
    ]

    for finding in findings:
        finding_rows.append(
            [
                _p(finding.get("control_id"), small),
                _p(finding.get("status"), small),
                _p(finding.get("severity"), small),
                _p(finding.get("observed_value"), small),
                _p(finding.get("expected_value"), small),
                _p(
                    "N/A"
                    if finding.get("risk_score") is None
                    else finding.get("risk_score"),
                    small,
                ),
            ]
        )

    ft = Table(
        finding_rows,
        colWidths=[30 * mm, 20 * mm, 22 * mm, 35 * mm, 35 * mm, 20 * mm],
        repeatRows=1,
    )
    ft.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eaf1f8")),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5df")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.extend([ft, Spacer(1, 3 * mm)])

    for finding in findings:
        story.append(
            Paragraph(
                f"<b>{escape(_text(finding.get('control_id')))} — "
                f"{escape(_text(finding.get('status')))}</b>",
                body,
            )
        )
        story.append(
            _p(
                f"Framework: {finding.get('framework')} | "
                f"Evidence: {finding.get('evidence')} | "
                f"Remediation: {finding.get('remediation_reference')}",
                small,
            )
        )
        story.append(Spacer(1, 1.5 * mm))

    unknown_lines = normalized.get("unknown_lines") or []
    if unknown_lines:
        story.append(Paragraph("Unknown Configuration Lines", heading))
        for item in unknown_lines:
            story.append(
                _p(
                    f"Line {item.get('line_number')}: {item.get('source')}",
                    body,
                )
            )

    ai = data.get("ai")
    if ai:
        story.append(Paragraph("AI Assistance — Advisory Only", heading))
        story.append(
            _p(
                f"Summary: {ai.get('summary', 'N/A')}",
                body,
            )
        )
        story.append(
            _p(
                f"Risk explanation: {ai.get('risk_explanation', 'N/A')}",
                body,
            )
        )
        story.append(
            _p(
                f"Remediation: {ai.get('remediation', 'N/A')}",
                body,
            )
        )

        interpretations = ai.get("unknown_command_interpretations") or []
        if interpretations:
            story.append(Spacer(1, 2 * mm))
            story.append(Paragraph("Unknown Command Suggestions", body))
            for item in interpretations:
                story.append(
                    _p(
                        f"Line {item.get('line_number')}: "
                        f"{item.get('command')} | "
                        f"Category: {item.get('suggested_category')} | "
                        f"Value: {item.get('suggested_value')} | "
                        f"Confidence: {item.get('confidence')}",
                        small,
                    )
                )

    story.extend(
        [
            Spacer(1, 6 * mm),
            Paragraph(
                "<b>Important:</b> PASS/FAIL results in this report are produced by "
                "SecureMe's deterministic compliance rules. AI content is advisory and "
                "does not override deterministic findings.",
                small,
            ),
        ]
    )

    doc.build(story)
    return buffer.getvalue()
