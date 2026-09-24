from __future__ import annotations

import os
import tempfile
from pathlib import Path
import io
import json
import re
from typing import Annotated

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, StreamingResponse

from app.pipeline import ALLOWED_EXTENSIONS, _max_size_bytes, run_pipeline
from app.pdf_report import build_pdf_report

PROJECT_ROOT = Path(__file__).resolve().parent
FRONTEND_FILE = PROJECT_ROOT / "frontend" / "index.html"
UPLOAD_DIR = PROJECT_ROOT / "uploads"

# Create the temporary upload directory automatically.
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="SIH26155 Member 2 Local API",
    version="0.1.1",
)


@app.get("/api/v1/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "sih26155-member2-local",
    }


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def index() -> HTMLResponse:
    if not FRONTEND_FILE.is_file():
        raise HTTPException(
            status_code=500,
            detail=f"Frontend file not found: {FRONTEND_FILE}",
        )

    try:
        html = FRONTEND_FILE.read_text(encoding="utf-8")

        return HTMLResponse(
            content=html,
            headers={"Cache-Control": "no-store"},
        )

    except OSError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Could not read frontend: {exc}",
        ) from exc


def _safe_original_name(filename: str | None) -> str:
    name = Path(filename or "configuration.conf").name

    if not name or name in {".", ".."}:
        name = "configuration.conf"

    return name


@app.post("/api/v1/analyses")
async def create_analysis(
    file: Annotated[
        UploadFile,
        File(description="Plain-text network configuration"),
    ],
):
    filename = _safe_original_name(file.filename)
    suffix = Path(filename).suffix.lower()

    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported file extension '{suffix}'. "
                f"Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
            ),
        )

    max_bytes = _max_size_bytes()

    data = await file.read(max_bytes + 1)

    if len(data) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"Configuration file is larger than {max_bytes // 1024} KB.",
        )

    try:
        text = data.decode("utf-8", errors="strict")

    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail="Configuration file must be valid UTF-8 plain text.",
        ) from exc

    temp_path: str | None = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=suffix,
            prefix="sih26155_",
            dir=UPLOAD_DIR,
            delete=False,
        ) as temp:
            temp.write(text)
            temp_path = temp.name

        # IMPORTANT:
        # The existing run_pipeline() remains the single source
        # of truth for parsing, normalization, compliance, and risk.
        result = run_pipeline(temp_path)

        # Show the actual uploaded filename in the response.
        result.source_file = filename
        result.normalized.source_file = filename

        return result.model_dump()

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {exc}",
        ) from exc

    finally:
        if temp_path:
            try:
                os.remove(temp_path)
            except OSError:
                pass

@app.get("/api/v1/analyses/{analysis_id}/pdf")
def download_analysis_pdf(analysis_id: str):
    """Generate and download a PDF report for a completed analysis."""
    if not re.fullmatch(r"[a-f0-9]{12}", analysis_id):
        raise HTTPException(status_code=400, detail="Invalid analysis ID.")

    analysis_path = PROJECT_ROOT / "output" / f"analysis_{analysis_id}.json"

    if not analysis_path.is_file():
        raise HTTPException(status_code=404, detail="Analysis not found.")

    try:
        data = json.loads(analysis_path.read_text(encoding="utf-8"))
        pdf_bytes = build_pdf_report(data)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Could not generate PDF report: {exc}",
        ) from exc

    filename = f"secureme-analysis-{analysis_id}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )

