from __future__ import annotations

import re
import tempfile
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.db_models import ReviewMapping
from app.pdf_report import build_pdf_report
from app.pipeline import ALLOWED_EXTENSIONS, PROJECT_ROOT, run_pipeline
from app.reaudit import run_reaudit


app = FastAPI(
    title="SIH26155 Member 2 Local API",
    version="0.1.2",
)


class ReviewDecision(BaseModel):
    reviewed_by: str
    normalized_field: str | None = None
    normalized_value: dict | None = None


@app.get("/api/v1/health")
def health():
    return {
        "status": "ok",
        "service": "SIH26155 Member 2 Local API",
    }


@app.get("/", response_class=HTMLResponse)
def home():
    frontend = PROJECT_ROOT / "frontend" / "index.html"

    if frontend.exists():
        return frontend.read_text(
            encoding="utf-8"
        )

    return """
    <html>
        <head>
            <title>SIH26155 Member 2</title>
        </head>
        <body>
            <h1>SIH26155 Member 2 Local API</h1>
            <p>API is running.</p>
            <p><a href="/docs">Open Swagger UI</a></p>
        </body>
    </html>
    """


@app.post("/api/v1/analyses")
async def create_analysis(
    file: UploadFile = File(...),
):
    filename = file.filename or "config.conf"
    suffix = Path(filename).suffix.lower()

    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported file extension '{suffix}'. "
                f"Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
            ),
        )

    data = await file.read()

    if not data:
        raise HTTPException(
            status_code=400,
            detail="Uploaded configuration is empty.",
        )

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=suffix,
        ) as temp_file:
            temp_file.write(data)
            temp_path = Path(temp_file.name)

        result = run_pipeline(str(temp_path))

        archive_dir = PROJECT_ROOT / "config_archive"
        archive_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        archive_path = (
            archive_dir / f"{result.analysis_id}{suffix}"
        )

        archive_path.write_bytes(data)

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
        if temp_path and temp_path.exists():
            temp_path.unlink()


@app.get(
    "/api/v1/analyses/{analysis_id}/reviews"
)
def get_reviews(
    analysis_id: str,
    db: Session = Depends(get_db),
):
    reviews = (
        db.query(ReviewMapping)
        .filter(
            ReviewMapping.analysis_id == analysis_id
        )
        .order_by(
            ReviewMapping.line_number
        )
        .all()
    )

    return [
        {
            "id": str(review.id),
            "analysis_id": review.analysis_id,
            "line_number": review.line_number,
            "source_command": review.source_command,
            "ai_category": review.ai_category,
            "ai_interpretation": review.ai_interpretation,
            "ai_confidence": (
                float(review.ai_confidence)
                if review.ai_confidence is not None
                else None
            ),
            "normalized_field": review.normalized_field,
            "normalized_value": review.normalized_value,
            "status": review.status,
            "reviewed_by": review.reviewed_by,
            "created_at": review.created_at,
            "updated_at": review.updated_at,
        }
        for review in reviews
    ]


@app.post(
    "/api/v1/reviews/{review_id}/approve"
)
def approve_review(
    review_id: str,
    decision: ReviewDecision,
    db: Session = Depends(get_db),
):
    review = (
        db.query(ReviewMapping)
        .filter(
            ReviewMapping.id == review_id
        )
        .first()
    )

    if review is None:
        raise HTTPException(
            status_code=404,
            detail="Review not found.",
        )

    if review.status == "APPROVED":
        raise HTTPException(
            status_code=400,
            detail="Review is already approved.",
        )

    if review.status == "REJECTED":
        raise HTTPException(
            status_code=400,
            detail="Rejected review cannot be approved.",
        )

    review.status = "APPROVED"
    review.reviewed_by = decision.reviewed_by
    review.normalized_field = decision.normalized_field
    review.normalized_value = decision.normalized_value

    db.commit()
    db.refresh(review)

    return {
        "status": "APPROVED",
        "review_id": str(review.id),
        "analysis_id": review.analysis_id,
    }


@app.post(
    "/api/v1/reviews/{review_id}/reject"
)
def reject_review(
    review_id: str,
    decision: ReviewDecision,
    db: Session = Depends(get_db),
):
    review = (
        db.query(ReviewMapping)
        .filter(
            ReviewMapping.id == review_id
        )
        .first()
    )

    if review is None:
        raise HTTPException(
            status_code=404,
            detail="Review not found.",
        )

    if review.status == "APPROVED":
        raise HTTPException(
            status_code=400,
            detail="Approved review cannot be rejected.",
        )

    review.status = "REJECTED"
    review.reviewed_by = decision.reviewed_by

    db.commit()
    db.refresh(review)

    return {
        "status": "REJECTED",
        "review_id": str(review.id),
        "analysis_id": review.analysis_id,
    }


@app.post(
    "/api/v1/analyses/{analysis_id}/reaudit"
)
def reaudit_analysis(
    analysis_id: str,
    db: Session = Depends(get_db),
):
    if not re.fullmatch(
        r"[a-f0-9]{12}",
        analysis_id,
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid analysis ID.",
        )

    archive_dir = PROJECT_ROOT / "config_archive"

    candidates = [
        path
        for path in archive_dir.glob(
            f"{analysis_id}.*"
        )
        if path.suffix.lower()
        in ALLOWED_EXTENSIONS
    ]

    if not candidates:
        raise HTTPException(
            status_code=404,
            detail=(
                "Original configuration unavailable. "
                "Upload the configuration again."
            ),
        )

    try:
        result = run_reaudit(
            parent_analysis_id=analysis_id,
            config_path=candidates[0],
            db=db,
        )

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
            detail=f"Re-audit failed: {exc}",
        ) from exc


@app.get(
    "/api/v1/analyses/{analysis_id}/pdf"
)
def download_analysis_pdf(
    analysis_id: str,
):
    if not re.fullmatch(
        r"[a-f0-9]{12}",
        analysis_id,
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid analysis ID.",
        )

    output_path = (
        PROJECT_ROOT
        / "output"
        / f"analysis_{analysis_id}.json"
    )

    if not output_path.exists():
        raise HTTPException(
            status_code=404,
            detail="Analysis not found.",
        )

    pdf_dir = PROJECT_ROOT / "output" / "pdf"

    pdf_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    pdf_path = (
        pdf_dir
        / f"analysis_{analysis_id}.pdf"
    )

    try:
        import json

        data = json.loads(
            output_path.read_text(
                encoding="utf-8"
            )
        )

        pdf_bytes = build_pdf_report(data)

        pdf_path.write_bytes(pdf_bytes)

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"PDF generation failed: {exc}",
        ) from exc

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=f"analysis_{analysis_id}.pdf",
    )