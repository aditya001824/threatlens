from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from apireconx.schemas import SecurityReport
from apireconx.services.reporting import build_markdown_report, build_security_report


router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/{scan_id}.md", response_class=PlainTextResponse)
def get_markdown_report(scan_id: str) -> str:
    report = build_security_report(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="Scan not found")
    return build_markdown_report(report)


@router.get("/{scan_id}", response_model=SecurityReport)
def get_report(scan_id: str) -> SecurityReport:
    report = build_security_report(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="Scan not found")
    return report
