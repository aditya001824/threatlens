from fastapi import APIRouter, HTTPException

from apireconx.schemas import ScanRequest, ScanResult, ScanSummary
from apireconx.services.scanner import scanner
from apireconx.storage import store


router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("", response_model=ScanResult)
async def run_scan(payload: ScanRequest) -> ScanResult:
    try:
        return await scanner.run_scan(payload)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("", response_model=list[ScanSummary])
def list_scans() -> list[ScanSummary]:
    return store.list_scans()


@router.get("/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: str) -> ScanResult:
    result = store.get_scan_result(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    summary, findings, attacks = result
    return ScanResult(summary=summary, findings=findings, attacks=attacks)
