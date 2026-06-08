from __future__ import annotations

from fastapi import APIRouter, HTTPException

from apireconx.schemas import ApiEndpoint, GenerateAttackRequest, OpenAPIImportRequest, OpenAPIImportResponse
from apireconx.services.attack_generator import generate_attack_cases
from apireconx.services.openapi_importer import fetch_spec, parse_openapi, parse_spec_text
from apireconx.storage import store


router = APIRouter(prefix="/api/discovery", tags=["discovery"])


@router.post("/openapi", response_model=OpenAPIImportResponse)
async def import_openapi(payload: OpenAPIImportRequest) -> OpenAPIImportResponse:
    try:
        if payload.spec_url:
            spec_text = await fetch_spec(payload.spec_url)
        elif payload.spec_text:
            spec_text = payload.spec_text
        else:
            raise ValueError("Provide spec_text or spec_url")
        spec = parse_spec_text(spec_text)
        endpoints = parse_openapi(spec, source_name=payload.source_name)
        saved = store.upsert_endpoints(endpoints)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    imported_ids = {endpoint.id for endpoint in endpoints}
    return OpenAPIImportResponse(imported=len(endpoints), endpoints=[endpoint for endpoint in saved if endpoint.id in imported_ids])


@router.get("/endpoints", response_model=list[ApiEndpoint])
def list_endpoints() -> list[ApiEndpoint]:
    return store.list_endpoints()


@router.post("/attacks")
def generate_attacks(payload: GenerateAttackRequest):
    endpoint = store.get_endpoint(payload.endpoint_id)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return generate_attack_cases(endpoint)
