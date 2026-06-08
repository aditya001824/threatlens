from fastapi import APIRouter

from apireconx.schemas import JwtAnalysis, JwtAnalyzeRequest
from apireconx.services.jwt_analyzer import analyze_jwt


router = APIRouter(prefix="/api/jwt", tags=["jwt"])


@router.post("/analyze", response_model=JwtAnalysis)
def analyze(payload: JwtAnalyzeRequest) -> JwtAnalysis:
    return analyze_jwt(payload.token, payload.weak_secrets)
