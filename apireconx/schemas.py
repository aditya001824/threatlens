from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


HttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
Severity = Literal["info", "low", "medium", "high", "critical"]


class ApiEndpoint(BaseModel):
    id: str
    method: HttpMethod
    path: str
    summary: str = ""
    operation_id: str | None = None
    tags: list[str] = Field(default_factory=list)
    parameters: list[dict[str, Any]] = Field(default_factory=list)
    request_schema: dict[str, Any] | None = None
    response_schema: dict[str, Any] | None = None
    auth_required: bool = True
    source: str = "manual"
    created_at: datetime | None = None


class OpenAPIImportRequest(BaseModel):
    spec_text: str | None = None
    spec_url: str | None = None
    source_name: str = "openapi"


class OpenAPIImportResponse(BaseModel):
    imported: int
    endpoints: list[ApiEndpoint]


class AttackCase(BaseModel):
    id: str
    name: str
    category: str
    method: HttpMethod
    path: str
    description: str
    payload: dict[str, Any] | None = None
    query_params: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    path_params: dict[str, Any] = Field(default_factory=dict)
    expected_signal: str = ""


class GenerateAttackRequest(BaseModel):
    endpoint_id: str


class JwtAnalyzeRequest(BaseModel):
    token: str
    weak_secrets: list[str] = Field(
        default_factory=lambda: ["secret", "password", "changeme", "admin", "jwt", "test", "dev", "api"]
    )


class JwtFinding(BaseModel):
    severity: Severity
    title: str
    detail: str


class JwtAnalysis(BaseModel):
    valid_shape: bool
    header: dict[str, Any] = Field(default_factory=dict)
    payload: dict[str, Any] = Field(default_factory=dict)
    findings: list[JwtFinding] = Field(default_factory=list)
    weak_secret: str | None = None
    risk_score: int = 0


class ScanRequest(BaseModel):
    target_base_url: str
    endpoint_ids: list[str] | None = None
    auth_headers: dict[str, str] = Field(default_factory=dict)
    secondary_auth_headers: dict[str, str] = Field(default_factory=dict)
    authorized: bool = False
    dry_run: bool = False
    checks: list[str] = Field(default_factory=lambda: ["auth", "bola", "data_exposure", "mass_assignment", "ssrf", "rate_limit"])
    max_requests_per_endpoint: int = Field(default=8, ge=1, le=25)
    rate_limit_burst: int = Field(default=8, ge=2, le=30)
    timeout_seconds: float = Field(default=8.0, ge=1.0, le=30.0)


class Finding(BaseModel):
    id: str
    scan_id: str
    endpoint_id: str | None = None
    severity: Severity
    category: str
    title: str
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str = ""
    created_at: datetime


class AttackRecord(BaseModel):
    id: str
    scan_id: str
    endpoint_id: str | None = None
    name: str
    method: HttpMethod
    url: str
    payload_json: dict[str, Any] | None = None
    headers_json: dict[str, str] = Field(default_factory=dict)
    status_code: int | None = None
    response_excerpt: str = ""
    impact: str = ""
    replayable: bool = True
    created_at: datetime


class ScanSummary(BaseModel):
    scan_id: str
    status: Literal["queued", "running", "completed", "failed"]
    target_base_url: str
    started_at: datetime
    completed_at: datetime | None = None
    endpoints_tested: int = 0
    attacks_executed: int = 0
    findings_count: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)


class ScanResult(BaseModel):
    summary: ScanSummary
    findings: list[Finding] = Field(default_factory=list)
    attacks: list[AttackRecord] = Field(default_factory=list)


class SecurityReport(BaseModel):
    scan: ScanSummary
    generated_at: datetime
    risk_score: int
    executive_summary: str
    endpoint_count: int
    replay_count: int
    severity_counts: dict[str, int] = Field(default_factory=dict)
    category_counts: dict[str, int] = Field(default_factory=dict)
    top_findings: list[Finding] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class ReplayRequest(BaseModel):
    authorized: bool = False
    override_base_url: str | None = None
    timeout_seconds: float = Field(default=8.0, ge=1.0, le=30.0)


class GraphNode(BaseModel):
    id: str
    label: str
    kind: str
    severity: Severity = "info"
    metadata: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str
    risk: Severity = "info"
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackGraph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
