from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any
from urllib.parse import urljoin

import httpx

from apireconx.schemas import ApiEndpoint, AttackCase, AttackRecord, ScanRequest, ScanResult
from apireconx.services.attack_generator import SENSITIVE_KEYS, generate_attack_cases
from apireconx.storage import AppStore, store


class ApiScanner:
    def __init__(self, app_store: AppStore = store) -> None:
        self.store = app_store

    async def run_scan(self, request: ScanRequest) -> ScanResult:
        if not request.authorized:
            raise PermissionError("Scanning requires authorized=true for owned or approved targets.")

        endpoints = self.store.list_endpoints(request.endpoint_ids)
        scan = self.store.create_scan(request.target_base_url)
        findings = []
        attacks = []
        endpoint_count = 0
        executed = 0

        timeout = httpx.Timeout(request.timeout_seconds)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            for endpoint in endpoints:
                endpoint_count += 1
                cases = [case for case in generate_attack_cases(endpoint, max_cases=request.max_requests_per_endpoint) if case.category in request.checks]
                for case in cases:
                    if case.category == "rate_limit":
                        burst_attacks, burst_findings = await self._run_rate_limit_case(client, scan.scan_id, endpoint, case, request)
                        attacks.extend(burst_attacks)
                        findings.extend(burst_findings)
                        executed += len(burst_attacks)
                        continue

                    attack, case_findings = await self._run_case(client, scan.scan_id, endpoint, case, request)
                    attacks.append(attack)
                    findings.extend(case_findings)
                    executed += 1

        severity_counts = Counter(f.severity for f in findings)
        summary = self.store.finish_scan(
            scan.scan_id,
            "completed",
            {
                "endpoints_tested": endpoint_count,
                "attacks_executed": executed,
                "findings_count": len(findings),
                "severity_counts": dict(severity_counts),
            },
        )
        return ScanResult(summary=summary, findings=findings, attacks=attacks)

    async def replay_attack(self, attack: AttackRecord, timeout_seconds: float = 8.0, override_base_url: str | None = None) -> AttackRecord:
        url = attack.url
        if override_base_url:
            parsed_path = "/" + "/".join(url.split("/", 3)[3:]) if "://" in url else url
            url = _join_url(override_base_url, parsed_path)

        async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=False) as client:
            response = await client.request(
                attack.method,
                url,
                headers=attack.headers_json,
                json=attack.payload_json if attack.payload_json is not None else None,
            )
        return self.store.add_attack(
            scan_id=attack.scan_id,
            endpoint_id=attack.endpoint_id,
            name=f"Replay: {attack.name}",
            method=attack.method,
            url=url,
            payload_json=attack.payload_json,
            headers_json=attack.headers_json,
            status_code=response.status_code,
            response_excerpt=_response_excerpt(response),
            impact=attack.impact,
            replayable=True,
        )

    async def _run_case(
        self,
        client: httpx.AsyncClient,
        scan_id: str,
        endpoint: ApiEndpoint,
        case: AttackCase,
        request: ScanRequest,
    ) -> tuple[AttackRecord, list[Any]]:
        headers = _headers_for_case(case, request)
        url = _build_url(request.target_base_url, endpoint.path, case.path_params)
        payload = case.payload if _method_accepts_body(endpoint.method) else None

        if request.dry_run:
            attack = self.store.add_attack(
                scan_id,
                endpoint.id,
                case.name,
                endpoint.method,
                url,
                payload,
                headers,
                None,
                "Dry run: request was not sent.",
                "Planned attack simulation",
            )
            return attack, []

        response = await client.request(endpoint.method, url, headers=headers, params=case.query_params, json=payload)
        attack = self.store.add_attack(
            scan_id,
            endpoint.id,
            case.name,
            endpoint.method,
            str(response.url),
            payload,
            headers,
            response.status_code,
            _response_excerpt(response),
            _impact_for_case(case, response),
        )
        findings = self._evaluate_case(scan_id, endpoint, case, response, attack)
        return attack, findings

    async def _run_rate_limit_case(
        self,
        client: httpx.AsyncClient,
        scan_id: str,
        endpoint: ApiEndpoint,
        case: AttackCase,
        request: ScanRequest,
    ) -> tuple[list[AttackRecord], list[Any]]:
        attacks = []
        findings = []
        throttled = False
        burst = min(request.rate_limit_burst, request.max_requests_per_endpoint)
        for index in range(burst):
            attack, case_findings = await self._run_case(client, scan_id, endpoint, case, request)
            attacks.append(attack)
            findings.extend(case_findings)
            if attack.status_code in {401, 403, 429}:
                throttled = True
        if not request.dry_run and not throttled and burst >= 5:
            findings.append(
                self.store.add_finding(
                    scan_id=scan_id,
                    endpoint_id=endpoint.id,
                    severity="medium",
                    category="rate_limit",
                    title="No throttling observed during bounded burst",
                    description="The endpoint accepted a burst of repeated requests without returning 429, 403, or 401.",
                    evidence={"burst": burst, "attack_ids": [attack.id for attack in attacks]},
                    remediation="Apply per-user and per-IP rate limits to sensitive API operations.",
                )
            )
        return attacks, findings

    def _evaluate_case(
        self,
        scan_id: str,
        endpoint: ApiEndpoint,
        case: AttackCase,
        response: httpx.Response,
        attack: AttackRecord,
    ) -> list[Any]:
        findings = []
        status = response.status_code
        body_json = _safe_json(response)

        if case.category == "auth" and status < 400:
            findings.append(
                self.store.add_finding(
                    scan_id,
                    "high",
                    "broken_authentication",
                    "Endpoint responded successfully without authentication",
                    "An auth-required endpoint returned a non-error response when credentials were omitted.",
                    endpoint.id,
                    {"status_code": status, "attack_id": attack.id},
                    "Require authentication middleware before business logic executes.",
                )
            )

        if case.category == "bola" and status < 400:
            findings.append(
                self.store.add_finding(
                    scan_id,
                    "high",
                    "bola",
                    "Potential object-level authorization bypass",
                    "The API accepted a swapped object identifier. Confirm whether the authenticated principal owns this object.",
                    endpoint.id,
                    {"status_code": status, "attack_id": attack.id, "path_params": case.path_params, "payload": case.payload},
                    "Enforce ownership checks for every object read or mutation.",
                )
            )

        sensitive = _sensitive_response_keys(body_json)
        if sensitive:
            findings.append(
                self.store.add_finding(
                    scan_id,
                    "medium",
                    "excessive_data_exposure",
                    "Sensitive keys found in API response",
                    "The response body includes fields that commonly carry secrets or private authentication data.",
                    endpoint.id,
                    {"status_code": status, "attack_id": attack.id, "keys": sorted(sensitive)},
                    "Return only fields required by the client and redact secrets server-side.",
                )
            )

        if case.category == "mass_assignment" and status < 400:
            findings.append(
                self.store.add_finding(
                    scan_id,
                    "medium",
                    "mass_assignment",
                    "Privilege fields accepted in request body",
                    "The endpoint returned success when server-owned privilege fields were supplied by the client.",
                    endpoint.id,
                    {"status_code": status, "attack_id": attack.id, "payload": case.payload},
                    "Use allow-lists for writable fields and ignore client-supplied authorization attributes.",
                )
            )

        if case.category == "ssrf" and status < 500 and status not in {400, 422}:
            findings.append(
                self.store.add_finding(
                    scan_id,
                    "medium",
                    "ssrf",
                    "URL-like input accepted",
                    "The endpoint accepted an internal callback URL. Confirm egress controls and URL validation.",
                    endpoint.id,
                    {"status_code": status, "attack_id": attack.id},
                    "Block internal IP ranges, require allow-listed hosts, and fetch URLs through hardened egress services.",
                )
            )

        return findings


def _headers_for_case(case: AttackCase, request: ScanRequest) -> dict[str, str]:
    if case.category == "auth":
        return case.headers
    if case.category == "bola" and request.secondary_auth_headers:
        return {**request.secondary_auth_headers, **case.headers}
    return {**request.auth_headers, **case.headers}


def _build_url(base_url: str, path: str, path_params: dict[str, Any]) -> str:
    rendered = path
    for name in re.findall(r"{([^}]+)}", path):
        value = path_params.get(name, "1")
        rendered = rendered.replace("{" + name + "}", str(value))
    return _join_url(base_url, rendered)


def _join_url(base_url: str, path: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def _response_excerpt(response: httpx.Response) -> str:
    content_type = response.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            return json.dumps(response.json(), indent=2)[:2000]
        except Exception:
            pass
    return response.text[:2000]


def _impact_for_case(case: AttackCase, response: httpx.Response) -> str:
    if response.status_code >= 500:
        return "Server error during attack simulation"
    if response.status_code < 400:
        return f"Potential {case.category} signal"
    return "Blocked or rejected"


def _safe_json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except Exception:
        return None


def _sensitive_response_keys(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            lower = str(key).lower()
            if lower in SENSITIVE_KEYS or any(token in lower for token in ("secret", "token", "password", "private_key")):
                found.add(str(key))
            found.update(_sensitive_response_keys(child))
    elif isinstance(value, list):
        for item in value[:10]:
            found.update(_sensitive_response_keys(item))
    return found


def _method_accepts_body(method: str) -> bool:
    return method in {"POST", "PUT", "PATCH", "DELETE"}


scanner = ApiScanner()
