from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any

import httpx
import yaml

from apireconx.schemas import ApiEndpoint


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


def endpoint_id(method: str, path: str) -> str:
    digest = hashlib.sha1(f"{method.upper()} {path}".encode("utf-8")).hexdigest()[:12]
    return f"{method.lower()}-{digest}"


async def fetch_spec(url: str, timeout: float = 10.0) -> str:
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.text


def parse_spec_text(spec_text: str) -> dict[str, Any]:
    text = spec_text.strip()
    if not text:
        raise ValueError("OpenAPI spec is empty")
    if text.startswith("{"):
        return json.loads(text)
    parsed = yaml.safe_load(text)
    if not isinstance(parsed, dict):
        raise ValueError("OpenAPI spec must parse to an object")
    return parsed


def parse_openapi(spec: dict[str, Any], source_name: str = "openapi") -> list[ApiEndpoint]:
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        raise ValueError("OpenAPI spec does not contain a paths object")

    endpoints: list[ApiEndpoint] = []
    global_security = spec.get("security")

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        path_parameters = path_item.get("parameters", [])
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            parameters = []
            parameters.extend(deepcopy(path_parameters) if isinstance(path_parameters, list) else [])
            parameters.extend(deepcopy(operation.get("parameters", [])) if isinstance(operation.get("parameters"), list) else [])

            request_schema = _extract_request_schema(spec, operation)
            response_schema = _extract_response_schema(spec, operation)
            auth_required = _auth_required(global_security, operation.get("security"))

            endpoints.append(
                ApiEndpoint(
                    id=endpoint_id(method, path),
                    method=method.upper(),
                    path=path,
                    summary=operation.get("summary") or operation.get("description") or "",
                    operation_id=operation.get("operationId"),
                    tags=operation.get("tags", []) if isinstance(operation.get("tags", []), list) else [],
                    parameters=parameters,
                    request_schema=request_schema,
                    response_schema=response_schema,
                    auth_required=auth_required,
                    source=source_name,
                )
            )
    return endpoints


def _auth_required(global_security: Any, operation_security: Any) -> bool:
    security = operation_security if operation_security is not None else global_security
    if security == []:
        return False
    return bool(security)


def _extract_request_schema(spec: dict[str, Any], operation: dict[str, Any]) -> dict[str, Any] | None:
    body = operation.get("requestBody")
    body = _resolve_ref(spec, body)
    if not isinstance(body, dict):
        return None
    content = body.get("content", {})
    if not isinstance(content, dict):
        return None
    media = content.get("application/json") or next(iter(content.values()), None)
    if not isinstance(media, dict):
        return None
    return _resolve_ref(spec, media.get("schema"))


def _extract_response_schema(spec: dict[str, Any], operation: dict[str, Any]) -> dict[str, Any] | None:
    responses = operation.get("responses", {})
    if not isinstance(responses, dict):
        return None
    for code in ("200", "201", "202", "default"):
        response = _resolve_ref(spec, responses.get(code))
        if not isinstance(response, dict):
            continue
        content = response.get("content", {})
        if not isinstance(content, dict):
            continue
        media = content.get("application/json") or next(iter(content.values()), None)
        if isinstance(media, dict):
            return _resolve_ref(spec, media.get("schema"))
    return None


def _resolve_ref(spec: dict[str, Any], value: Any) -> Any:
    if not isinstance(value, dict) or "$ref" not in value:
        return value
    ref = value["$ref"]
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return value
    current: Any = spec
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or part not in current:
            return value
        current = current[part]
    return deepcopy(current)
