from __future__ import annotations

import hashlib
import re
from typing import Any

from apireconx.schemas import ApiEndpoint, AttackCase


AMOUNT_NAMES = {"amount", "price", "total", "balance", "quantity", "limit", "discount"}
IDENTITY_NAMES = {"user_id", "userid", "account_id", "accountid", "owner_id", "customer_id", "sender", "receiver"}
ROLE_NAMES = {"role", "roles", "permission", "permissions", "is_admin", "admin", "plan", "tier"}
URL_NAMES = {"url", "uri", "callback", "callback_url", "redirect", "redirect_uri", "webhook", "avatar", "image_url"}
SENSITIVE_KEYS = {"password", "passwd", "secret", "token", "api_key", "apikey", "private_key", "session", "ssn"}


def generate_attack_cases(endpoint: ApiEndpoint, max_cases: int = 10) -> list[AttackCase]:
    cases: list[AttackCase] = []
    names = _field_names(endpoint)
    base_payload = _sample_payload(endpoint.request_schema)

    if endpoint.auth_required:
        cases.append(
            _case(
                endpoint,
                "Missing authentication",
                "auth",
                "Send the request without auth headers and flag unexpected success.",
                payload=base_payload if _method_accepts_body(endpoint.method) else None,
                expected_signal="2xx/3xx response without credentials",
            )
        )

    path_params = _path_params(endpoint)
    if path_params or names & IDENTITY_NAMES:
        cases.append(
            _case(
                endpoint,
                "BOLA object swap",
                "bola",
                "Swap an object identifier to check whether authorization is enforced per object.",
                payload=_payload_with_identity_swap(base_payload, names),
                path_params={name: "2" for name in path_params},
                expected_signal="Successful response for an object owned by another principal",
            )
        )

    if names & AMOUNT_NAMES:
        for label, value in [("Negative numeric value", -1), ("Integer boundary value", 2147483648)]:
            cases.append(
                _case(
                    endpoint,
                    label,
                    "business_logic",
                    "Mutate monetary or numeric fields to test business logic boundaries.",
                    payload=_payload_with_value(base_payload, names & AMOUNT_NAMES, value),
                    expected_signal="Accepted transaction or state change with unsafe numeric value",
                )
            )

    if base_payload and (endpoint.method in {"POST", "PUT", "PATCH"}):
        cases.append(
            _case(
                endpoint,
                "Mass assignment privilege fields",
                "mass_assignment",
                "Add server-owned fields to verify the API rejects client-side privilege changes.",
                payload={**base_payload, "is_admin": True, "role": "admin", "plan": "enterprise"},
                expected_signal="2xx response or reflected privilege fields",
            )
        )

    if names & URL_NAMES:
        cases.append(
            _case(
                endpoint,
                "SSRF callback probe",
                "ssrf",
                "Inject a controlled callback-style URL into URL-like fields.",
                payload=_payload_with_value(base_payload, names & URL_NAMES, "http://127.0.0.1:1/apireconx-ssrf-check"),
                query_params={name: "http://127.0.0.1:1/apireconx-ssrf-check" for name in names & URL_NAMES},
                expected_signal="Server attempts to fetch or validates internal callback URL",
            )
        )

    if endpoint.response_schema and _schema_contains_sensitive_keys(endpoint.response_schema):
        cases.append(
            _case(
                endpoint,
                "Sensitive response field review",
                "data_exposure",
                "Check whether response schemas expose secrets or authentication material.",
                payload=base_payload if _method_accepts_body(endpoint.method) else None,
                expected_signal="Sensitive keys in response body",
            )
        )

    cases.append(
        _case(
            endpoint,
            "Rate limit burst",
            "rate_limit",
            "Repeat the same request in a bounded burst and check for throttling.",
            payload=base_payload if _method_accepts_body(endpoint.method) else None,
            expected_signal="No 429/403 response during repeated calls",
        )
    )

    return cases[:max_cases]


def _case(
    endpoint: ApiEndpoint,
    name: str,
    category: str,
    description: str,
    payload: dict[str, Any] | None = None,
    query_params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    path_params: dict[str, Any] | None = None,
    expected_signal: str = "",
) -> AttackCase:
    digest = hashlib.sha1(f"{endpoint.id}:{name}:{payload}:{query_params}:{path_params}".encode("utf-8")).hexdigest()[:10]
    return AttackCase(
        id=f"atk-{digest}",
        name=name,
        category=category,
        method=endpoint.method,
        path=endpoint.path,
        description=description,
        payload=payload,
        query_params=query_params or {},
        headers=headers or {},
        path_params=path_params or {},
        expected_signal=expected_signal,
    )


def _field_names(endpoint: ApiEndpoint) -> set[str]:
    names = {str(param.get("name", "")).lower() for param in endpoint.parameters if isinstance(param, dict)}
    names.update(_schema_field_names(endpoint.request_schema))
    names.update(_schema_field_names(endpoint.response_schema))
    names.update(name.lower() for name in re.findall(r"{([^}]+)}", endpoint.path))
    return {name for name in names if name}


def _path_params(endpoint: ApiEndpoint) -> list[str]:
    return [name for name in re.findall(r"{([^}]+)}", endpoint.path)]


def _schema_field_names(schema: dict[str, Any] | None) -> set[str]:
    if not isinstance(schema, dict):
        return set()
    names: set[str] = set()
    properties = schema.get("properties", {})
    if isinstance(properties, dict):
        for name, child in properties.items():
            names.add(str(name).lower())
            if isinstance(child, dict):
                names.update(_schema_field_names(child))
    items = schema.get("items")
    if isinstance(items, dict):
        names.update(_schema_field_names(items))
    return names


def _sample_payload(schema: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(schema, dict):
        return {}
    if schema.get("type") == "array":
        return {"items": [_sample_payload(schema.get("items"))]}
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        return {}
    payload: dict[str, Any] = {}
    for name, child in properties.items():
        payload[name] = _sample_value(str(name), child if isinstance(child, dict) else {})
    return payload


def _sample_value(name: str, schema: dict[str, Any]) -> Any:
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    lower = name.lower()
    schema_type = schema.get("type")
    if lower in AMOUNT_NAMES or schema_type in {"integer", "number"}:
        return 1
    if lower in IDENTITY_NAMES or lower.endswith("_id"):
        return "1"
    if lower in ROLE_NAMES:
        return "user"
    if lower in URL_NAMES:
        return "https://example.test/callback"
    if schema_type == "boolean":
        return False
    if schema_type == "array":
        return []
    if schema_type == "object":
        return _sample_payload(schema)
    return "APIRECONX_TEST"


def _payload_with_identity_swap(payload: dict[str, Any], names: set[str]) -> dict[str, Any]:
    if not payload:
        payload = {}
    mutated = dict(payload)
    for name in names & IDENTITY_NAMES:
        mutated[name] = "2"
    if not mutated:
        mutated["user_id"] = "2"
    return mutated


def _payload_with_value(payload: dict[str, Any], names: set[str], value: Any) -> dict[str, Any]:
    mutated = dict(payload or {})
    for name in names:
        mutated[name] = value
    return mutated


def _method_accepts_body(method: str) -> bool:
    return method in {"POST", "PUT", "PATCH", "DELETE"}


def _schema_contains_sensitive_keys(schema: dict[str, Any]) -> bool:
    return bool(_schema_field_names(schema) & SENSITIVE_KEYS)
