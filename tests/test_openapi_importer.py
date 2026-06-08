from pathlib import Path

from apireconx.services.openapi_importer import parse_openapi, parse_spec_text


def test_parse_demo_openapi_spec() -> None:
    spec_text = Path("samples/apireconx-demo-openapi.yaml").read_text(encoding="utf-8")
    spec = parse_spec_text(spec_text)
    endpoints = parse_openapi(spec, source_name="test")

    paths = {(endpoint.method, endpoint.path) for endpoint in endpoints}

    assert ("GET", "/users/{user_id}") in paths
    assert ("PATCH", "/users/{user_id}") in paths
    assert ("POST", "/transfer") in paths
    assert any(endpoint.auth_required is False for endpoint in endpoints if endpoint.path == "/login")
