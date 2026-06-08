import base64
import hashlib
import hmac
import json

from apireconx.services.jwt_analyzer import analyze_jwt


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def test_jwt_analyzer_detects_weak_secret_and_missing_exp() -> None:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8"))
    payload = _b64(json.dumps({"sub": "1", "role": "admin"}).encode("utf-8"))
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = _b64(hmac.new(b"secret", signing_input, hashlib.sha256).digest())

    result = analyze_jwt(f"{header}.{payload}.{signature}", ["secret"])

    assert result.valid_shape is True
    assert result.weak_secret == "secret"
    assert result.risk_score >= 70
    assert any(finding.title == "Missing expiration" for finding in result.findings)
