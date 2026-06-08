from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

from apireconx.schemas import JwtAnalysis, JwtFinding


HMAC_ALGS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def analyze_jwt(token: str, weak_secrets: list[str]) -> JwtAnalysis:
    parts = token.strip().split(".")
    findings: list[JwtFinding] = []
    if len(parts) != 3:
        return JwtAnalysis(
            valid_shape=False,
            findings=[
                JwtFinding(
                    severity="high",
                    title="Invalid JWT structure",
                    detail="A JWT should contain header, payload, and signature segments.",
                )
            ],
            risk_score=70,
        )

    header = _decode_json_segment(parts[0])
    payload = _decode_json_segment(parts[1])
    if header is None or payload is None:
        return JwtAnalysis(
            valid_shape=False,
            findings=[
                JwtFinding(
                    severity="high",
                    title="JWT segment decoding failed",
                    detail="Header or payload could not be decoded as base64url JSON.",
                )
            ],
            risk_score=70,
        )

    alg = str(header.get("alg", "")).upper()
    if not alg:
        findings.append(JwtFinding(severity="medium", title="Missing algorithm", detail="The JWT header does not declare an alg value."))
    if alg == "NONE":
        findings.append(JwtFinding(severity="critical", title="Unsigned token accepted risk", detail="The token advertises alg=none. APIs must reject unsigned tokens."))
    if alg.startswith("HS"):
        findings.append(
            JwtFinding(
                severity="low",
                title="Symmetric JWT signing",
                detail="HMAC tokens are valid when managed carefully, but weak shared secrets are common and should be tested.",
            )
        )
    if alg in {"HS256", "HS384", "HS512"} and any(str(x).upper().startswith("RS") for x in [header.get("kid", ""), header.get("jku", "")]):
        findings.append(
            JwtFinding(
                severity="medium",
                title="Algorithm confusion review needed",
                detail="HMAC signing with key-discovery style headers should be reviewed for algorithm confusion controls.",
            )
        )

    now = int(datetime.now(timezone.utc).timestamp())
    exp = payload.get("exp")
    if exp is None:
        findings.append(JwtFinding(severity="high", title="Missing expiration", detail="Tokens without exp can remain usable indefinitely if replayed."))
    elif isinstance(exp, (int, float)) and exp < now:
        findings.append(JwtFinding(severity="info", title="Expired token", detail="The exp claim is already in the past."))

    nbf = payload.get("nbf")
    if isinstance(nbf, (int, float)) and nbf > now:
        findings.append(JwtFinding(severity="medium", title="Token not yet valid", detail="The nbf claim is in the future."))

    iat = payload.get("iat")
    if isinstance(iat, (int, float)) and iat > now + 300:
        findings.append(JwtFinding(severity="medium", title="Issued-at claim in future", detail="The iat claim is more than five minutes in the future."))

    elevated_claims = _elevated_claims(payload)
    if elevated_claims:
        findings.append(
            JwtFinding(
                severity="medium",
                title="Privilege-bearing claims present",
                detail=f"Review server-side authorization for these claims: {', '.join(elevated_claims)}.",
            )
        )

    weak_secret = _find_weak_secret(token, parts, alg, weak_secrets)
    if weak_secret:
        findings.append(
            JwtFinding(
                severity="critical",
                title="Weak JWT signing secret",
                detail="The signature validates with a common weak secret from the configured wordlist.",
            )
        )

    score = _risk_score(findings)
    return JwtAnalysis(valid_shape=True, header=header, payload=payload, findings=findings, weak_secret=weak_secret, risk_score=score)


def _decode_json_segment(segment: str) -> dict[str, Any] | None:
    try:
        padded = segment + "=" * (-len(segment) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        decoded = json.loads(raw.decode("utf-8"))
        return decoded if isinstance(decoded, dict) else None
    except Exception:
        return None


def _find_weak_secret(token: str, parts: list[str], alg: str, weak_secrets: list[str]) -> str | None:
    digest = HMAC_ALGS.get(alg)
    if not digest:
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    expected = parts[2]
    for secret in weak_secrets:
        mac = hmac.new(secret.encode("utf-8"), signing_input, digest).digest()
        signature = base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")
        if hmac.compare_digest(signature, expected):
            return secret
    return None


def _elevated_claims(payload: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    for key in ("role", "roles", "scope", "scopes", "permissions", "is_admin", "admin", "tenant_id", "org_id"):
        if key in payload:
            candidates.append(key)
    return candidates


def _risk_score(findings: list[JwtFinding]) -> int:
    weights = {"info": 5, "low": 12, "medium": 25, "high": 45, "critical": 70}
    return min(100, sum(weights[f.severity] for f in findings))
