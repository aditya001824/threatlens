from __future__ import annotations

from collections import Counter

from apireconx.schemas import Finding, SecurityReport
from apireconx.storage import AppStore, store, utcnow


SEVERITY_WEIGHT = {"info": 1, "low": 4, "medium": 9, "high": 18, "critical": 30}
SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def build_security_report(scan_id: str, app_store: AppStore = store) -> SecurityReport | None:
    result = app_store.get_scan_result(scan_id)
    if not result:
        return None
    scan, findings, attacks = result
    severity_counts = Counter(finding.severity for finding in findings)
    category_counts = Counter(finding.category for finding in findings)
    risk_score = _risk_score(severity_counts)
    top_findings = sorted(findings, key=_finding_sort_key, reverse=True)[:8]
    recommendations = _recommendations(top_findings)

    return SecurityReport(
        scan=scan,
        generated_at=utcnow(),
        risk_score=risk_score,
        executive_summary=_executive_summary(scan.target_base_url, risk_score, severity_counts, len(findings), len(attacks)),
        endpoint_count=scan.endpoints_tested,
        replay_count=len(attacks),
        severity_counts=dict(severity_counts),
        category_counts=dict(category_counts),
        top_findings=top_findings,
        recommendations=recommendations,
    )


def build_markdown_report(report: SecurityReport) -> str:
    lines = [
        f"# APIRECON-X Security Report",
        "",
        f"- Target: `{report.scan.target_base_url}`",
        f"- Scan ID: `{report.scan.scan_id}`",
        f"- Generated: `{report.generated_at.isoformat()}`",
        f"- Risk score: **{report.risk_score}/100**",
        f"- Endpoints tested: **{report.endpoint_count}**",
        f"- Replayable attacks: **{report.replay_count}**",
        "",
        "## Executive Summary",
        "",
        report.executive_summary,
        "",
        "## Severity Breakdown",
        "",
    ]
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"- {severity.title()}: {report.severity_counts.get(severity, 0)}")

    lines.extend(["", "## Top Findings", ""])
    if report.top_findings:
        for finding in report.top_findings:
            lines.extend(
                [
                    f"### {finding.title}",
                    "",
                    f"- Severity: `{finding.severity}`",
                    f"- Category: `{finding.category}`",
                    f"- Endpoint ID: `{finding.endpoint_id or 'n/a'}`",
                    "",
                    finding.description,
                    "",
                    f"Remediation: {finding.remediation or 'Review and enforce server-side controls.'}",
                    "",
                ]
            )
    else:
        lines.append("No findings were recorded for this scan.")

    lines.extend(["", "## Recommended Next Actions", ""])
    for recommendation in report.recommendations:
        lines.append(f"- {recommendation}")
    return "\n".join(lines).strip() + "\n"


def _risk_score(severity_counts: Counter) -> int:
    raw = sum(SEVERITY_WEIGHT.get(severity, 0) * count for severity, count in severity_counts.items())
    return min(100, raw)


def _finding_sort_key(finding: Finding) -> tuple[int, str]:
    return (SEVERITY_RANK.get(finding.severity, 0), finding.category)


def _executive_summary(target: str, risk_score: int, severity_counts: Counter, finding_count: int, attack_count: int) -> str:
    high_or_critical = severity_counts.get("critical", 0) + severity_counts.get("high", 0)
    if finding_count == 0:
        return f"No security findings were recorded for {target}. Continue testing with richer auth contexts and business workflows."
    if high_or_critical:
        return (
            f"APIRECON-X found {finding_count} findings on {target}, including {high_or_critical} high or critical signals. "
            f"The scan executed {attack_count} replayable attack simulations. Prioritize authorization and authentication fixes first."
        )
    return (
        f"APIRECON-X found {finding_count} findings on {target} with an aggregate risk score of {risk_score}. "
        f"The scan executed {attack_count} replayable attack simulations for regression testing."
    )


def _recommendations(findings: list[Finding]) -> list[str]:
    categories = {finding.category for finding in findings}
    recommendations: list[str] = []
    if "bola" in categories:
        recommendations.append("Add object ownership checks to every read and write path that accepts user-controlled identifiers.")
    if "broken_authentication" in categories:
        recommendations.append("Move authentication enforcement into shared middleware and block unauthenticated requests before handlers execute.")
    if "mass_assignment" in categories:
        recommendations.append("Use explicit writable-field allow-lists and reject client-supplied role, plan, admin, or ownership fields.")
    if "excessive_data_exposure" in categories:
        recommendations.append("Redact secrets and return role-specific response DTOs instead of raw persistence models.")
    if "rate_limit" in categories:
        recommendations.append("Apply per-user and per-IP throttles to login, payment, admin, and mutation endpoints.")
    if "ssrf" in categories:
        recommendations.append("Validate callback URLs against an allow-list and block internal network ranges at egress.")
    if not recommendations:
        recommendations.append("Expand coverage with multiple roles, tenant fixtures, and business workflow replay tests.")
    return recommendations
