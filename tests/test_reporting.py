from apireconx.schemas import ApiEndpoint
from apireconx.services.reporting import build_markdown_report, build_security_report
from apireconx.storage import AppStore


def test_security_report_summarizes_scan(tmp_path) -> None:
    app_store = AppStore(tmp_path / "report.sqlite3")
    app_store.upsert_endpoints([ApiEndpoint(id="get-user", method="GET", path="/users/{user_id}")])
    scan = app_store.create_scan("http://target.test")
    app_store.add_finding(
        scan.scan_id,
        severity="high",
        category="bola",
        title="Potential object-level authorization bypass",
        description="Object swap succeeded.",
        endpoint_id="get-user",
        remediation="Check ownership server-side.",
    )
    app_store.add_attack(
        scan.scan_id,
        endpoint_id="get-user",
        name="BOLA object swap",
        method="GET",
        url="http://target.test/users/2",
        payload_json=None,
        headers_json={},
        status_code=200,
        response_excerpt="{}",
        impact="Potential bola signal",
    )
    app_store.finish_scan(
        scan.scan_id,
        "completed",
        {"endpoints_tested": 1, "attacks_executed": 1, "findings_count": 1, "severity_counts": {"high": 1}},
    )

    report = build_security_report(scan.scan_id, app_store)

    assert report is not None
    assert report.risk_score >= 18
    assert report.category_counts["bola"] == 1
    assert "ownership checks" in " ".join(report.recommendations)
    assert "APIRECON-X Security Report" in build_markdown_report(report)
