from __future__ import annotations

import pandas as pd


def severity_from_score(score: float) -> str:
    if score >= 0.78:
        return "critical"
    if score >= 0.58:
        return "high"
    if score >= 0.35:
        return "medium"
    return "low"


def categorize(row: pd.Series) -> str:
    if row["failed_logins"] >= 8:
        return "credential attack"
    if row["privilege_change"] == 1 and row["is_off_hours"] == 1:
        return "privilege escalation"
    if row["unique_dst_ports"] >= 12 or row["connections_last_min"] >= 80:
        return "lateral movement"
    if row["src_bytes"] > 100000 or row["bytes_per_second"] > 2500:
        return "data exfiltration"
    if row["is_off_hours"] == 1:
        return "off-hours anomaly"
    return "behavioral anomaly"

