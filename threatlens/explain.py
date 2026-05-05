from __future__ import annotations

import pandas as pd

from threatlens.schemas import FeatureExplanation


REASONS = {
    "duration": "Session duration is far from the learned normal range.",
    "src_bytes": "Source-to-destination transfer volume is unusually high.",
    "dst_bytes": "Destination response volume is unusual for this behavior.",
    "failed_logins": "Failed login count suggests credential probing.",
    "successful_logins": "Successful login pattern differs from the baseline.",
    "privilege_change": "Privilege change is rare and high-risk.",
    "unique_dst_ports": "Many destination ports can indicate scanning or lateral movement.",
    "connections_last_min": "Connection burst is higher than typical activity.",
    "bytes_per_second": "Transfer rate is unusual for normal sessions.",
    "is_off_hours": "Activity occurred outside normal working hours.",
}


class BaselineExplainer:
    """Lightweight local explanation based on robust deviation from training medians."""

    def __init__(self, baseline: pd.DataFrame):
        self.median = baseline.median(numeric_only=True)
        q1 = baseline.quantile(0.25, numeric_only=True)
        q3 = baseline.quantile(0.75, numeric_only=True)
        self.iqr = (q3 - q1).replace(0, 1.0)

    def explain(self, row: pd.Series, limit: int = 4) -> list[FeatureExplanation]:
        contributions = ((row - self.median).abs() / self.iqr).sort_values(ascending=False)
        explanations = []
        for feature, contribution in contributions.head(limit).items():
            explanations.append(
                FeatureExplanation(
                    feature=feature,
                    value=float(row[feature]),
                    contribution=round(float(contribution), 3),
                    reason=REASONS.get(feature, "Feature deviates from the learned baseline."),
                )
            )
        return explanations

