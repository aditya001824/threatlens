from __future__ import annotations

from dataclasses import dataclass

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from threatlens.data import feature_frame, generate_synthetic_logs
from threatlens.explain import BaselineExplainer
from threatlens.schemas import Alert, LogEvent
from threatlens.security_rules import categorize, severity_from_score
from threatlens.settings import FEATURE_COLUMNS, MODEL_DIR, MODEL_PATH


@dataclass
class ThreatLensModel:
    pipeline: Pipeline
    baseline: pd.DataFrame
    threshold: float

    @property
    def explainer(self) -> BaselineExplainer:
        return BaselineExplainer(self.baseline)

    def score_frame(self, df: pd.DataFrame) -> pd.DataFrame:
        features = feature_frame(df)
        raw_scores = -self.pipeline.decision_function(features)
        normalized = (raw_scores - raw_scores.min()) / max(raw_scores.max() - raw_scores.min(), 1e-9)
        scored = df.copy()
        scored["anomaly_score"] = normalized
        scored["is_anomaly"] = raw_scores >= self.threshold
        scored["severity"] = [severity_from_score(float(score)) for score in normalized]
        scored["category"] = [categorize(row) for _, row in scored.iterrows()]
        return scored

    def score_event(self, event: LogEvent) -> Alert:
        df = pd.DataFrame([event.model_dump()])
        features = feature_frame(df)
        raw_score = float(-self.pipeline.decision_function(features)[0])
        baseline_scores = -self.pipeline.decision_function(self.baseline)
        min_score = float(baseline_scores.min())
        max_score = float(baseline_scores.max())
        normalized = (raw_score - min_score) / max(max_score - min_score, 1e-9)
        normalized = max(0.0, min(1.0, normalized))
        row = features.iloc[0]
        return Alert(
            event=event,
            anomaly_score=round(normalized, 4),
            is_anomaly=raw_score >= self.threshold,
            severity=severity_from_score(normalized),
            category=categorize(row),
            explanations=self.explainer.explain(row),
        )


def train_model(df: pd.DataFrame | None = None, contamination: float = 0.08) -> ThreatLensModel:
    training_df = df if df is not None else generate_synthetic_logs(rows=1800, anomaly_rate=0.05)
    features = feature_frame(training_df)
    pipeline = Pipeline(
        steps=[
            ("scale", StandardScaler()),
            (
                "model",
                IsolationForest(
                    n_estimators=220,
                    contamination=contamination,
                    random_state=42,
                    n_jobs=-1,
                ),
            ),
        ]
    )
    pipeline.fit(features)
    raw_scores = -pipeline.decision_function(features)
    threshold = float(pd.Series(raw_scores).quantile(1 - contamination))
    return ThreatLensModel(pipeline=pipeline, baseline=features, threshold=threshold)


def save_model(model: ThreatLensModel, path=MODEL_PATH) -> None:
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "pipeline": model.pipeline,
            "baseline": model.baseline,
            "threshold": model.threshold,
        },
        path,
    )


def load_model(path=MODEL_PATH) -> ThreatLensModel:
    if not path.exists():
        model = train_model()
        save_model(model, path)
        return model
    try:
        artifact = joblib.load(path)
        if isinstance(artifact, ThreatLensModel):
            return artifact
        return ThreatLensModel(
            pipeline=artifact["pipeline"],
            baseline=artifact["baseline"],
            threshold=artifact["threshold"],
        )
    except (AttributeError, KeyError, TypeError):
        model = train_model()
        save_model(model, path)
        return model


def train_and_save() -> ThreatLensModel:
    model = train_model()
    save_model(model)
    return model


if __name__ == "__main__":
    trained = train_and_save()
    print(f"Trained ThreatLens on {len(trained.baseline)} rows with {len(FEATURE_COLUMNS)} features.")
    print(f"Saved model to {MODEL_PATH}")
