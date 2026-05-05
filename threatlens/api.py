from __future__ import annotations

from fastapi import FastAPI

from threatlens.data import generate_synthetic_logs
from threatlens.model import load_model, save_model, train_model
from threatlens.schemas import Alert, LogEvent, TrainResponse
from threatlens.settings import MODEL_PATH

app = FastAPI(title="ThreatLens API", version="0.1.0")
MODEL = load_model()
STREAM = generate_synthetic_logs(rows=500, anomaly_rate=0.16, seed=1337)
STREAM_INDEX = 0


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "model": str(MODEL_PATH)}


@app.post("/train", response_model=TrainResponse)
def train(contamination: float = 0.08) -> TrainResponse:
    global MODEL
    MODEL = train_model(contamination=contamination)
    save_model(MODEL)
    return TrainResponse(rows=len(MODEL.baseline), contamination=contamination, model_path=str(MODEL_PATH))


@app.post("/score", response_model=Alert)
def score(event: LogEvent) -> Alert:
    return MODEL.score_event(event)


@app.get("/alerts/next", response_model=Alert)
def next_alert() -> Alert:
    global STREAM_INDEX
    event = LogEvent(**STREAM.iloc[STREAM_INDEX % len(STREAM)].to_dict())
    STREAM_INDEX += 1
    return MODEL.score_event(event)


@app.get("/alerts/batch")
def batch_alerts(limit: int = 50) -> list[Alert]:
    safe_limit = min(max(limit, 1), 200)
    events = []
    for _ in range(safe_limit):
        events.append(next_alert())
    return events

