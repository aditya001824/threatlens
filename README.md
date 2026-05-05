# ThreatLens

ThreatLens is an AI-powered log anomaly detector for security operations demos. It simulates system and network telemetry, trains an unsupervised anomaly detector, flags suspicious activity in near real time, and explains which features made each alert look risky.

## Why It Matters

Most beginner security projects stop at scanning ports or parsing logs. ThreatLens combines:

- AI anomaly detection with an Isolation Forest
- Security-focused log features such as failed logins, unusual ports, data transfer, and privilege changes
- Explainable alerts that describe why a log was flagged
- A FastAPI backend and Streamlit dashboard for a production-style shape

## Features

- Synthetic network and authentication log generator
- Optional CSV ingestion for CICIDS2017, KDD Cup 99, or similar tabular datasets
- Isolation Forest training and scoring
- Per-alert feature contribution explanations
- Alert severity and attack category hints
- REST API for training, scoring, and streaming alerts
- Streamlit dashboard with live alert simulation and charts

## Project Structure

```text
threatlens/
  api.py              FastAPI backend
  dashboard.py        Streamlit dashboard
  data.py             Synthetic logs and CSV loading
  explain.py          Feature contribution explanations
  model.py            Training and scoring pipeline
  schemas.py          Shared API schemas
  security_rules.py   Severity and category logic
  settings.py         Paths and feature config
models/               Saved model artifacts
sample_data/          Optional local datasets
```

## Quick Start

Create and activate a virtual environment, then install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Train the baseline model:

```powershell
python -m threatlens.model
```

Run the API:

```powershell
uvicorn threatlens.api:app --reload
```

In another terminal, run the dashboard:

```powershell
streamlit run threatlens/dashboard.py
```

If `streamlit` or `uvicorn` is not on your PATH on Windows, use the module form:

```powershell
python -m streamlit run threatlens/dashboard.py
python -m uvicorn threatlens.api:app --reload
```

## Deploy

### Streamlit Community Cloud

- Repository: this GitHub repo
- Main file path: `threatlens/dashboard.py`
- Python version: `3.12`

The dashboard trains a demo model automatically if `models/isolation_forest.joblib` is missing, so the app can deploy without committing model artifacts.

### Render

Use the included `render.yaml`, or configure a web service manually:

```bash
pip install -r requirements.txt
python -m streamlit run threatlens/dashboard.py --server.address=0.0.0.0 --server.port=$PORT
```

### Docker

```bash
docker build -t threatlens .
docker run -p 8501:8501 threatlens
```

## API Examples

Train or retrain the model:

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8000/train
```

Score one synthetic event:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/alerts/next
```

## Dataset Notes

ThreatLens runs out of the box with synthetic telemetry. To use a public dataset, place a CSV in `sample_data/` and call:

```python
from threatlens.data import load_csv_logs

df = load_csv_logs("sample_data/your_dataset.csv")
```

The model expects numeric feature columns. If your dataset has categorical protocol/service fields, map them to numeric encodings before training.

## Resume Pitch

Built an AI-powered security analytics tool that detects anomalous log behavior using unsupervised ML, explains alert drivers, categorizes likely intrusion patterns, and exposes results through FastAPI and Streamlit.
