from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from threatlens.data import generate_synthetic_logs
from threatlens.model import load_model, train_and_save
from threatlens.schemas import LogEvent


st.set_page_config(page_title="ThreatLens", page_icon="TL", layout="wide")


@st.cache_resource
def get_model():
    return load_model()


def load_demo_events(rows: int, anomaly_rate: float) -> pd.DataFrame:
    return generate_synthetic_logs(rows=rows, anomaly_rate=anomaly_rate, seed=2026)


st.title("ThreatLens")
st.caption("AI-powered log anomaly detection with explainable security alerts")

with st.sidebar:
    st.header("Simulation")
    rows = st.slider("Events", 100, 3000, 800, step=100)
    anomaly_rate = st.slider("Injected anomaly rate", 0.01, 0.30, 0.12, step=0.01)
    threshold_view = st.slider("Show alerts above score", 0.0, 1.0, 0.45, step=0.05)
    if st.button("Retrain baseline model", type="primary"):
        train_and_save()
        get_model.clear()
        st.success("Model retrained.")

model = get_model()
events = load_demo_events(rows, anomaly_rate)
scored = model.score_frame(events)
alerts = scored[(scored["is_anomaly"]) & (scored["anomaly_score"] >= threshold_view)].copy()
alerts = alerts.sort_values("anomaly_score", ascending=False)

total_events, total_alerts, critical_alerts, top_category = st.columns(4)
total_events.metric("Events scored", f"{len(scored):,}")
total_alerts.metric("Alerts", f"{len(alerts):,}")
critical_alerts.metric("Critical", f"{(alerts['severity'] == 'critical').sum():,}" if len(alerts) else "0")
top_category.metric("Top category", alerts["category"].mode().iloc[0] if len(alerts) else "none")

chart_col, category_col = st.columns([2, 1])
with chart_col:
    fig = px.scatter(
        scored,
        x="timestamp",
        y="anomaly_score",
        color="severity",
        hover_data=["username", "source_ip", "action", "category"],
        title="Anomaly score over time",
    )
    fig.update_layout(height=380, margin=dict(l=16, r=16, t=48, b=16))
    st.plotly_chart(fig, width="stretch")

with category_col:
    counts = alerts["category"].value_counts().reset_index()
    counts.columns = ["category", "alerts"]
    if len(counts):
        fig = px.bar(counts, x="alerts", y="category", orientation="h", title="Alert categories")
        fig.update_layout(height=380, margin=dict(l=16, r=16, t=48, b=16))
        st.plotly_chart(fig, width="stretch")
    else:
        st.info("No alerts above the selected score.")

st.subheader("Live alert queue")
visible_columns = [
    "timestamp",
    "severity",
    "category",
    "anomaly_score",
    "source_ip",
    "destination_ip",
    "username",
    "action",
    "failed_logins",
    "privilege_change",
    "unique_dst_ports",
    "connections_last_min",
]
st.dataframe(alerts[visible_columns], width="stretch", height=280)

st.subheader("Explain an alert")
if len(alerts):
    selected_index = st.selectbox(
        "Select alert",
        alerts.index,
        format_func=lambda idx: f"{alerts.loc[idx, 'severity'].upper()} | {alerts.loc[idx, 'category']} | {alerts.loc[idx, 'source_ip']}",
    )
    alert_event = scored.loc[selected_index]
    event_payload = {field: alert_event[field] for field in LogEvent.model_fields}
    alert = model.score_event(LogEvent(**event_payload))
    exp_df = pd.DataFrame([item.model_dump() for item in alert.explanations])
    st.write(
        f"ThreatLens flagged this as **{alert.category}** with **{alert.severity}** severity "
        f"and an anomaly score of **{alert.anomaly_score:.2f}**."
    )
    st.dataframe(exp_df, width="stretch", hide_index=True)
else:
    st.write("No selected alert yet. Lower the score filter or increase injected anomaly rate.")
