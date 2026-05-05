from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "models"
MODEL_PATH = MODEL_DIR / "isolation_forest.joblib"

FEATURE_COLUMNS = [
    "duration",
    "src_bytes",
    "dst_bytes",
    "failed_logins",
    "successful_logins",
    "privilege_change",
    "unique_dst_ports",
    "connections_last_min",
    "bytes_per_second",
    "is_off_hours",
]

