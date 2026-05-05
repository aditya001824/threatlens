from __future__ import annotations

from datetime import datetime, timedelta
from random import Random

import numpy as np
import pandas as pd

from threatlens.settings import FEATURE_COLUMNS


USERS = ["alice", "bob", "chandra", "diego", "fatima", "mei", "sam"]
ACTIONS = ["login", "file_read", "dns_query", "ssh", "rdp", "database_query"]
ATTACK_ACTIONS = ["brute_force", "privilege_escalation", "lateral_movement", "data_exfiltration"]


def _ip(rng: Random, private_prefix: str = "10.0") -> str:
    return f"{private_prefix}.{rng.randint(0, 12)}.{rng.randint(2, 250)}"


def generate_synthetic_logs(rows: int = 1500, anomaly_rate: float = 0.08, seed: int = 42) -> pd.DataFrame:
    rng = Random(seed)
    np_rng = np.random.default_rng(seed)
    start = datetime.utcnow() - timedelta(hours=12)
    records = []

    for index in range(rows):
        is_attack = rng.random() < anomaly_rate
        timestamp = start + timedelta(seconds=index * rng.randint(5, 25))
        off_hours = int(timestamp.hour < 7 or timestamp.hour > 20)

        if is_attack:
            action = rng.choice(ATTACK_ACTIONS)
            failed_logins = int(np_rng.integers(4, 30)) if action == "brute_force" else int(np_rng.integers(0, 5))
            successful_logins = int(np_rng.integers(0, 3))
            privilege_change = int(action == "privilege_escalation" or rng.random() < 0.25)
            unique_dst_ports = int(np_rng.integers(8, 80)) if action == "lateral_movement" else int(np_rng.integers(1, 18))
            connections = int(np_rng.integers(40, 220))
            src_bytes = float(np_rng.lognormal(11.0, 1.0)) if action == "data_exfiltration" else float(np_rng.lognormal(8.0, 1.0))
            dst_bytes = float(np_rng.lognormal(8.0, 1.0))
            duration = float(np_rng.uniform(15, 900))
        else:
            action = rng.choice(ACTIONS)
            failed_logins = int(np_rng.poisson(0.4))
            successful_logins = int(np_rng.integers(1, 4))
            privilege_change = int(rng.random() < 0.015)
            unique_dst_ports = int(np_rng.integers(1, 8))
            connections = int(np_rng.integers(1, 35))
            src_bytes = float(np_rng.lognormal(6.8, 0.8))
            dst_bytes = float(np_rng.lognormal(7.1, 0.9))
            duration = float(np_rng.uniform(1, 180))

        bytes_per_second = (src_bytes + dst_bytes) / max(duration, 1.0)
        records.append(
            {
                "timestamp": timestamp.isoformat(timespec="seconds") + "Z",
                "source_ip": _ip(rng),
                "destination_ip": _ip(rng, "172.16"),
                "username": rng.choice(USERS),
                "action": action,
                "duration": round(duration, 3),
                "src_bytes": round(src_bytes, 3),
                "dst_bytes": round(dst_bytes, 3),
                "failed_logins": failed_logins,
                "successful_logins": successful_logins,
                "privilege_change": privilege_change,
                "unique_dst_ports": unique_dst_ports,
                "connections_last_min": connections,
                "bytes_per_second": round(bytes_per_second, 3),
                "is_off_hours": off_hours,
            }
        )

    return pd.DataFrame.from_records(records)


def load_csv_logs(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    missing = [column for column in FEATURE_COLUMNS if column not in df.columns]
    if missing:
        raise ValueError(f"CSV is missing required feature columns: {', '.join(missing)}")
    return df


def feature_frame(df: pd.DataFrame) -> pd.DataFrame:
    return df[FEATURE_COLUMNS].astype(float)

