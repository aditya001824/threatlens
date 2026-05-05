from pydantic import BaseModel, Field


class LogEvent(BaseModel):
    timestamp: str
    source_ip: str
    destination_ip: str
    username: str
    action: str
    duration: float = Field(ge=0)
    src_bytes: float = Field(ge=0)
    dst_bytes: float = Field(ge=0)
    failed_logins: int = Field(ge=0)
    successful_logins: int = Field(ge=0)
    privilege_change: int = Field(ge=0, le=1)
    unique_dst_ports: int = Field(ge=1)
    connections_last_min: int = Field(ge=1)
    bytes_per_second: float = Field(ge=0)
    is_off_hours: int = Field(ge=0, le=1)


class FeatureExplanation(BaseModel):
    feature: str
    value: float
    contribution: float
    reason: str


class Alert(BaseModel):
    event: LogEvent
    anomaly_score: float
    is_anomaly: bool
    severity: str
    category: str
    explanations: list[FeatureExplanation]


class TrainResponse(BaseModel):
    rows: int
    contamination: float
    model_path: str

